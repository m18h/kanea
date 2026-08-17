package scaling

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// The scaling policy engine (PRD §9.2).
//
// The arithmetic is HPA's, because it is the shape people already understand:
// desired = ceil(current × value / target), taken as the maximum across rules.
// Everything interesting here is the guardrails around it, and each exists
// because of a specific way an autoscaler misbehaves in production:
//
//   - **Tolerance.** A service sitting at 71% against a 70% target does not
//     need another replica. Without a dead band, every evaluation is a change
//     and the service oscillates around the target forever.
//   - **Asymmetric stabilization.** Scaling up late costs a user-visible
//     outage; scaling down early costs the same outage five minutes later when
//     the traffic returns. So up is immediate and down waits for the whole
//     window to agree.
//   - **Step limits.** A metric spike (or a bad reading) must not take a
//     service from 2 replicas to 200. The step caps what one evaluation can do
//     without capping what a sustained trend can do over several.
//   - **Cooldown.** Even correct decisions need spacing: a rollout has to
//     finish and its effect appear in the metrics before the next decision is
//     based on them.
//   - **Refusing to act on no data.** A rule whose metric has no samples is
//     skipped, never treated as zero. The two lead to opposite decisions.

// Policy is a service's scaling configuration, as the job spec declares it.
type Policy struct {
	// Min and Max bound the replica count. Max of zero means the service does
	// not autoscale at all: the declared count stands.
	Min, Max int
	Rules    []Rule
	// Cooldown is the minimum time between changes for this service.
	Cooldown time.Duration
}

// Enabled reports whether this policy asks for autoscaling.
func (p Policy) Enabled() bool { return p.Max > 0 && len(p.Rules) > 0 }

// Rule is one metric target.
type Rule struct {
	Metric string
	Target float64
}

// Defaults for the guardrails (§9.2).
const (
	// DefaultEvaluationInterval is how often the loop runs.
	DefaultEvaluationInterval = 5 * time.Second
	// DefaultAverageWindow is how much history a rule's value averages over:
	// exactly DefaultMinPoints samples at the 5 s scrape resolution.
	//
	// This is the number that decides how fast the platform reacts, and it is
	// in tension with the one below it. Three samples is the cheapest defence
	// against acting on a single anomalous scrape; three samples at 5 s take
	// 15 s to accumulate. Add one evaluation tick and a sustained breach takes
	// up to 20 s to produce a decision, which is why PRD v1.21 restates §21's
	// budget as 20 s rather than 15 s. Reacting faster than this means reacting
	// to one or two samples, which is how an autoscaler chases noise instead of
	// load.
	DefaultAverageWindow = 15 * time.Second
	// DefaultMinPoints is how many samples a rule needs before it may act. Two
	// samples can both be wrong in the same direction; this is the cheapest
	// defence against acting on a single anomalous scrape.
	DefaultMinPoints = 3
	// DefaultScaleDownStabilization is how long the desired count must stay
	// below the current one before shrinking.
	DefaultScaleDownStabilization = 5 * time.Minute
	// DefaultCooldown spaces changes when the spec does not say.
	DefaultCooldown = 2 * time.Minute
	// DefaultTolerance is the dead band around a target, as a fraction.
	DefaultTolerance = 0.1
	// DefaultMaxScaleUpFactor and DefaultMaxScaleDownFactor cap one step.
	DefaultMaxScaleUpFactor   = 2.0
	DefaultMaxScaleDownFactor = 0.5
)

// Decision is what one evaluation concluded, including why.
//
// The reason is part of the result rather than a log line, because it is what
// the event, the notification and the dashboard's scaling history all show. An
// operator asking "why did this scale at 3am" should not have to find the log.
type Decision struct {
	Service string
	Current int
	Desired int
	// Changed reports whether Desired differs from Current.
	Changed bool
	// Rule names the metric that drove the decision, when one did.
	Rule string
	// Reason is a sentence an operator can act on.
	Reason string
	// Observed is the value the winning rule saw, for the same reason.
	Observed float64
	Target   float64
}

// EvaluatorConfig configures the policy engine.
type EvaluatorConfig struct {
	Metrics *Metrics
	// AverageWindow, MinPoints, ScaleDownStabilization, Tolerance and the step
	// factors default to the constants above when zero.
	AverageWindow          time.Duration
	MinPoints              int
	ScaleDownStabilization time.Duration
	Tolerance              float64
	MaxScaleUpFactor       float64
	MaxScaleDownFactor     float64
	Logger                 *slog.Logger
	Now                    func() time.Time
}

// Evaluator decides replica counts from metrics.
type Evaluator struct {
	metrics   *Metrics
	window    time.Duration
	minPoints int
	stabilize time.Duration
	tolerance float64
	upFactor  float64
	downStep  float64
	log       *slog.Logger
	now       func() time.Time

	mu    sync.Mutex
	state map[string]*serviceState
}

// serviceState is what the evaluator remembers between passes.
type serviceState struct {
	lastChange time.Time
	// since is when the evaluator started tracking this service: this
	// process, not this service's lifetime. A shrink is refused until a full
	// stabilization window has been *observed* (v1.37): the window's promise
	// is "stayed below current the whole time", and an empty history satisfies
	// any predicate vacuously. Without this, the first evaluation after a
	// daemon restart (or the first for a newly tracked service) could scale
	// down through a window it never saw.
	since time.Time
	// history is the recent raw desired counts, for the scale-down window. A
	// shrink is only allowed to the *highest* count the window contains, so one
	// quiet minute inside a busy five does not shed capacity.
	history []desiredAt
}

type desiredAt struct {
	at    time.Time
	count int
}

// NewEvaluator builds the policy engine.
func NewEvaluator(cfg EvaluatorConfig) (*Evaluator, error) {
	if cfg.Metrics == nil {
		return nil, fmt.Errorf("scaling: a metrics store is required")
	}
	if cfg.AverageWindow <= 0 {
		cfg.AverageWindow = DefaultAverageWindow
	}
	if cfg.MinPoints <= 0 {
		cfg.MinPoints = DefaultMinPoints
	}
	if cfg.ScaleDownStabilization <= 0 {
		cfg.ScaleDownStabilization = DefaultScaleDownStabilization
	}
	if cfg.Tolerance <= 0 {
		cfg.Tolerance = DefaultTolerance
	}
	if cfg.MaxScaleUpFactor <= 1 {
		cfg.MaxScaleUpFactor = DefaultMaxScaleUpFactor
	}
	if cfg.MaxScaleDownFactor <= 0 || cfg.MaxScaleDownFactor >= 1 {
		cfg.MaxScaleDownFactor = DefaultMaxScaleDownFactor
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Evaluator{
		metrics: cfg.Metrics, window: cfg.AverageWindow, minPoints: cfg.MinPoints,
		stabilize: cfg.ScaleDownStabilization, tolerance: cfg.Tolerance,
		upFactor: cfg.MaxScaleUpFactor, downStep: cfg.MaxScaleDownFactor,
		log: cfg.Logger, now: cfg.Now, state: map[string]*serviceState{},
	}, nil
}

// Evaluate decides what a service's replica count should be.
//
// It does not apply anything: the reconciler owns convergence, and a scaler
// that wrote counts directly would be a second thing deciding what runs. The
// caller applies the decision and calls Applied, which is what starts the
// cooldown, so a change the reconciler refused is retried next pass rather
// than silently counted as done.
func (e *Evaluator) Evaluate(service string, current int, policy Policy) Decision {
	decision := Decision{Service: service, Current: current, Desired: current}
	if !policy.Enabled() {
		decision.Reason = "no scaling policy"
		return decision
	}

	now := e.now()
	raw, rule, observed, ok := e.rawDesired(service, current, policy)
	if !ok {
		// Every rule was short of data. Doing nothing is the only honest
		// answer: an autoscaler that treats a missing metric as zero scales a
		// service to its minimum the moment its metrics pipeline breaks.
		decision.Reason = "no metrics yet"
		return decision
	}
	decision.Rule, decision.Observed, decision.Target = rule.Metric, observed, rule.Target

	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.stateFor(service)
	state.record(now, raw, e.stabilize)

	desired := clamp(raw, policy.Min, policy.Max)
	switch {
	case desired > current:
		desired = e.capStepUp(current, desired)
	case desired < current:
		// Scaling up trusts the moment; scaling down has to trust the window,
		// and a window the evaluator has not been watching for is not one it
		// may trust (v1.37); an empty history has no higher count in it for
		// the check below to find.
		if now.Sub(state.since) < e.stabilize {
			decision.Reason = fmt.Sprintf("holding %d: no full %s window observed yet",
				current, e.stabilize)
			return decision
		}
		// Only shrink to the highest count the stabilization window saw. This
		// is what makes scale-down cautious without a separate timer: a single
		// quiet evaluation inside a busy window changes nothing.
		windowed := clamp(state.maxDesired(now, e.stabilize), policy.Min, policy.Max)
		if windowed >= current {
			decision.Reason = fmt.Sprintf("holding %d: %s was higher within the last %s",
				current, rule.Metric, e.stabilize)
			return decision
		}
		desired = e.capStepDown(current, max(desired, windowed))
	}

	if desired == current {
		decision.Reason = fmt.Sprintf("%s %.1f is within tolerance of %.1f",
			rule.Metric, observed, rule.Target)
		return decision
	}

	// Cooldown last: a decision that is right but too soon is still a decision
	// worth reporting, and saying "waiting out the cooldown" is more useful
	// than saying nothing.
	cooldown := policy.Cooldown
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	if !state.lastChange.IsZero() && now.Sub(state.lastChange) < cooldown {
		decision.Reason = fmt.Sprintf("would move to %d, waiting out the %s cooldown",
			desired, cooldown)
		return decision
	}

	decision.Desired = desired
	decision.Changed = true
	decision.Reason = fmt.Sprintf("%s %.1f against a target of %.1f: %d → %d",
		rule.Metric, observed, rule.Target, current, desired)
	return decision
}

// Applied records that a decision was carried out, starting the cooldown.
//
// It is also the seed path (v1.37): at startup the daemon replays each
// service's persisted last-change time through it, so a scale applied two
// minutes before a restart still has three minutes of cooldown after it.
func (e *Evaluator) Applied(service string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stateFor(service).lastChange = at
}

// stateFor returns a service's state, creating it. The caller holds the lock.
//
// since is stamped from the evaluator's own clock, never from a caller's
// timestamp: a seeded cooldown carries a time from before the restart, and
// letting it stand as "tracked since" would hand the warm-up guard a window
// nobody watched.
func (e *Evaluator) stateFor(service string) *serviceState {
	state := e.state[service]
	if state == nil {
		state = &serviceState{since: e.now()}
		e.state[service] = state
	}
	return state
}

// Forget drops a service's history when it goes away.
func (e *Evaluator) Forget(service string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.state, service)
}

// rawDesired applies every rule and returns the largest result.
//
// The maximum, not the mean: the rules are constraints, and a service that is
// CPU-comfortable but latency-bound needs the count latency asks for. Taking an
// average would let a satisfied rule veto a breached one.
func (e *Evaluator) rawDesired(service string, current int, policy Policy) (int, Rule, float64, bool) {
	best, bestValue := 0, 0.0
	var bestRule Rule
	found := false

	for _, rule := range policy.Rules {
		if rule.Target <= 0 {
			continue
		}
		value, points := e.metrics.Average(Key{Subject: service, Metric: rule.Metric}, e.window)
		if points < e.minPoints {
			continue
		}

		ratio := value / rule.Target
		if math.Abs(ratio-1) <= e.tolerance {
			// Inside the dead band: this rule is satisfied and asks for what is
			// already running.
			ratio = 1
		}
		want := int(math.Ceil(float64(current) * ratio))
		if current == 0 {
			// A stopped service cannot be scaled proportionally: anything
			// times zero is zero. One replica is the smallest step that lets
			// the next evaluation have a ratio to work with.
			want = 1
			if ratio <= 1 {
				want = 0
			}
		}
		if !found || want > best {
			best, bestRule, bestValue, found = want, rule, value, true
		}
	}
	return best, bestRule, bestValue, found
}

// capStepUp bounds one upward step.
func (e *Evaluator) capStepUp(current, desired int) int {
	ceiling := int(math.Ceil(float64(current) * e.upFactor))
	if current == 0 {
		// Doubling zero is zero, so a service starting from stopped needs a
		// floor rather than a factor.
		ceiling = 1
	}
	return min(desired, ceiling)
}

// capStepDown bounds one downward step.
func (e *Evaluator) capStepDown(current, desired int) int {
	floor := int(math.Floor(float64(current) * e.downStep))
	return max(desired, floor)
}

// record appends a raw desired count and drops what the window no longer needs.
func (s *serviceState) record(at time.Time, desired int, window time.Duration) {
	s.history = append(s.history, desiredAt{at: at, count: desired})

	cutoff := at.Add(-window)
	keep := s.history[:0]
	for _, entry := range s.history {
		if !entry.at.Before(cutoff) {
			keep = append(keep, entry)
		}
	}
	s.history = keep
}

// maxDesired is the highest count the stabilization window contains.
func (s *serviceState) maxDesired(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	highest := 0
	for _, entry := range s.history {
		if entry.at.Before(cutoff) {
			continue
		}
		highest = max(highest, entry.count)
	}
	return highest
}

// clamp bounds a count to a policy's range.
func clamp(value, low, high int) int {
	if high > 0 && value > high {
		value = high
	}
	if value < low {
		value = low
	}
	if value < 0 {
		return 0
	}
	return value
}

// Services lists the services the evaluator holds state for, sorted. For the
// exporter and for tests.
func (e *Evaluator) Services() []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]string, 0, len(e.state))
	for service := range e.state {
		out = append(out, service)
	}
	sort.Strings(out)
	return out
}
