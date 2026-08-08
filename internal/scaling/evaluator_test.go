package scaling_test

import (
	"testing"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// evalHarness is an evaluator over a metrics store both share a clock with.
type evalHarness struct {
	eval    *scaling.Evaluator
	metrics *scaling.Metrics
	clock   *clock
}

func newEval(t *testing.T, adjust ...func(*scaling.EvaluatorConfig)) *evalHarness {
	t.Helper()
	c := newClock()
	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	cfg := scaling.EvaluatorConfig{Metrics: m, Now: c.now}
	for _, apply := range adjust {
		apply(&cfg)
	}
	e, err := scaling.NewEvaluator(cfg)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return &evalHarness{eval: e, metrics: m, clock: c}
}

// feed records n samples of a metric, advancing the clock between them.
func (h *evalHarness) feed(service, metric string, value float64, n int) {
	for range n {
		h.metrics.Record(scaling.Key{Subject: service, Metric: metric}, h.clock.at, value)
		h.clock.advance(scaling.RawInterval)
	}
}

// feedAll records samples for several services over the same span of time.
//
// feed advances the clock as it goes, so feeding two services in sequence would
// leave the first one's samples outside the trailing average window by the time
// the second finished — which looks exactly like a service with no metrics.
func (h *evalHarness) feedAll(metric string, value float64, n int, services ...string) {
	for range n {
		for _, service := range services {
			h.metrics.Record(scaling.Key{Subject: service, Metric: metric}, h.clock.at, value)
		}
		h.clock.advance(scaling.RawInterval)
	}
}

// cpuPolicy is the shape §6.1 writes: `metric "cpu" { target = 70 }`.
func cpuPolicy(minReplicas, maxReplicas int) scaling.Policy {
	return scaling.Policy{
		Min: minReplicas, Max: maxReplicas,
		Rules:    []scaling.Rule{{Metric: scaling.MetricCPU, Target: 70}},
		Cooldown: time.Minute,
	}
}

func TestScalesUpProportionally(t *testing.T) {
	h := newEval(t)
	// 140% of a 70% target on 2 replicas asks for 4.
	h.feed("shop/web", scaling.MetricCPU, 140, 6)

	d := h.eval.Evaluate("shop/web", 2, cpuPolicy(1, 10))
	if !d.Changed || d.Desired != 4 {
		t.Fatalf("decision = %+v; want a change to 4", d)
	}
	// The reason is what the event, the notification and the dashboard show.
	if d.Rule != scaling.MetricCPU || d.Observed < 139 || d.Observed > 141 {
		t.Errorf("decision does not say what drove it: %+v", d)
	}
}

func TestDoesNothingWithoutMetrics(t *testing.T) {
	h := newEval(t)
	// The failure mode this prevents: a metrics pipeline that breaks would
	// otherwise read as zero load and shrink every service to its minimum.
	d := h.eval.Evaluate("shop/web", 5, cpuPolicy(1, 10))
	if d.Changed {
		t.Fatalf("scaled with no metrics: %+v", d)
	}
	if d.Desired != 5 {
		t.Errorf("desired = %d, want the current count left alone", d.Desired)
	}
}

func TestRefusesToActOnTooFewSamples(t *testing.T) {
	h := newEval(t)
	// Two samples can both be wrong in the same direction; the minimum exists
	// so one anomalous scrape cannot move a service.
	h.feed("shop/web", scaling.MetricCPU, 500, 2)

	if d := h.eval.Evaluate("shop/web", 2, cpuPolicy(1, 10)); d.Changed {
		t.Fatalf("acted on two samples: %+v", d)
	}
}

func TestToleranceStopsOscillation(t *testing.T) {
	h := newEval(t)
	// 73 against a target of 70 is 4% over. Acting on it means acting on every
	// evaluation forever.
	h.feed("shop/web", scaling.MetricCPU, 73, 6)

	if d := h.eval.Evaluate("shop/web", 3, cpuPolicy(1, 10)); d.Changed {
		t.Fatalf("changed inside the tolerance band: %+v", d)
	}
}

func TestClampsToMax(t *testing.T) {
	h := newEval(t)
	h.feed("shop/web", scaling.MetricCPU, 700, 6) // asks for 10× the replicas

	d := h.eval.Evaluate("shop/web", 4, cpuPolicy(1, 6))
	if d.Desired > 6 {
		t.Fatalf("desired = %d, past the declared max of 6", d.Desired)
	}
}

func TestClampsToMin(t *testing.T) {
	h := newEval(t)
	h.feed("shop/web", scaling.MetricCPU, 0, 6)

	// Even at zero load the floor holds: min is a statement about availability,
	// not about efficiency.
	d := h.eval.Evaluate("shop/web", 4, cpuPolicy(2, 10))
	if d.Desired < 2 {
		t.Fatalf("desired = %d, below the declared min of 2", d.Desired)
	}
}

func TestScaleUpIsStepLimited(t *testing.T) {
	h := newEval(t)
	// A spike asking for 20× must not take a service from 2 to 40 in one step:
	// a bad reading and a real surge look identical for one evaluation.
	h.feed("shop/web", scaling.MetricCPU, 1400, 6)

	d := h.eval.Evaluate("shop/web", 2, cpuPolicy(1, 100))
	if d.Desired != 4 {
		t.Fatalf("desired = %d, want the 2× step cap", d.Desired)
	}
}

func TestSustainedLoadStillReachesTheTarget(t *testing.T) {
	h := newEval(t)
	policy := cpuPolicy(1, 100)
	policy.Cooldown = time.Nanosecond // the step cap is what is under test

	// The step cap bounds one evaluation, not the trend. Repeated evaluations
	// under sustained load must still converge, or the cap would be a ceiling.
	current := 2
	for range 5 {
		h.feed("shop/web", scaling.MetricCPU, 1400, 6)
		d := h.eval.Evaluate("shop/web", current, policy)
		if d.Changed {
			current = d.Desired
			h.eval.Applied("shop/web", h.clock.at)
		}
		h.clock.advance(time.Minute)
	}
	if current < 20 {
		t.Fatalf("reached only %d replicas under sustained load; the step cap became a ceiling", current)
	}
}

func TestScaleDownWaitsForTheWholeWindow(t *testing.T) {
	h := newEval(t)
	policy := cpuPolicy(1, 10)
	policy.Cooldown = time.Nanosecond

	// Busy, then quiet. Shrinking on the first quiet evaluation is how a
	// service loses capacity thirty seconds before the traffic returns.
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	h.eval.Evaluate("shop/web", 4, policy)

	h.feed("shop/web", scaling.MetricCPU, 10, 6)
	if d := h.eval.Evaluate("shop/web", 4, policy); d.Changed {
		t.Fatalf("shrank immediately: %+v", d)
	}

	// Once the whole window has been quiet, it may shrink.
	h.clock.advance(scaling.DefaultScaleDownStabilization)
	h.feed("shop/web", scaling.MetricCPU, 10, 6)
	d := h.eval.Evaluate("shop/web", 4, policy)
	if !d.Changed || d.Desired >= 4 {
		t.Fatalf("decision = %+v; want a shrink after the window", d)
	}
}

func TestScaleDownIsStepLimited(t *testing.T) {
	h := newEval(t)
	policy := scaling.Policy{
		Min: 1, Max: 100,
		Rules:    []scaling.Rule{{Metric: scaling.MetricCPU, Target: 70}},
		Cooldown: time.Nanosecond,
	}

	// Idle for the whole window, asking for 1 from 20. Halving is the cap: a
	// service does not shed 95% of its capacity on one evaluation.
	for range 3 {
		h.feed("shop/web", scaling.MetricCPU, 1, 12)
		h.eval.Evaluate("shop/web", 20, policy)
		h.clock.advance(2 * time.Minute)
	}
	// Fresh samples: the averaging window is trailing, so the two-minute jump
	// above left nothing recent enough to decide on.
	h.feed("shop/web", scaling.MetricCPU, 1, 6)
	d := h.eval.Evaluate("shop/web", 20, policy)
	if !d.Changed {
		t.Fatalf("never shrank: %+v", d)
	}
	if d.Desired < 10 {
		t.Fatalf("desired = %d, past the 0.5× step cap from 20", d.Desired)
	}
}

func TestCooldownSpacesChanges(t *testing.T) {
	h := newEval(t)
	policy := cpuPolicy(1, 10)

	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	d := h.eval.Evaluate("shop/web", 2, policy)
	if !d.Changed {
		t.Fatalf("no first change: %+v", d)
	}
	h.eval.Applied("shop/web", h.clock.at)

	// A rollout has to finish and show up in the metrics before the next
	// decision is based on them.
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	d = h.eval.Evaluate("shop/web", 4, policy)
	if d.Changed {
		t.Fatalf("changed inside the cooldown: %+v", d)
	}
	// And it says so, rather than reporting nothing.
	if d.Reason == "" {
		t.Error("a suppressed decision gave no reason")
	}

	h.clock.advance(2 * time.Minute)
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if d := h.eval.Evaluate("shop/web", 4, policy); !d.Changed {
		t.Fatalf("still suppressed after the cooldown: %+v", d)
	}
}

func TestAFailedApplyDoesNotStartTheCooldown(t *testing.T) {
	h := newEval(t)
	policy := cpuPolicy(1, 10)

	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if d := h.eval.Evaluate("shop/web", 2, policy); !d.Changed {
		t.Fatalf("no decision: %+v", d)
	}
	// The caller does not call Applied, because the reconciler refused it. The
	// next pass must retry rather than treat the change as done.
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if d := h.eval.Evaluate("shop/web", 2, policy); !d.Changed {
		t.Fatalf("a refused change was counted as applied: %+v", d)
	}
}

func TestTheMostDemandingRuleWins(t *testing.T) {
	h := newEval(t)
	// CPU is comfortable, latency is not. The rules are constraints, so the
	// count is whatever the breached one needs — an average would let the
	// satisfied rule veto it.
	h.feed("shop/web", scaling.MetricCPU, 35, 6)
	h.feed("shop/web", scaling.MetricP95, 1600, 6)

	policy := scaling.Policy{
		Min: 1, Max: 20,
		Rules: []scaling.Rule{
			{Metric: scaling.MetricCPU, Target: 70},
			{Metric: scaling.MetricP95, Target: 800},
		},
		Cooldown: time.Minute,
	}
	d := h.eval.Evaluate("shop/web", 2, policy)
	if !d.Changed || d.Desired != 4 {
		t.Fatalf("decision = %+v; want latency to drive it to 4", d)
	}
	if d.Rule != scaling.MetricP95 {
		t.Errorf("rule = %q, want the breached one named", d.Rule)
	}
}

func TestARuleWithNoDataIsSkippedNotZero(t *testing.T) {
	h := newEval(t)
	// rps has samples; p95 has none. The missing rule must not pull the
	// decision down as though latency were zero.
	h.feed("shop/web", scaling.MetricRPS, 1000, 6)

	policy := scaling.Policy{
		Min: 1, Max: 20,
		Rules: []scaling.Rule{
			{Metric: scaling.MetricRPS, Target: 500},
			{Metric: scaling.MetricP95, Target: 800},
		},
		Cooldown: time.Minute,
	}
	d := h.eval.Evaluate("shop/web", 2, policy)
	if !d.Changed || d.Desired != 4 {
		t.Fatalf("decision = %+v; want rps alone to drive it", d)
	}
}

func TestNoPolicyMeansNoScaling(t *testing.T) {
	h := newEval(t)
	h.feed("shop/web", scaling.MetricCPU, 1000, 6)

	for _, policy := range []scaling.Policy{
		{},                // nothing declared
		{Min: 1, Max: 0},  // max zero: the declared count stands
		{Min: 1, Max: 10}, // bounds but no rules
	} {
		if d := h.eval.Evaluate("shop/web", 3, policy); d.Changed {
			t.Fatalf("policy %+v scaled anyway: %+v", policy, d)
		}
	}
}

func TestAStoppedServiceCanStart(t *testing.T) {
	h := newEval(t)
	// Anything times zero is zero, so a proportional rule alone can never lift
	// a stopped service. One replica is the smallest step that gives the next
	// evaluation a ratio to work with.
	h.feed("shop/web", scaling.MetricRPS, 900, 6)

	policy := scaling.Policy{
		Min: 0, Max: 10,
		Rules:    []scaling.Rule{{Metric: scaling.MetricRPS, Target: 500}},
		Cooldown: time.Minute,
	}
	d := h.eval.Evaluate("shop/web", 0, policy)
	if !d.Changed || d.Desired != 1 {
		t.Fatalf("decision = %+v; want a stopped service to start at 1", d)
	}
}

func TestForgetDropsHistory(t *testing.T) {
	h := newEval(t)
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	h.eval.Evaluate("shop/web", 2, cpuPolicy(1, 10))
	h.eval.Applied("shop/web", h.clock.at)

	h.eval.Forget("shop/web")
	if len(h.eval.Services()) != 0 {
		t.Fatalf("state survived Forget: %v", h.eval.Services())
	}
	// And with the cooldown forgotten, a redeployed service is not held back by
	// the history of the one it replaced.
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if d := h.eval.Evaluate("shop/web", 2, cpuPolicy(1, 10)); !d.Changed {
		t.Fatalf("a forgotten service is still in cooldown: %+v", d)
	}
}

func TestNewEvaluatorRequiresMetrics(t *testing.T) {
	if _, err := scaling.NewEvaluator(scaling.EvaluatorConfig{}); err == nil {
		t.Fatal("an evaluator with no metrics was accepted")
	}
}

// PRD v1.21 budgets 20 s from a sustained metric breach to a scale decision:
// the averaging window plus one evaluation tick. A default changed without
// checking would blow it silently, and the number is a promise in §21.
func TestDecisionLatencyFitsTheBudget(t *testing.T) {
	const budget = 20 * time.Second
	if got := scaling.DefaultAverageWindow + scaling.DefaultEvaluationInterval; got > budget {
		t.Fatalf("a breach takes up to %s to reach a decision, past the %s §21 allows", got, budget)
	}
}
