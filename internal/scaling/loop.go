package scaling

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Service is what the loop needs to know about one service to scale it.
type Service struct {
	// Key is "project/service", which is also the metric subject.
	Key   string
	Count int
	// Policy is the declared scaling configuration.
	Policy Policy
}

// Fleet is where the loop reads desired state and writes a new count.
//
// Narrow on purpose: the autoscaler is not a second scheduler. It changes one
// number and lets the reconciler converge, which is what keeps health-gated
// rollouts, dependency order and restart policy in one place (§9.2).
type Fleet interface {
	// Services lists what is running and what policy governs it.
	Services(ctx context.Context) ([]Service, error)
	// SetCount records a new desired count. The reconciler does the rest.
	SetCount(ctx context.Context, service string, count int) error
}

// Recorder receives scaling decisions that were acted on, for the event log
// and notifications (§9.2: "every action emits an event").
type Recorder interface {
	ScaleDecided(ctx context.Context, d Decision)
}

// Breaker reports whether scale actions are currently permitted.
//
// The global circuit breaker of §4.3. It is an interface here so the loop does
// not have to know what trips it: node-wide failure rates are the reconciler's
// business, not the autoscaler's.
type Breaker interface {
	// Allow reports whether a scale action may proceed, and why not.
	Allow() (bool, string)
}

// LoopConfig configures the autoscaling loop.
type LoopConfig struct {
	Evaluator *Evaluator
	Fleet     Fleet
	Recorder  Recorder
	Breaker   Breaker
	// Interval defaults to DefaultEvaluationInterval.
	Interval time.Duration
	Logger   *slog.Logger
	Now      func() time.Time
}

// Loop evaluates every service on a ticker and applies what it decides.
type Loop struct {
	eval     *Evaluator
	fleet    Fleet
	recorder Recorder
	breaker  Breaker
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
}

// NewLoop builds the autoscaling loop.
func NewLoop(cfg LoopConfig) (*Loop, error) {
	if cfg.Evaluator == nil {
		return nil, errors.New("scaling: an evaluator is required")
	}
	if cfg.Fleet == nil {
		return nil, errors.New("scaling: a fleet is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultEvaluationInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Loop{
		eval: cfg.Evaluator, fleet: cfg.Fleet, recorder: cfg.Recorder,
		breaker: cfg.Breaker, interval: cfg.Interval, log: cfg.Logger, now: cfg.Now,
	}, nil
}

// Run evaluates until the context ends.
func (l *Loop) Run(ctx context.Context) {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := l.Once(ctx); err != nil {
			l.log.Warn("scaling pass failed", "error", err)
		}
	}
}

// Once runs a single pass and reports how many services it changed.
func (l *Loop) Once(ctx context.Context) (changed int, err error) {
	services, err := l.fleet.Services(ctx)
	if err != nil {
		return 0, fmt.Errorf("scaling: read services: %w", err)
	}

	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		seen[svc.Key] = true
		if !svc.Policy.Enabled() {
			continue
		}

		decision := l.eval.Evaluate(svc.Key, svc.Count, svc.Policy)
		if !decision.Changed {
			// Logged at debug because it is the common case and happens every
			// few seconds for every service on the node.
			l.log.Debug("no scale change", "service", svc.Key, "reason", decision.Reason)
			continue
		}

		// The breaker is checked here rather than before evaluating, so a
		// tripped breaker still produces a decision to record and a reason an
		// operator can read: "we would have scaled, and why we did not".
		if l.breaker != nil {
			if allowed, why := l.breaker.Allow(); !allowed {
				l.log.Warn("scale action suppressed by the circuit breaker",
					"service", svc.Key, "want", decision.Desired, "reason", why)
				continue
			}
		}

		if err := l.fleet.SetCount(ctx, svc.Key, decision.Desired); err != nil {
			// Not fatal to the pass: one service failing to scale must not stop
			// the rest. The cooldown is deliberately not started, so this is
			// retried on the next tick.
			l.log.Error("cannot apply a scale decision",
				"service", svc.Key, "want", decision.Desired, "error", err)
			continue
		}

		l.eval.Applied(svc.Key, l.now())
		changed++
		l.log.Info("scaled", "service", svc.Key,
			"from", decision.Current, "to", decision.Desired, "reason", decision.Reason)
		if l.recorder != nil {
			l.recorder.ScaleDecided(ctx, decision)
		}
	}

	// A service that no longer exists takes its cooldown and history with it,
	// so a name reused later is not held back by the one it replaced.
	for _, service := range l.eval.Services() {
		if !seen[service] {
			l.eval.Forget(service)
		}
	}
	return changed, nil
}
