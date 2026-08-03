package reconciler

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// The global circuit breaker (PRD §4.3).
//
// It exists for one failure mode: a node where something systemic has broken —
// a full disk, a dead registry, a bad kernel upgrade — and every alloc that
// starts fails within seconds. The reconciler's job is to restart failed
// allocs, so its correct behaviour becomes the thing amplifying the problem,
// and the autoscaler's correct behaviour adds replicas to services that cannot
// start. Both are right locally and catastrophic together.
//
// What it does is narrow and deliberate: it pauses **rollouts and scale
// actions**. It does not pause crash restarts, because a service that is
// crash-looping for its own reasons still needs its restart policy, and
// stopping that would turn one broken service into an outage. The breaker is
// about not making a bad node worse, not about giving up on it.

// Breaker trips when failures across the node exceed a rate.
type Breaker struct {
	threshold int
	window    time.Duration
	cooldown  time.Duration
	log       *slog.Logger
	now       func() time.Time

	mu sync.Mutex
	// failures holds the timestamps inside the window. Bounded by the threshold
	// it is compared against, not by how bad things get.
	failures []time.Time
	// trippedAt is when it last opened, zero when closed.
	trippedAt time.Time
	// trips counts openings, for the exporter and for tests.
	trips int
}

// Defaults for the breaker.
const (
	// DefaultBreakerThreshold is how many alloc failures inside the window trip
	// it. Ten is well above the noise of a single service crash-looping — which
	// its own restart backoff already handles — and well below what a node-wide
	// fault produces in the same time.
	DefaultBreakerThreshold = 10
	// DefaultBreakerWindow is the period failures are counted over.
	DefaultBreakerWindow = time.Minute
	// DefaultBreakerCooldown is how long it stays open once tripped. Long
	// enough that a flapping node does not get a rollout every few seconds,
	// short enough that a fixed node resumes without an operator.
	DefaultBreakerCooldown = 5 * time.Minute
)

// BreakerConfig configures the breaker.
type BreakerConfig struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
	Logger    *slog.Logger
	Now       func() time.Time
}

// NewBreaker builds a closed breaker.
func NewBreaker(cfg BreakerConfig) *Breaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultBreakerThreshold
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultBreakerWindow
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultBreakerCooldown
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{
		threshold: cfg.Threshold, window: cfg.Window, cooldown: cfg.Cooldown,
		log: cfg.Logger, now: cfg.Now,
	}
}

// RecordFailure notes one alloc failure and reports whether it tripped.
func (b *Breaker) RecordFailure(service string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.failures = append(b.failures, now)
	b.prune(now)

	if len(b.failures) < b.threshold || b.openAt(now) {
		return false
	}

	b.trippedAt = now
	b.trips++
	// Warn, not error: the breaker working is the system behaving correctly
	// under a fault, and an operator reading this needs to look at the *node*,
	// which is what the message says.
	b.log.Warn("circuit breaker tripped: pausing rollouts and scale actions",
		"failures", len(b.failures), "window", b.window, "cooldown", b.cooldown,
		"last_service", service,
		"detail", "this many allocs failing across the node usually means something "+
			"systemic — disk, registry, or the runtime — rather than one bad service")
	return true
}

// Allow reports whether a rollout or scale action may proceed.
func (b *Breaker) Allow() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if !b.openAt(now) {
		return true, ""
	}
	remaining := b.cooldown - now.Sub(b.trippedAt)
	return false, fmt.Sprintf("%d alloc failures within %s; resuming in %s",
		len(b.failures), b.window, remaining.Round(time.Second))
}

// Open reports whether the breaker is currently open.
func (b *Breaker) Open() bool {
	allowed, _ := b.Allow()
	return !allowed
}

// Trips is how many times it has opened, for the exporter.
func (b *Breaker) Trips() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.trips
}

// Reset closes the breaker immediately.
//
// For an operator who has fixed the node and does not want to wait out the
// cooldown. Deliberately manual: nothing automatic clears it early, because
// "it looks better now" is exactly the judgement the cooldown exists to
// distrust.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.trippedAt.IsZero() {
		b.log.Info("circuit breaker reset by request")
	}
	b.trippedAt = time.Time{}
	b.failures = nil
}

// openAt reports whether the breaker is open at a given instant. The caller
// holds the lock.
func (b *Breaker) openAt(now time.Time) bool {
	if b.trippedAt.IsZero() {
		return false
	}
	if now.Sub(b.trippedAt) < b.cooldown {
		return true
	}
	// The cooldown expired. Closing here rather than on a timer means the
	// breaker needs no goroutine and cannot leak one.
	b.trippedAt = time.Time{}
	b.log.Info("circuit breaker closed; rollouts and scale actions resume")
	return false
}

// prune drops failures that have aged out. The caller holds the lock.
func (b *Breaker) prune(now time.Time) {
	cutoff := now.Add(-b.window)
	keep := b.failures[:0]
	for _, at := range b.failures {
		if !at.Before(cutoff) {
			keep = append(keep, at)
		}
	}
	b.failures = keep
}
