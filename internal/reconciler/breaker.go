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
	persist   func(trippedAt time.Time, trips, failures int)

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
	// Persist is called on trip and on reset — the transitions, never the
	// per-failure samples — so the open state can survive a restart (v1.37).
	// A daemon restart is most likely during exactly the node-wide fault the
	// breaker guards against, and before this the restart silently re-enabled
	// the rollouts the breaker had paused. Called outside the breaker's lock;
	// best-effort, so a failed write never blocks a trip. Nil disables it.
	Persist func(trippedAt time.Time, trips, failures int)
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
		log: cfg.Logger, now: cfg.Now, persist: cfg.Persist,
	}
}

// Restore seeds the breaker from state persisted before a restart (v1.37).
//
// The trip count always carries over — the exporter's counter should not
// restart at zero. The open state carries over only while its cooldown still
// has time left; a trip that expired while the daemon was down reads as
// closed, exactly as it would have had the daemon stayed up. The failure
// window is deliberately not restored beyond the count at the trip: a node
// still faulting refills it within one window, and a node that recovered
// should not inherit stale samples.
func (b *Breaker) Restore(trippedAt time.Time, trips, failures int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trips = trips
	if trippedAt.IsZero() {
		return
	}
	now := b.now()
	remaining := b.cooldown - now.Sub(trippedAt)
	if remaining <= 0 {
		return
	}
	b.trippedAt = trippedAt
	// The failures that tripped it, stamped at the trip. They make Allow's
	// refusal honest and age out of the window on their own — the cooldown
	// outlives the window, so they can never contribute to a second trip.
	for range failures {
		b.failures = append(b.failures, trippedAt)
	}
	b.log.Warn("circuit breaker restored open from before the restart",
		"tripped_at", trippedAt, "resuming_in", remaining.Round(time.Second))
}

// RecordFailure notes one alloc failure and reports whether it tripped.
func (b *Breaker) RecordFailure(service string) bool {
	b.mu.Lock()

	now := b.now()
	b.failures = append(b.failures, now)
	b.prune(now)

	if len(b.failures) < b.threshold || b.openAt(now) {
		b.mu.Unlock()
		return false
	}

	b.trippedAt = now
	b.trips++
	trips, failures := b.trips, len(b.failures)
	// Warn, not error: the breaker working is the system behaving correctly
	// under a fault, and an operator reading this needs to look at the *node*,
	// which is what the message says.
	b.log.Warn("circuit breaker tripped: pausing rollouts and scale actions",
		"failures", failures, "window", b.window, "cooldown", b.cooldown,
		"last_service", service,
		"detail", "this many allocs failing across the node usually means something "+
			"systemic — disk, registry, or the runtime — rather than one bad service")
	b.mu.Unlock()

	// Outside the lock: a Store write must never sit between Allow and its
	// caller. The fault the breaker just tripped on may be the disk, so the
	// write is best-effort by design — the in-memory state is authoritative.
	if b.persist != nil {
		b.persist(now, trips, failures)
	}
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
	if !b.trippedAt.IsZero() {
		b.log.Info("circuit breaker reset by request")
	}
	b.trippedAt = time.Time{}
	b.failures = nil
	trips := b.trips
	b.mu.Unlock()

	// A put with a zero trip time rather than a delete, so the trip count the
	// exporter publishes stays monotonic across restarts.
	if b.persist != nil {
		b.persist(time.Time{}, trips, 0)
	}
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
