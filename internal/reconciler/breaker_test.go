package reconciler_test

import (
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
)

type breakerClock struct{ at time.Time }

func (c *breakerClock) now() time.Time          { return c.at }
func (c *breakerClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newBreaker(t *testing.T, adjust ...func(*reconciler.BreakerConfig)) (*reconciler.Breaker, *breakerClock) {
	t.Helper()
	c := &breakerClock{at: time.Unix(1_800_000_000, 0).UTC()}
	cfg := reconciler.BreakerConfig{Now: c.now}
	for _, apply := range adjust {
		apply(&cfg)
	}
	return reconciler.NewBreaker(cfg), c
}

func TestBreakerStartsClosed(t *testing.T) {
	b, _ := newBreaker(t)
	if allowed, why := b.Allow(); !allowed {
		t.Fatalf("a fresh breaker is open: %s", why)
	}
}

func TestBreakerTripsPastTheThreshold(t *testing.T) {
	b, _ := newBreaker(t)

	for i := range reconciler.DefaultBreakerThreshold - 1 {
		if tripped := b.RecordFailure("shop/web"); tripped {
			t.Fatalf("tripped at failure %d, below the threshold", i+1)
		}
	}
	// One service crash-looping is handled by its own restart backoff; the
	// breaker is for what that cannot explain.
	if allowed, _ := b.Allow(); !allowed {
		t.Fatal("open below the threshold")
	}

	if tripped := b.RecordFailure("shop/api"); !tripped {
		t.Fatal("did not trip at the threshold")
	}
	allowed, why := b.Allow()
	if allowed {
		t.Fatal("still allowing actions after tripping")
	}
	// The reason has to point at the node, which is where the operator should
	// be looking.
	if why == "" {
		t.Error("no reason given for a refusal")
	}
}

func TestFailuresAgeOutOfTheWindow(t *testing.T) {
	b, c := newBreaker(t)

	// Nine failures, then a long quiet period, then one more. A breaker that
	// counted forever would trip on a node that has been healthy for an hour.
	for range reconciler.DefaultBreakerThreshold - 1 {
		b.RecordFailure("shop/web")
	}
	c.advance(2 * reconciler.DefaultBreakerWindow)

	if tripped := b.RecordFailure("shop/web"); tripped {
		t.Fatal("tripped on failures that had aged out of the window")
	}
	if allowed, _ := b.Allow(); !allowed {
		t.Fatal("open after the failures aged out")
	}
}

func TestBreakerClosesAfterTheCooldown(t *testing.T) {
	b, c := newBreaker(t)
	for range reconciler.DefaultBreakerThreshold {
		b.RecordFailure("shop/web")
	}
	if allowed, _ := b.Allow(); allowed {
		t.Fatal("did not trip")
	}

	// Still open partway through: a node that looks better after thirty seconds
	// is exactly the judgement the cooldown exists to distrust.
	c.advance(reconciler.DefaultBreakerCooldown / 2)
	if allowed, _ := b.Allow(); allowed {
		t.Fatal("closed halfway through the cooldown")
	}

	c.advance(reconciler.DefaultBreakerCooldown)
	if allowed, _ := b.Allow(); !allowed {
		t.Fatal("never closed; a fixed node would need an operator to resume it")
	}
}

func TestResetClosesImmediately(t *testing.T) {
	b, _ := newBreaker(t)
	for range reconciler.DefaultBreakerThreshold {
		b.RecordFailure("shop/web")
	}

	b.Reset()
	if allowed, why := b.Allow(); !allowed {
		t.Fatalf("still open after a reset: %s", why)
	}
	// And the failures that tripped it are cleared too, so the next one does
	// not immediately re-trip it.
	if tripped := b.RecordFailure("shop/web"); tripped {
		t.Fatal("re-tripped on the first failure after a reset")
	}
}

func TestTripsAreCounted(t *testing.T) {
	b, c := newBreaker(t)
	for range reconciler.DefaultBreakerThreshold {
		b.RecordFailure("shop/web")
	}
	if b.Trips() != 1 {
		t.Fatalf("trips = %d, want 1", b.Trips())
	}

	// Failures while already open must not count as new trips: an event per
	// failure during an outage is a notification storm.
	for range reconciler.DefaultBreakerThreshold {
		b.RecordFailure("shop/web")
	}
	if b.Trips() != 1 {
		t.Fatalf("trips = %d; a single outage produced several", b.Trips())
	}

	// A genuinely separate outage does count.
	c.advance(2 * reconciler.DefaultBreakerCooldown)
	b.Reset()
	for range reconciler.DefaultBreakerThreshold {
		b.RecordFailure("shop/web")
	}
	if b.Trips() != 2 {
		t.Fatalf("trips = %d, want 2", b.Trips())
	}
}

func TestBreakerIsConcurrencySafe(t *testing.T) {
	b, _ := newBreaker(t, func(cfg *reconciler.BreakerConfig) { cfg.Threshold = 1000 })
	done := make(chan struct{})

	go func() {
		defer close(done)
		for range 500 {
			b.RecordFailure("shop/web")
		}
	}()
	for range 500 {
		b.Allow()
		b.Open()
	}
	<-done
}

// The breaker is only useful if the reconciler feeds it, which no unit test of
// the breaker itself can check.
func TestCrashesReachTheBreaker(t *testing.T) {
	c := &breakerClock{at: time.Unix(1_800_000_000, 0).UTC()}
	b := reconciler.NewBreaker(reconciler.BreakerConfig{Threshold: 3, Now: c.now})

	h := newHarness(t, func(cfg *reconciler.Config) { cfg.Breaker = b })
	d := desired(3)
	d.Restart = reconciler.RestartPolicy{Attempts: 5, Backoff: []time.Duration{time.Minute}}
	h.setDesired(t, d)
	h.reconcile(t)

	// Three allocs crash at once — the shape of a node-wide fault rather than
	// one bad service, which is what the breaker is for.
	for i := range 3 {
		h.driver.crash(reconciler.AllocID("shop", "web", i), 137, h.now)
	}
	h.reconcile(t)

	if allowed, why := b.Allow(); allowed {
		t.Fatalf("three simultaneous crashes did not trip the breaker (why=%q)", why)
	}
}

// A crash that lands in backoff counts as much as one that exhausts the restart
// budget: a node where every alloc dies on first start never reaches a budget,
// and that is precisely the case §4.3 is about.
func TestBackoffCountsTowardTheBreaker(t *testing.T) {
	c := &breakerClock{at: time.Unix(1_800_000_000, 0).UTC()}
	b := reconciler.NewBreaker(reconciler.BreakerConfig{Threshold: 2, Now: c.now})

	h := newHarness(t, func(cfg *reconciler.Config) { cfg.Breaker = b })
	d := desired(2)
	// A generous restart budget, so neither alloc reaches AllocFailed.
	d.Restart = reconciler.RestartPolicy{Attempts: 99, Backoff: []time.Duration{time.Hour}}
	h.setDesired(t, d)
	h.reconcile(t)

	for i := range 2 {
		h.driver.crash(reconciler.AllocID("shop", "web", i), 1, h.now)
	}
	h.reconcile(t)

	if allowed, _ := b.Allow(); allowed {
		t.Fatal("crashes that landed in backoff did not reach the breaker")
	}
}

func trip(t *testing.T, b *reconciler.Breaker) {
	t.Helper()
	for range reconciler.DefaultBreakerThreshold {
		b.RecordFailure("shop/web")
	}
	if allowed, _ := b.Allow(); allowed {
		t.Fatal("the breaker did not trip")
	}
}

func TestRestoreReopensWithinCooldown(t *testing.T) {
	// The scenario the persistence exists for (v1.37): the breaker tripped,
	// the daemon restarted two minutes into the cooldown, and the node is
	// still broken. The restored breaker refuses with the time that is
	// actually left, not a fresh cooldown.
	b, c := newBreaker(t)
	trippedAt := c.at.Add(-2 * time.Minute)

	b.Restore(trippedAt, 3, reconciler.DefaultBreakerThreshold)

	allowed, why := b.Allow()
	if allowed {
		t.Fatal("a restored trip inside its cooldown allowed actions")
	}
	if why == "" {
		t.Error("no reason given for the restored refusal")
	}
	if b.Trips() != 3 {
		t.Errorf("trips = %d, want the restored 3", b.Trips())
	}

	// The remaining cooldown is the original one, measured from the original
	// trip — not restarted at the restore.
	c.advance(3*time.Minute + time.Second)
	if allowed, _ := b.Allow(); !allowed {
		t.Error("still open after the original cooldown expired")
	}
}

func TestRestoreIgnoresAnExpiredTrip(t *testing.T) {
	b, c := newBreaker(t)
	b.Restore(c.at.Add(-reconciler.DefaultBreakerCooldown), 5, reconciler.DefaultBreakerThreshold)

	if allowed, why := b.Allow(); !allowed {
		t.Fatalf("a trip that expired while the daemon was down reopened: %s", why)
	}
	// The count still carries: the exporter's counter must not restart at zero.
	if b.Trips() != 5 {
		t.Errorf("trips = %d, want 5", b.Trips())
	}
}

func TestRestoredFailuresCannotCauseASecondTrip(t *testing.T) {
	// The restored samples are stamped at the trip, so once the cooldown
	// expires they are long out of the window — one fresh failure on a
	// recovered node must not re-trip on inherited history.
	b, c := newBreaker(t)
	b.Restore(c.at.Add(-time.Minute), 1, reconciler.DefaultBreakerThreshold)

	c.advance(reconciler.DefaultBreakerCooldown)
	if tripped := b.RecordFailure("shop/web"); tripped {
		t.Fatal("one failure after recovery re-tripped on restored samples")
	}
}

func TestPersistFiresOnTransitionsOnly(t *testing.T) {
	// The record is written on trip and on reset, never per failure sample —
	// a per-failure write would be a metric stream into the Store.
	var calls []time.Time
	b, c := newBreaker(t, func(cfg *reconciler.BreakerConfig) {
		cfg.Persist = func(trippedAt time.Time, trips, _ int) {
			calls = append(calls, trippedAt)
			if trips != 1 && !trippedAt.IsZero() {
				t.Errorf("persisted trips = %d at the first trip", trips)
			}
		}
	})

	trip(t, b)
	if len(calls) != 1 {
		t.Fatalf("%d failures persisted %d records, want exactly 1 (the trip)",
			reconciler.DefaultBreakerThreshold, len(calls))
	}
	if !calls[0].Equal(c.at) {
		t.Errorf("persisted trip time %v, want %v", calls[0], c.at)
	}

	b.Reset()
	if len(calls) != 2 {
		t.Fatalf("reset persisted %d records, want 1", len(calls)-1)
	}
	if !calls[1].IsZero() {
		t.Error("a reset persisted a non-zero trip time")
	}
}
