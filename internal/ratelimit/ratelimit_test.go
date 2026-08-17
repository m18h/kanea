package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// testClock drives the limiter's notion of time: every property here is about
// what happens as time passes, and none of it is testable against a real clock.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func testSpec(requests int, window time.Duration) Spec {
	return Spec{Requests: requests, Window: window}
}

func TestLimiterSpendsAndRefills(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(16, clock.Now)
	spec := testSpec(3, time.Minute)

	for i := range 3 {
		if ok, _ := l.Allow("a", spec); !ok {
			t.Fatalf("request %d refused with a full bucket", i)
		}
	}
	ok, retry := l.Allow("a", spec)
	if ok {
		t.Fatal("a fourth request passed a limit of three")
	}
	if retry <= 0 {
		t.Errorf("retry = %v, want a positive wait", retry)
	}

	// A third of a window buys back exactly one token.
	clock.advance(20 * time.Second)
	if ok, _ := l.Allow("a", spec); !ok {
		t.Error("no token after a third of the window")
	}
	if ok, _ := l.Allow("a", spec); ok {
		t.Error("two tokens after a third of the window")
	}
}

// An idle client accumulates a burst, not an unbounded credit: a bucket that
// kept filling would let someone quiet for a day arrive with a day's traffic.
func TestLimiterCapsAccumulation(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(16, clock.Now)
	spec := testSpec(5, time.Minute)

	clock.advance(24 * time.Hour)

	var allowed int
	for range 100 {
		if ok, _ := l.Allow("a", spec); ok {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("allowed %d after a day idle, want the bucket size 5", allowed)
	}
}

// The bucket set is bounded because its keys are chosen by whoever sends
// traffic. Without a cap this map is a memory exhaustion vector reachable by
// anyone who can open connections.
func TestLimiterEvictsAtCapacity(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(8, clock.Now)
	spec := testSpec(1, time.Minute)

	for i := range 100 {
		l.Allow(fmt.Sprintf("key-%d", i), spec)
	}
	if got := l.Len(); got > 8 {
		t.Errorf("holding %d buckets with a capacity of 8", got)
	}
}

// Eviction is least-recently-used, so a busy client keeps its bucket while a
// spray of one-off keys passes through.
func TestLimiterEvictsTheLeastRecentlyUsed(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(4, clock.Now)
	spec := testSpec(1, time.Hour)

	// "busy" spends its only token.
	if ok, _ := l.Allow("busy", spec); !ok {
		t.Fatal("the first request was refused")
	}

	for i := range 3 {
		l.Allow(fmt.Sprintf("spray-%d", i), spec)
		// Touch "busy" so it stays at the front of the use order.
		if ok, _ := l.Allow("busy", spec); ok {
			t.Fatal("busy got a token back without waiting")
		}
	}

	// It is still throttled: the spray did not evict it.
	if ok, _ := l.Allow("busy", spec); ok {
		t.Error("the busy bucket was evicted and reset by a spray of new keys")
	}
}

// A route whose limit changed gets a fresh bucket: counting a new rule against
// a count accumulated under the old one is arbitrary.
func TestLimiterResetsWhenTheRuleChanges(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(16, clock.Now)

	tight := testSpec(1, time.Hour)
	if ok, _ := l.Allow("a", tight); !ok {
		t.Fatal("the first request was refused")
	}
	if ok, _ := l.Allow("a", tight); ok {
		t.Fatal("the limit of one was not enforced")
	}

	loose := testSpec(10, time.Hour)
	if ok, _ := l.Allow("a", loose); !ok {
		t.Error("the raised limit did not take effect")
	}
}

// Sweeping is housekeeping (the cap is the safety property) but without it a
// node that saw a spike holds the high-water mark of buckets forever.
func TestLimiterSweepsIdleBuckets(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(1000, clock.Now)
	spec := testSpec(1, time.Minute)

	for i := range 50 {
		l.Allow(fmt.Sprintf("key-%d", i), spec)
	}
	if l.Len() != 50 {
		t.Fatalf("holding %d buckets, want 50", l.Len())
	}

	// Not yet idle enough to have refilled.
	clock.advance(time.Minute)
	if dropped := l.Sweep(); dropped != 0 {
		t.Errorf("swept %d buckets that had not refilled", dropped)
	}

	clock.advance(2 * time.Minute)
	if dropped := l.Sweep(); dropped != 50 {
		t.Errorf("swept %d buckets, want 50", dropped)
	}
	if l.Len() != 0 {
		t.Errorf("%d buckets remain after the sweep", l.Len())
	}
}

// A bucket still in use survives a sweep even when older ones around it go.
func TestLimiterSweepKeepsActiveBuckets(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	l := New(1000, clock.Now)
	spec := testSpec(10, time.Minute)

	l.Allow("old", spec)
	clock.advance(3 * time.Minute)
	l.Allow("fresh", spec)

	if dropped := l.Sweep(); dropped != 1 {
		t.Errorf("swept %d, want just the idle one", dropped)
	}
	if l.Len() != 1 {
		t.Errorf("holding %d buckets, want the fresh one", l.Len())
	}
}

func TestLimiterIsConcurrencySafe(t *testing.T) {
	l := New(64, time.Now)
	spec := testSpec(1000, time.Minute)

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 64 {
				l.Allow(fmt.Sprintf("key-%d", (i*64+j)%128), spec)
			}
		}()
	}
	wg.Wait()

	if got := l.Len(); got > 64 {
		t.Errorf("holding %d buckets with a capacity of 64", got)
	}
}

func TestSpecRateAndCapacity(t *testing.T) {
	spec := Spec{Requests: 60, Window: time.Minute}
	if got := spec.Rate(); got != 1 {
		t.Errorf("rate = %v, want 1/s", got)
	}
	if got := spec.Capacity(); got != 60 {
		t.Errorf("capacity = %v, want the full allowance", got)
	}
	spec.Burst = 20
	if got := spec.Capacity(); got != 80 {
		t.Errorf("capacity = %v, want requests+burst", got)
	}
}
