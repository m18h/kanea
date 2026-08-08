package notify_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// recorder is a Channel that remembers the batches it was given.
type recorder struct {
	mu      sync.Mutex
	batches [][]notify.Event
	errs    []error
	name    string
	block   chan struct{}
}

func newRecorder(name string) *recorder { return &recorder{name: name} }

func (r *recorder) Name() string { return r.name }

func (r *recorder) Send(_ context.Context, batch []notify.Event) error {
	if r.block != nil {
		<-r.block
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.batches = append(r.batches, append([]notify.Event(nil), batch...))
	if len(r.errs) > 0 {
		err := r.errs[0]
		r.errs = r.errs[1:]
		return err
	}
	return nil
}

func (r *recorder) sent() [][]notify.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]notify.Event(nil), r.batches...)
}

func (r *recorder) attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

// clock is a manual time source.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock() *clock {
	return &clock{at: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func allEvents(t *testing.T) notify.Filter {
	t.Helper()
	f, err := notify.NewFilter([]string{"*"}, notify.SeverityInfo)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	return f
}

func TestPublishNeverBlocksAndCountsDrops(t *testing.T) {
	// AGENTS.md #8 and §11's "never block the control plane". A reconciler
	// noticing forty crashed allocs is already having a bad minute; making it
	// wait on Telegram would turn this into an outage amplifier.
	ch := newRecorder("slow")
	ch.block = make(chan struct{}) // never released — the channel is wedged

	d, err := notify.New(notify.Config{
		Routes:     []notify.Route{{Channel: ch, Filter: allEvents(t)}},
		QueueDepth: 4,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Far more than the queue holds, from the caller's goroutine, with nothing
	// draining it. This must return, not deadlock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			d.Publish(notify.NewEvent(notify.EventServiceCrashed, "shop", "web",
				"alloc exited", time.Now().Add(time.Duration(i))))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked")
	}

	// And the drops are counted rather than silent: a silent drop in a
	// notification system is the worst possible failure.
	if got := d.Stats().Dropped; got < 900 {
		t.Fatalf("dropped = %d, want most of 1000 events", got)
	}
}

func TestCoalescesAStormIntoOneMessage(t *testing.T) {
	// §11: "42 allocs restarted in 5m" — one message, not 42.
	ch := newRecorder("chat")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{Channel: ch, Filter: allEvents(t)}},
		Now:    c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)

	for i := range 20 {
		d.Publish(notify.NewEvent(notify.EventServiceCrashed, "shop", "web",
			"alloc exited", c.now().Add(time.Duration(i)*time.Second)))
	}
	// Nothing should have gone out yet: the window has not closed.
	time.Sleep(100 * time.Millisecond)
	if got := ch.attempts(); got != 0 {
		t.Fatalf("%d messages sent before the window closed", got)
	}

	c.advance(notify.DefaultCoalesceWindow + time.Second)
	waitFor(t, func() bool { return ch.attempts() == 1 })
	cancel()

	sent := ch.sent()
	if len(sent) != 1 {
		t.Fatalf("%d messages, want 1", len(sent))
	}
	if len(sent[0]) != 20 {
		t.Fatalf("batch of %d, want all 20 events", len(sent[0]))
	}
	// Oldest first, so the digest reads as a timeline.
	for i := 1; i < len(sent[0]); i++ {
		if sent[0][i].At.Before(sent[0][i-1].At) {
			t.Fatal("the digest is not in time order")
		}
	}
}

func TestAFullBatchGoesWithoutWaitingOutTheWindow(t *testing.T) {
	// The window exists to gather a storm. Once the batch is already a storm,
	// waiting longer only delays it.
	ch := newRecorder("chat")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes:   []notify.Route{{Channel: ch, Filter: allEvents(t)}},
		MaxBatch: 5,
		Now:      c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	for range 5 {
		d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	}
	// No clock advance at all.
	waitFor(t, func() bool { return ch.attempts() == 1 })
	if got := len(ch.sent()[0]); got != 5 {
		t.Fatalf("batch of %d, want 5", got)
	}
}

func TestRateLimitProtectsTheThirdParty(t *testing.T) {
	// §11: "a crash-looping fleet must never get the Telegram bot rate-limited
	// or blocked" — which is a limit imposed on Kanea if Kanea does not impose
	// one on itself.
	ch := newRecorder("chat")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{
			Channel: ch, Filter: allEvents(t),
			RateLimit: 2, CoalesceWindow: time.Second,
		}},
		MaxBatch: 1,
		Now:      c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	for range 6 {
		d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	}
	waitFor(t, func() bool { return d.Stats().Suppressed >= 4 })

	if got := ch.attempts(); got != 2 {
		t.Fatalf("%d messages sent, want 2 — the rest should be suppressed", got)
	}

	// And the limit is a window, not a cap: a minute later it sends again.
	c.advance(2 * time.Minute)
	d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	waitFor(t, func() bool { return ch.attempts() == 3 })
}

func TestRetriesTransientFailuresButNotPermanentOnes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		attempts int
	}{
		{"transient", errors.New("502 bad gateway"), 3},
		{"permanent", notify.ErrPermanent, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := newRecorder("chat")
			ch.errs = []error{tc.err, tc.err, nil}
			c := newClock()

			d, err := notify.New(notify.Config{
				Routes:      []notify.Route{{Channel: ch, Filter: allEvents(t)}},
				MaxBatch:    1,
				MaxAttempts: 3,
				Now:         c.now,
				// No real waiting: the backoff schedule is not what is under
				// test, the decision to retry at all is.
				RetryBase: time.Nanosecond,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go d.Run(ctx)

			d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
			waitFor(t, func() bool { return ch.attempts() >= tc.attempts })
			time.Sleep(50 * time.Millisecond) // let a wrong extra attempt show up

			if got := ch.attempts(); got != tc.attempts {
				t.Fatalf("%d attempts, want %d", got, tc.attempts)
			}
		})
	}
}

func TestProjectRoutesOnlySeeTheirOwnProject(t *testing.T) {
	// The same boundary R5 draws for secrets: one project's chat must not
	// receive another project's failures.
	shop, billing, node := newRecorder("shop"), newRecorder("billing"), newRecorder("node")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{
			{Channel: shop, Filter: allEvents(t), Project: "shop"},
			{Channel: billing, Filter: allEvents(t), Project: "billing"},
			{Channel: node, Filter: allEvents(t)},
		},
		MaxBatch: 1,
		Now:      c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	waitFor(t, func() bool { return shop.attempts() == 1 && node.attempts() == 1 })
	time.Sleep(50 * time.Millisecond)

	if billing.attempts() != 0 {
		t.Fatal("billing's channel received shop's event")
	}
	// A server-level route with no project sees everything, which is what makes
	// it a default rather than a fourth project.
	if node.attempts() != 1 {
		t.Fatal("the node-level channel did not receive the event")
	}
}

func TestShutdownFlushesWhatIsPending(t *testing.T) {
	// A digest two seconds from being sent when the daemon restarts is a digest
	// nobody ever sees — and the events in it are exactly the ones that
	// preceded the restart.
	ch := newRecorder("chat")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{Channel: ch, Filter: allEvents(t)}},
		Now:    c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()

	d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	waitFor(t, func() bool { return d.Stats().Dropped == 0 })
	time.Sleep(50 * time.Millisecond) // let it be routed into the pending batch

	cancel()
	<-done

	if ch.attempts() != 1 {
		t.Fatalf("%d messages on shutdown, want the pending one flushed", ch.attempts())
	}
}

// sink records what the feed would see.
type sink struct {
	mu     sync.Mutex
	events []notify.Event
}

func (s *sink) Record(_ context.Context, e notify.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestTheFeedSeesEventsNoChannelWanted(t *testing.T) {
	// §11 says all channels are mirrored into the dashboard feed. The feed is
	// the record and the channels are the notification, so an event that no
	// filter matched still belongs in the record — otherwise the dashboard
	// shows only what someone configured a chat for.
	ch := newRecorder("chat")
	narrow, err := notify.NewFilter([]string{"cert.*"}, notify.SeverityInfo)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	feed := &sink{}
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{Channel: ch, Filter: narrow}},
		Sink:   feed,
		Now:    c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	waitFor(t, func() bool { return feed.count() == 1 })

	time.Sleep(50 * time.Millisecond)
	if ch.attempts() != 0 {
		t.Fatal("a channel received an event its filter did not match")
	}
}

// waitFor polls until cond is true or the test times out.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within the deadline")
}

func TestShutdownSendsEvenWhatTheRateLimitWasHolding(t *testing.T) {
	// Holding a batch back is right while the daemon is running and will try
	// again. It is wrong when the daemon is going away: the events would be
	// re-pended into a struct nobody will ever look at, which is a silent loss
	// wearing backpressure's clothes.
	ch := newRecorder("chat")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{
			Channel: ch, Filter: allEvents(t), RateLimit: 1,
		}},
		// Two per message, so the second flush is held whole rather than
		// trimmed by the hold cap — the cap is a separate behaviour.
		MaxBatch: 2,
		Now:      c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()

	// The first pair exhausts the limit of one message a minute; the second
	// pair is held.
	for range 4 {
		d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	}
	waitFor(t, func() bool { return d.Stats().Suppressed >= 1 })

	cancel()
	<-done

	sent := ch.sent()
	if len(sent) != 2 {
		t.Fatalf("%d messages, want 2 — one allowed, one final flush", len(sent))
	}
	// And the held events are in the final message rather than lost.
	if len(sent[1]) != 2 {
		t.Fatalf("the final message carried %d events, want the 2 that were held", len(sent[1]))
	}
}
