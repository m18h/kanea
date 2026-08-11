package notify_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// Runtime route reload (PRD v1.46). The dispatcher's routes were startup-static
// until settings could change them; the reload must swap the set without losing
// what the old routes were still holding, and without racing the handler-side
// readers (Test, Channels).

// channelNames is what Channels() reports, used to observe when a SetRoutes has
// actually been applied on Run's goroutine — the swap is asynchronous, and a
// test publishing "after the reload" must know the reload landed first.
func routesApplied(d *notify.Dispatcher, want int) func() bool {
	return func() bool { return len(d.Channels()) == want }
}

func TestSetRoutesReplacesTheRouteSet(t *testing.T) {
	// After a reload, the new channel receives and the old one does not — the
	// whole point of hot reload is that the retired channel is actually retired,
	// not merely joined by its replacement.
	oldCh, newCh := newRecorder("old"), newRecorder("new")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{Channel: oldCh, Filter: allEvents(t)}},
		// One event per message, so deliveries do not wait out a coalesce
		// window the test would have to advance the clock through.
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
	waitFor(t, func() bool { return oldCh.attempts() == 1 })

	d.SetRoutes([]notify.Route{{Channel: newCh, Filter: allEvents(t)}})
	// The swap happens on Run's goroutine; wait until Channels() shows the new
	// set before publishing, or the event could legitimately meet the old one.
	waitFor(t, func() bool {
		names := d.Channels()
		return len(names) == 1 && names[0] == "new"
	})

	d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom again", c.now()))
	waitFor(t, func() bool { return newCh.attempts() == 1 })
	time.Sleep(50 * time.Millisecond) // let a wrong delivery to the old channel show up

	if got := oldCh.attempts(); got != 1 {
		t.Fatalf("the retired channel received %d messages, want only the pre-reload one", got)
	}
}

func TestReloadFlushesPendingDigests(t *testing.T) {
	// applyRoutes force-flushes the outgoing routes before swapping: a digest
	// two seconds from sending when the operator reconfigured channels must not
	// be silently discarded — delivering it through the outgoing route is the
	// only honest option. The same rule shutdown follows, applied to reload.
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
	defer cancel()
	go d.Run(ctx)

	// Publish and let it be routed into the pending batch; the clock never
	// advances, so the coalesce window cannot close on its own.
	d.Publish(notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", c.now()))
	waitFor(t, func() bool { return d.Stats().Dropped == 0 })
	time.Sleep(50 * time.Millisecond)
	if got := ch.attempts(); got != 0 {
		t.Fatalf("%d messages before the reload; the window should still be open", got)
	}

	// Replace with nothing at all — the hardest case, because there is no new
	// route the pending events could be re-filed onto.
	d.SetRoutes(nil)

	waitFor(t, func() bool { return ch.attempts() == 1 })
	if got := len(ch.sent()[0]); got != 1 {
		t.Fatalf("the flushed digest carried %d events, want the pending one", got)
	}
	waitFor(t, routesApplied(d, 0))
}

func TestTestAndChannelsRaceWithReload(t *testing.T) {
	// Test and Channels read the route set from handler goroutines while Run's
	// goroutine swaps it (v1.46). The atomic pointer is the mechanism; -race is
	// the assertion — this test exists to give it something to bite on.
	c := newClock()
	d, err := notify.New(notify.Config{
		Routes: []notify.Route{{Channel: newRecorder("a"), Filter: allEvents(t)}},
		Now:    c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 100 {
			// Alternate between a populated set and an empty one, so the
			// readers see both shapes mid-swap.
			if i%2 == 0 {
				d.SetRoutes([]notify.Route{{Channel: newRecorder("b"), Filter: allEvents(t)}})
			} else {
				d.SetRoutes(nil)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			d.Test("", "")
			d.Channels()
		}
	}()
	wg.Wait()
	// No assertion: a data race or a panic is the failure mode.
}

func TestNodeChannels(t *testing.T) {
	// TestNodeChannels exists because Test's project filter can never name the
	// node-wide routes — their scope is the empty string, and `Test("", ...)`
	// means "every route", which would page the projects' channels too.
	node, shop := newRecorder("node/webhook"), newRecorder("shop/webhook")
	c := newClock()

	d, err := notify.New(notify.Config{
		Routes: []notify.Route{
			{Channel: node, Filter: allEvents(t)},
			{Channel: shop, Filter: allEvents(t), Project: "shop"},
		},
		Now: c.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	results := d.TestNodeChannels("")
	if len(results) != 1 {
		t.Fatalf("%d results, want only the node-wide route", len(results))
	}
	if results[0].Channel != "node/webhook" || !results[0].OK {
		t.Fatalf("result = %+v, want the node channel, ok", results[0])
	}
	if node.attempts() != 1 {
		t.Errorf("the node channel got %d test messages, want 1", node.attempts())
	}
	// The project's channel was never touched: an admin testing the node-wide
	// defaults must not page a project's chat.
	if shop.attempts() != 0 {
		t.Errorf("the project channel got %d test messages, want 0", shop.attempts())
	}
}
