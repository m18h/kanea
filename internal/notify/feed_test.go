package notify_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/notify"
	"github.com/kanea-dev/kanea/internal/store"
)

func newFeed(t *testing.T, retention int) (*notify.Feed, store.Store) {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	feed, err := notify.NewFeed(notify.FeedConfig{Store: st, Retention: retention})
	if err != nil {
		t.Fatalf("NewFeed: %v", err)
	}
	return feed, st
}

func TestFeedReturnsNewestFirst(t *testing.T) {
	feed, _ := newFeed(t, 100)
	ctx := context.Background()
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	for i := range 5 {
		feed.Record(ctx, notify.NewEvent(notify.EventDeployStarted, "shop", "web",
			"deploy", at.Add(time.Duration(i)*time.Minute)))
	}

	got, err := feed.List(ctx, "", 3)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("%d events, want 3", len(got))
	}
	// Newest first: an operator opening the dashboard wants what just happened,
	// and the alternative is scanning every event ever written to find it.
	for i := 1; i < len(got); i++ {
		if got[i].At.After(got[i-1].At) {
			t.Fatal("events are not newest-first")
		}
	}
	if !got[0].At.Equal(at.Add(4 * time.Minute)) {
		t.Fatalf("first event is %v, want the newest", got[0].At)
	}
}

func TestFeedIsBounded(t *testing.T) {
	// A crash loop emits events for as long as it loops. An unbounded bucket in
	// a single-writer bbolt is a way to make the control plane slow.
	feed, _ := newFeed(t, 20)
	ctx := context.Background()
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	for i := range 200 {
		feed.Record(ctx, notify.NewEvent(notify.EventServiceCrashed, "shop", "web",
			"alloc exited", at.Add(time.Duration(i)*time.Second)))
	}
	feed.Prune(ctx)

	got, err := feed.List(ctx, "", 1000)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 20 {
		t.Fatalf("%d events retained, want the 20 the bound allows", len(got))
	}
	// The newest are the ones kept: during an incident the recent state is what
	// anyone needs.
	if !got[0].At.Equal(at.Add(199 * time.Second)) {
		t.Fatalf("newest retained is %v, want the last one written", got[0].At)
	}
}

func TestFeedFiltersByProject(t *testing.T) {
	feed, _ := newFeed(t, 100)
	ctx := context.Background()
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	feed.Record(ctx, notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", at))
	feed.Record(ctx, notify.NewEvent(notify.EventDeployFailed, "billing", "api", "boom",
		at.Add(time.Second)))

	got, err := feed.List(ctx, "shop", 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Project != "shop" {
		t.Fatalf("got %+v, want only shop's event", got)
	}
}

func TestFeedRoundTripsSeverity(t *testing.T) {
	// Severity is an int internally so a floor is one comparison, and a name on
	// the wire so nobody depends on Kanea's iota order. A stored event has to
	// come back with the same severity either way.
	feed, _ := newFeed(t, 100)
	ctx := context.Background()

	feed.Record(ctx, notify.NewEvent(notify.EventDeployFailed, "shop", "web", "boom", time.Now()))

	got, err := feed.List(ctx, "", 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d events", len(got))
	}
	if got[0].Severity != notify.SeverityError {
		t.Fatalf("severity = %v, want error", got[0].Severity)
	}
}

func TestFeedSinceReturnsATimeline(t *testing.T) {
	feed, _ := newFeed(t, 100)
	ctx := context.Background()
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	for i := range 5 {
		feed.Record(ctx, notify.NewEvent(notify.EventScaleUp, "shop", "web", "scaled",
			at.Add(time.Duration(i)*time.Minute)))
	}

	got, err := feed.Since(ctx, at.Add(2*time.Minute), 100)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("%d events after the cutoff, want 2", len(got))
	}
	// Oldest first: a reconnecting dashboard is replaying what it missed, and a
	// replay runs forwards.
	if got[0].At.After(got[1].At) {
		t.Fatal("Since did not return a timeline")
	}
}
