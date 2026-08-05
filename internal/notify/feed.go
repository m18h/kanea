package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kanea-dev/kanea/internal/store"
)

// The event feed (PRD §11: "all channels also mirrored into the dashboard
// notification feed").
//
// Events go in the Store rather than a file, because unlike logs and metrics
// they are state: bounded, low-rate, and something an operator expects to still
// be there after a restart. The bound is what keeps that true — a crash loop
// emits events for as long as it loops, and an unbounded bucket in a
// single-writer bbolt is a way to make the control plane slow (constraint #2).

// Feed defaults.
const (
	// DefaultRetention is how many events are kept. Enough to cover an
	// incident and the hours around it; small enough that the whole feed is
	// one bounded read.
	DefaultRetention = 500
	// DefaultFeedListLimit is how many a caller gets when it does not say.
	DefaultFeedListLimit = 100
	// pruneEvery is how many writes pass between prunes. Pruning on every
	// write would double the write load for a bucket that is already bounded
	// within a rounding error of its target.
	pruneEvery = 50
)

// EventKey is an event's Store key. The id is time-ordered, so the bucket is
// too, and "the newest 100" is a bounded reverse scan rather than a full one.
func EventKey(e Event) string { return e.ID }

// Feed stores events and serves them back.
type Feed struct {
	store store.Store
	log   *slog.Logger
	// retention bounds the bucket.
	retention int

	// writes counts since the last prune.
	writes atomic.Int64
	// pruning keeps two prunes from running at once, which on a single-writer
	// store would only make them queue behind each other.
	pruning sync.Mutex
}

// FeedConfig configures the feed.
type FeedConfig struct {
	Store     store.Store
	Logger    *slog.Logger
	Retention int
}

// NewFeed builds the feed.
func NewFeed(cfg FeedConfig) (*Feed, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("notify: a store is required for the event feed")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Retention <= 0 {
		cfg.Retention = DefaultRetention
	}
	return &Feed{store: cfg.Store, log: cfg.Logger, retention: cfg.Retention}, nil
}

// Record writes an event. It satisfies Sink.
//
// A failure is logged and swallowed: this is called from the dispatcher's
// goroutine on behalf of a control-plane path that has already moved on, and
// there is nobody left to hand an error to.
func (f *Feed) Record(ctx context.Context, e Event) {
	if _, err := store.PutValue(ctx, f.store, store.KindEvent, EventKey(e), e); err != nil {
		f.log.Error("cannot record an event", "event", e.Name, "error", err)
		return
	}
	if f.writes.Add(1)%pruneEvery == 0 {
		f.prune(ctx)
	}
}

// List returns events, newest first.
func (f *Feed) List(ctx context.Context, project string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = DefaultFeedListLimit
	}

	// Reverse, because the bucket is time-ordered and what anyone wants is the
	// end of it. Without this, "the last 100 events" means scanning every event
	// ever written — the one read pattern a bounded-transaction rule cannot
	// afford (AGENTS.md #2).
	out := make([]Event, 0, limit)
	var after string
	for len(out) < limit {
		values, page, err := store.ListValues[Event](ctx, f.store, store.KindEvent,
			store.ListOptions{Reverse: true, After: after, Limit: limit})
		if err != nil {
			return nil, fmt.Errorf("notify: list events: %w", err)
		}
		for _, e := range values {
			// Filtering after the read rather than by key prefix: the key is
			// time-ordered so that the newest are cheap to find, and a key that
			// led with the project would make "newest across all projects" the
			// expensive case instead. At this bucket size the difference is
			// noise either way.
			if project != "" && e.Project != project {
				continue
			}
			out = append(out, e)
			if len(out) == limit {
				break
			}
		}
		if !page.More {
			break
		}
		after = page.NextAfter
	}
	return out, nil
}

// prune drops the oldest events past the retention bound.
func (f *Feed) prune(ctx context.Context) {
	if !f.pruning.TryLock() {
		return
	}
	defer f.pruning.Unlock()

	// Keys only: the values are not needed to decide what to delete, and
	// reading five hundred event bodies to throw most of them away is work the
	// single writer does not need.
	var keys []string
	var after string
	for {
		page, err := f.store.List(ctx, store.KindEvent, store.ListOptions{
			After: after, Limit: 500, KeysOnly: true,
		})
		if err != nil {
			f.log.Error("cannot list events to prune", "error", err)
			return
		}
		for _, rec := range page.Records {
			keys = append(keys, rec.Key)
		}
		if !page.More {
			break
		}
		after = page.NextAfter
	}

	excess := len(keys) - f.retention
	if excess <= 0 {
		return
	}
	// The list is ascending and the ids are time-ordered, so the oldest are at
	// the front.
	muts := make([]store.Mutation, 0, excess)
	for _, key := range keys[:excess] {
		muts = append(muts, store.DeleteMutation(store.KindEvent, key))
	}
	if _, err := f.store.Apply(ctx, muts...); err != nil {
		f.log.Error("cannot prune events", "count", excess, "error", err)
		return
	}
	f.log.Debug("pruned events", "removed", excess, "retained", f.retention)
}

// Prune is the exported form, for a startup sweep and for tests.
func (f *Feed) Prune(ctx context.Context) { f.prune(ctx) }

// Since returns events newer than a timestamp, oldest first.
//
// The websocket feed's resume path: a dashboard that reconnects asks for what
// it missed rather than re-reading the whole bucket.
func (f *Feed) Since(ctx context.Context, at time.Time, limit int) ([]Event, error) {
	recent, err := f.List(ctx, "", limit)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(recent))
	// List is newest-first; walk it backwards to hand back a timeline.
	for i := len(recent) - 1; i >= 0; i-- {
		if recent[i].At.After(at) {
			out = append(out, recent[i])
		}
	}
	return out, nil
}
