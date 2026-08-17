package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// Durable circuit-breaker state (v1.37, PRD §4.3).
//
// The breaker pauses rollouts and scale actions during a node-wide fault:
// and a daemon restart is most likely during exactly such a fault. Before
// v1.37 the restart silently closed the breaker, un-pausing rollouts into the
// still-broken node. Only the transitions are written (a trip, an operator
// reset), never the per-failure samples: the record changes at most once per
// cooldown, so it costs replication nothing.

// breakerStateKey is where the record lives in the kv bucket.
const breakerStateKey = "reconciler/breaker"

// breakerRecord is the persisted transition.
//
// TrippedAt is omitzero because it is in no way a zero value: a record with
// no trip time is a closed breaker that remembers its trip count.
type breakerRecord struct {
	TrippedAt time.Time `json:"tripped_at,omitzero"`
	Trips     int       `json:"trips"`
	Failures  int       `json:"failures_at_trip,omitempty"`
}

// persistBreaker returns the transition hook NewBreaker takes.
//
// The context is detached from the agent's: a trip during shutdown is still
// worth recording, and the write is bounded by the Store, not by the caller.
func persistBreaker(ctx context.Context, st store.Store, log *slog.Logger) func(time.Time, int, int) {
	return func(trippedAt time.Time, trips, failures int) {
		rec := breakerRecord{TrippedAt: trippedAt, Trips: trips, Failures: failures}
		if _, err := store.PutValue(ctx, st, store.KindKV, breakerStateKey, rec); err != nil {
			// Best-effort by design: the fault that tripped the breaker may be
			// the disk. The in-memory state is authoritative for this process.
			log.Error("cannot persist the circuit-breaker state", "error", err)
		}
	}
}

// restoreBreaker seeds a new breaker from the persisted record, if any.
func restoreBreaker(ctx context.Context, st store.Store, b *reconciler.Breaker, log *slog.Logger) {
	rec, _, err := store.GetValue[breakerRecord](ctx, st, store.KindKV, breakerStateKey)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			log.Warn("cannot read the persisted circuit-breaker state; starting closed", "error", err)
		}
		return
	}
	b.Restore(rec.TrippedAt, rec.Trips, rec.Failures)
}
