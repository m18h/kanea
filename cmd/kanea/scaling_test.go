package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
)

func openScalingStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSetCountWritesTheCooldownRecordAtomically(t *testing.T) {
	// The cooldown clock rides in the scale action's own Apply batch (v1.37):
	// one index, one CDC unit — durability at zero extra replication cost.
	ctx := context.Background()
	st := openScalingStore(t)

	desired := reconciler.Desired{Project: "shop", Service: "web", Image: "img:1", Count: 2}
	if _, err := store.PutValue(ctx, st, store.KindService, "shop/web", desired); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	before, err := st.Index(ctx)
	if err != nil {
		t.Fatalf("index: %v", err)
	}

	fleet := storeFleet{store: st, notify: make(chan struct{}, 1), log: slog.New(slog.DiscardHandler)}
	if err := fleet.SetCount(ctx, "shop/web", 3); err != nil {
		t.Fatalf("SetCount: %v", err)
	}

	after, err := st.Index(ctx)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if after != before+1 {
		t.Errorf("a scale action spent %d store batches, want 1", after-before)
	}

	got, _, err := store.GetValue[reconciler.Desired](ctx, st, store.KindService, "shop/web")
	if err != nil {
		t.Fatalf("read service: %v", err)
	}
	if got.Count != 3 {
		t.Errorf("count = %d, want 3", got.Count)
	}
	cool, _, err := store.GetValue[scaleCooldownRecord](ctx, st, store.KindKV, cooldownKey("shop/web"))
	if err != nil {
		t.Fatalf("read cooldown: %v", err)
	}
	if cool.At.IsZero() {
		t.Error("the cooldown record carries no time")
	}
}

func TestSeedCooldownsReplaysLiveAndReapsDead(t *testing.T) {
	ctx := context.Background()
	st := openScalingStore(t)
	log := slog.New(slog.DiscardHandler)

	desired := reconciler.Desired{Project: "shop", Service: "web", Image: "img:1", Count: 2}
	if _, err := store.PutValue(ctx, st, store.KindService, "shop/web", desired); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	at := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	for _, service := range []string{"shop/web", "shop/gone"} {
		if _, err := store.PutValue(ctx, st, store.KindKV, cooldownKey(service),
			scaleCooldownRecord{At: at}); err != nil {
			t.Fatalf("seed cooldown: %v", err)
		}
	}

	metrics := scaling.NewMetrics(scaling.MetricsConfig{})
	evaluator, err := scaling.NewEvaluator(scaling.EvaluatorConfig{Metrics: metrics, Logger: log})
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	seedCooldowns(ctx, st, evaluator, log)

	// The live service's cooldown was replayed into the evaluator…
	services := evaluator.Services()
	if len(services) != 1 || services[0] != "shop/web" {
		t.Errorf("evaluator tracks %v, want only shop/web", services)
	}
	// …and the dead service's record was reaped rather than left to grow.
	if _, _, err := store.GetValue[scaleCooldownRecord](ctx, st, store.KindKV,
		cooldownKey("shop/gone")); err == nil {
		t.Error("a cooldown for a deleted service survived the seed sweep")
	}
	if _, _, err := store.GetValue[scaleCooldownRecord](ctx, st, store.KindKV,
		cooldownKey("shop/web")); err != nil {
		t.Errorf("the live cooldown record was reaped: %v", err)
	}
}
