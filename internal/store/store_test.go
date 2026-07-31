package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/store"
)

type service struct {
	Name     string `json:"name"`
	Replicas int    `json:"replicas"`
}

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return s
}

func put(t *testing.T, s store.Store, kind store.Kind, key string, v any) uint64 {
	t.Helper()
	m, err := store.PutMutation(kind, key, v)
	if err != nil {
		t.Fatalf("put mutation: %v", err)
	}
	idx, err := s.Apply(context.Background(), m)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return idx
}

func TestGetAndPutRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	want := service{Name: "web", Replicas: 3}
	idx := put(t, s, store.KindService, "shop/web", want)
	if idx != 1 {
		t.Fatalf("first index = %d, want 1", idx)
	}

	got, gotIdx, err := store.GetValue[service](ctx, s, store.KindService, "shop/web")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != want {
		t.Errorf("value = %+v, want %+v", got, want)
	}
	if gotIdx != idx {
		t.Errorf("record index = %d, want %d", gotIdx, idx)
	}
}

func TestGetErrors(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	tests := []struct {
		name string
		kind store.Kind
		key  string
		want error
	}{
		{"missing key", store.KindService, "nope", store.ErrNotFound},
		{"unknown kind", store.Kind("bogus"), "k", store.ErrInvalid},
		{"empty key", store.KindService, "", store.ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Get(ctx, tc.kind, tc.key); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIndexIsMonotonicAndPerBatch(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	// One index per Apply batch, not per mutation: a batch is one Raft command.
	a, _ := store.PutMutation(store.KindService, "shop/a", service{Name: "a"})
	b, _ := store.PutMutation(store.KindService, "shop/b", service{Name: "b"})
	idx, err := s.Apply(ctx, a, b)
	if err != nil {
		t.Fatalf("apply batch: %v", err)
	}
	if idx != 1 {
		t.Fatalf("batch index = %d, want 1", idx)
	}

	next := put(t, s, store.KindService, "shop/c", service{Name: "c"})
	if next != 2 {
		t.Fatalf("second batch index = %d, want 2", next)
	}
	if cur, err := s.Index(ctx); err != nil || cur != 2 {
		t.Fatalf("Index() = %d, %v; want 2, nil", cur, err)
	}

	// Both records from the batch carry the batch's index.
	for _, key := range []string{"shop/a", "shop/b"} {
		rec, err := s.Get(ctx, store.KindService, key)
		if err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		if rec.Index != 1 {
			t.Errorf("%s index = %d, want 1", key, rec.Index)
		}
	}
}

func TestApplyPreconditions(t *testing.T) {
	ctx := context.Background()

	t.Run("create-only rejects an existing key", func(t *testing.T) {
		s := newStore(t)
		put(t, s, store.KindService, "shop/web", service{Name: "web"})

		m, _ := store.CreateMutation(store.KindService, "shop/web", service{Name: "web2"})
		if _, err := s.Apply(ctx, m); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict", err)
		}
	})

	t.Run("create-only accepts a fresh key", func(t *testing.T) {
		s := newStore(t)
		m, _ := store.CreateMutation(store.KindService, "shop/new", service{Name: "new"})
		if _, err := s.Apply(ctx, m); err != nil {
			t.Fatalf("apply: %v", err)
		}
	})

	t.Run("compare-and-set rejects a stale index", func(t *testing.T) {
		s := newStore(t)
		idx := put(t, s, store.KindService, "shop/web", service{Name: "web", Replicas: 1})
		put(t, s, store.KindService, "shop/web", service{Name: "web", Replicas: 2}) // someone else wins

		m, _ := store.UpdateMutation(store.KindService, "shop/web", service{Name: "web", Replicas: 3}, idx)
		if _, err := s.Apply(ctx, m); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict", err)
		}
		// The loser's write must not have landed.
		got, _, err := store.GetValue[service](ctx, s, store.KindService, "shop/web")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Replicas != 2 {
			t.Errorf("replicas = %d, want 2 (stale write leaked)", got.Replicas)
		}
	})

	t.Run("compare-and-set accepts the current index", func(t *testing.T) {
		s := newStore(t)
		idx := put(t, s, store.KindService, "shop/web", service{Name: "web", Replicas: 1})
		m, _ := store.UpdateMutation(store.KindService, "shop/web", service{Name: "web", Replicas: 9}, idx)
		if _, err := s.Apply(ctx, m); err != nil {
			t.Fatalf("apply: %v", err)
		}
	})

	t.Run("compare-and-set on a deleted key conflicts", func(t *testing.T) {
		s := newStore(t)
		idx := put(t, s, store.KindService, "shop/web", service{Name: "web"})
		if _, err := s.Apply(ctx, store.DeleteMutation(store.KindService, "shop/web")); err != nil {
			t.Fatalf("delete: %v", err)
		}
		m, _ := store.UpdateMutation(store.KindService, "shop/web", service{Name: "web"}, idx)
		if _, err := s.Apply(ctx, m); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict", err)
		}
	})
}

func TestApplyIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	good, _ := store.PutMutation(store.KindService, "shop/good", service{Name: "good"})
	conflicting, _ := store.CreateMutation(store.KindService, "shop/taken", service{Name: "x"})
	put(t, s, store.KindService, "shop/taken", service{Name: "already here"})

	before, _ := s.Index(ctx)
	if _, err := s.Apply(ctx, good, conflicting); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if _, err := s.Get(ctx, store.KindService, "shop/good"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the batch half-applied: shop/good exists after a rejected batch")
	}
	if after, _ := s.Index(ctx); after != before {
		t.Errorf("index advanced on a rejected batch: %d -> %d", before, after)
	}
}

func TestApplyRejectsBadMutations(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	tests := []struct {
		name string
		mut  store.Mutation
	}{
		{"unknown kind", store.Mutation{Op: store.OpPut, Kind: "bogus", Key: "k"}},
		{"empty key", store.Mutation{Op: store.OpPut, Kind: store.KindService}},
		{"zero op", store.Mutation{Kind: store.KindService, Key: "k"}},
		{"contradictory preconditions", store.Mutation{
			Op: store.OpPut, Kind: store.KindService, Key: "k", PrevIndex: 1, ExpectAbsent: true,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Apply(ctx, tc.mut); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	put(t, s, store.KindService, "shop/web", service{Name: "web"})
	if _, err := s.Apply(ctx, store.DeleteMutation(store.KindService, "shop/web")); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if _, err := s.Apply(ctx, store.DeleteMutation(store.KindService, "shop/web")); err != nil {
		t.Fatalf("second delete must be a no-op, got %v", err)
	}
	if _, err := s.Get(ctx, store.KindService, "shop/web"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	// The no-op delete emits no change record: nothing happened to replicate.
	changes, err := s.Changes(ctx, 0, 100)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	deletes := 0
	for _, ch := range changes {
		if ch.Op == store.OpDelete {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("delete change records = %d, want 1", deletes)
	}
}

func TestListPaginatesInKeyOrder(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	for i := range 10 {
		put(t, s, store.KindAlloc, fmt.Sprintf("shop/web/%02d", i), service{Name: "web"})
	}
	put(t, s, store.KindAlloc, "other/api/00", service{Name: "api"})

	var seen []string
	opts := store.ListOptions{Prefix: "shop/web/", Limit: 3}
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		page, err := s.List(ctx, store.KindAlloc, opts)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, rec := range page.Records {
			seen = append(seen, rec.Key)
		}
		if !page.More {
			break
		}
		opts.After = page.NextAfter
	}

	if len(seen) != 10 {
		t.Fatalf("saw %d keys, want 10: %v", len(seen), seen)
	}
	for i, key := range seen {
		want := fmt.Sprintf("shop/web/%02d", i)
		if key != want {
			t.Fatalf("key[%d] = %q, want %q (order or prefix leak)", i, key, want)
		}
	}
}

func TestListLimitIsClamped(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	put(t, s, store.KindService, "a", service{Name: "a"})

	// A caller asking for the moon gets a bounded read, not an unbounded one.
	page, err := s.List(ctx, store.KindService, store.ListOptions{Limit: store.MaxListLimit * 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(page.Records))
	}
}

func TestListKeysOnlyOmitsValues(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	put(t, s, store.KindService, "shop/web", service{Name: "web"})

	page, err := s.List(ctx, store.KindService, store.ListOptions{KeysOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(page.Records))
	}
	if page.Records[0].Value != nil {
		t.Errorf("value = %q, want nil for KeysOnly", page.Records[0].Value)
	}
	if page.Records[0].Index == 0 {
		t.Error("index must still be reported for KeysOnly")
	}
}

func TestChangesFeedOrderAndContent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	a, _ := store.PutMutation(store.KindService, "shop/a", service{Name: "a"})
	b, _ := store.PutMutation(store.KindService, "shop/b", service{Name: "b"})
	if _, err := s.Apply(ctx, a, b); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := s.Apply(ctx, store.DeleteMutation(store.KindService, "shop/a")); err != nil {
		t.Fatalf("delete: %v", err)
	}

	changes, err := s.Changes(ctx, 0, 100)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if len(changes) != 3 {
		t.Fatalf("changes = %d, want 3", len(changes))
	}
	// Within-batch order is preserved, and the batch shares one index.
	if changes[0].Key != "shop/a" || changes[1].Key != "shop/b" {
		t.Errorf("within-batch order lost: %q then %q", changes[0].Key, changes[1].Key)
	}
	if changes[0].Index != 1 || changes[1].Index != 1 || changes[2].Index != 2 {
		t.Errorf("indexes = %d,%d,%d; want 1,1,2",
			changes[0].Index, changes[1].Index, changes[2].Index)
	}
	if changes[2].Op != store.OpDelete || changes[2].Value != nil {
		t.Errorf("delete change = %+v; want OpDelete with nil value", changes[2])
	}
	if changes[0].Time.IsZero() {
		t.Error("change records must carry a timestamp")
	}

	// `since` is exclusive on the index, so a replicator resumes without
	// re-shipping the batch it already acknowledged.
	tail, err := s.Changes(ctx, 1, 100)
	if err != nil {
		t.Fatalf("changes since: %v", err)
	}
	if len(tail) != 1 || tail[0].Index != 2 {
		t.Fatalf("tail = %+v, want only index 2", tail)
	}
}

func TestPruneChanges(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	for i := range 5 {
		put(t, s, store.KindEvent, fmt.Sprintf("e%d", i), service{Name: "e"})
	}
	pruned, err := s.PruneChanges(ctx, 3)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 3 {
		t.Fatalf("pruned = %d, want 3", pruned)
	}
	changes, err := s.Changes(ctx, 0, 100)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if len(changes) != 2 || changes[0].Index != 4 {
		t.Fatalf("remaining = %+v, want indexes 4,5", changes)
	}
	// Pruning the change log must not touch the records themselves.
	if _, err := s.Get(ctx, store.KindEvent, "e0"); err != nil {
		t.Errorf("pruning deleted a record: %v", err)
	}
}

func TestReopenPreservesStateAndIndex(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	idx := put(t, s, store.KindService, "shop/web", service{Name: "web", Replicas: 2})
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, gotIdx, err := store.GetValue[service](ctx, reopened, store.KindService, "shop/web")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.Replicas != 2 || gotIdx != idx {
		t.Errorf("after reopen: %+v at index %d; want replicas 2 at index %d", got, gotIdx, idx)
	}
	// Indexes must not restart: replication and Raft both depend on it.
	next := put(t, reopened, store.KindService, "shop/api", service{Name: "api"})
	if next != idx+1 {
		t.Errorf("index after reopen = %d, want %d", next, idx+1)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	bumpSchemaVersion(t, path, 99)

	if _, err := store.Open(store.Options{Path: path}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid for a newer on-disk schema", err)
	}
}

func TestOpenCreatesParentDirWithSafeMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "state.db")
	s, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// The file holds the secrets and certs buckets: it must not be world- or
	// group-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("db mode = %o, want 600", perm)
	}
}

func TestOpenRequiresPath(t *testing.T) {
	if _, err := store.Open(store.Options{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m, _ := store.PutMutation(store.KindService, "shop/web", service{Name: "web"})
	if _, err := s.Apply(ctx, m); !errors.Is(err, context.Canceled) {
		t.Errorf("Apply err = %v, want context.Canceled", err)
	}
	if _, err := s.Get(ctx, store.KindService, "shop/web"); !errors.Is(err, context.Canceled) {
		t.Errorf("Get err = %v, want context.Canceled", err)
	}
	if _, err := s.List(ctx, store.KindService, store.ListOptions{}); !errors.Is(err, context.Canceled) {
		t.Errorf("List err = %v, want context.Canceled", err)
	}
	if _, err := s.Changes(ctx, 0, 10); !errors.Is(err, context.Canceled) {
		t.Errorf("Changes err = %v, want context.Canceled", err)
	}
}

func TestEmptyApplyIsANoOp(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	put(t, s, store.KindService, "shop/web", service{Name: "web"})

	idx, err := s.Apply(ctx)
	if err != nil {
		t.Fatalf("empty apply: %v", err)
	}
	if cur, _ := s.Index(ctx); idx != cur {
		t.Errorf("empty apply returned %d, current index %d", idx, cur)
	}
}

func TestCompactProducesAReadableCopy(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.Open(store.Options{Path: filepath.Join(dir, "state.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := range 50 {
		put(t, s, store.KindService, fmt.Sprintf("shop/s%02d", i), service{Name: "s", Replicas: i})
	}
	dst := filepath.Join(dir, "compacted.db")
	if err := store.Compact(ctx, s, dst); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	copied, err := store.Open(store.Options{Path: dst})
	if err != nil {
		t.Fatalf("open compacted: %v", err)
	}
	defer copied.Close()

	got, _, err := store.GetValue[service](ctx, copied, store.KindService, "shop/s49")
	if err != nil {
		t.Fatalf("get from compacted: %v", err)
	}
	if got.Replicas != 49 {
		t.Errorf("compacted copy lost data: %+v", got)
	}
	if idx, err := copied.Index(ctx); err != nil || idx != 50 {
		t.Errorf("compacted index = %d, %v; want 50", idx, err)
	}
}

func TestTimestampsUseTheInjectedClock(t *testing.T) {
	ctx := context.Background()
	frozen := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	s, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "state.db"),
		Now:  func() time.Time { return frozen },
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	put(t, s, store.KindService, "shop/web", service{Name: "web"})
	changes, err := s.Changes(ctx, 0, 10)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if len(changes) != 1 || !changes[0].Time.Equal(frozen) {
		t.Fatalf("change time = %v, want %v", changes[0].Time, frozen)
	}
}

func TestClosedStoreRejectsCalls(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	put(t, s, store.KindService, "shop/web", service{Name: "web"})
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close must be a no-op, got %v", err)
	}

	m, _ := store.PutMutation(store.KindService, "shop/web", service{Name: "web"})
	checks := map[string]error{
		"get":     firstErr(func() error { _, err := s.Get(ctx, store.KindService, "shop/web"); return err }),
		"list":    firstErr(func() error { _, err := s.List(ctx, store.KindService, store.ListOptions{}); return err }),
		"apply":   firstErr(func() error { _, err := s.Apply(ctx, m); return err }),
		"index":   firstErr(func() error { _, err := s.Index(ctx); return err }),
		"changes": firstErr(func() error { _, err := s.Changes(ctx, 0, 10); return err }),
		"prune":   firstErr(func() error { _, err := s.PruneChanges(ctx, 1); return err }),
	}
	for name, err := range checks {
		if !errors.Is(err, store.ErrClosed) {
			t.Errorf("%s after close: err = %v, want ErrClosed", name, err)
		}
	}
}

func firstErr(f func() error) error { return f() }
