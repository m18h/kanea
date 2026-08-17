package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/store"
)

// The end-to-end test M10's exit criterion asks for: a node's state, shipped to
// a sink, restored onto a fresh path, and byte-for-byte the same afterwards.

func openStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func put(t *testing.T, s store.Store, kind store.Kind, key, value string) uint64 {
	t.Helper()
	index, err := s.Apply(context.Background(), store.Mutation{
		Op: store.OpPut, Kind: kind, Key: key, Value: []byte(value),
	})
	if err != nil {
		t.Fatalf("put %s/%s: %v", kind, key, err)
	}
	return index
}

func del(t *testing.T, s store.Store, kind store.Kind, key string) {
	t.Helper()
	if _, err := s.Apply(context.Background(), store.Mutation{
		Op: store.OpDelete, Kind: kind, Key: key,
	}); err != nil {
		t.Fatalf("delete %s/%s: %v", kind, key, err)
	}
}

func get(t *testing.T, s store.Store, kind store.Kind, key string) (string, bool) {
	t.Helper()
	rec, err := s.Get(context.Background(), kind, key)
	if errors.Is(err, store.ErrNotFound) {
		return "", false
	}
	if err != nil {
		t.Fatalf("get %s/%s: %v", kind, key, err)
	}
	return string(rec.Value), true
}

func newReplicator(t *testing.T, s store.Store, a *Archiver) *Replicator {
	t.Helper()
	r, err := NewReplicator(ReplicatorConfig{Archiver: a, Store: s})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}
	return r
}

func newStoreArchiver(t *testing.T, s store.Store, sink Sink, keys Keys) *Archiver {
	t.Helper()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	a, err := New(Config{
		Sink: sink, Keys: keys, Snapshotter: StoreSnapshotter{Store: s},
		WorkDir: t.TempDir(), Node: "node-1", Version: "test",
		Now: func() time.Time { at = at.Add(time.Second); return at },
	})
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	return a
}

func TestRestoreRecoversSnapshotPlusSegments(t *testing.T) {
	ctx := context.Background()
	keys := testKeys(t, 20)
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}

	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, keys)
	rep := newReplicator(t, src, archiver)

	// State that exists before the snapshot.
	put(t, src, store.KindService, "shop/web", "before")
	put(t, src, store.KindService, "shop/api", "kept")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// State that exists only in the changes after it: this is the part a
	// snapshot-only restore would lose, and the reason segments exist.
	put(t, src, store.KindService, "shop/web", "after")
	put(t, src, store.KindService, "shop/worker", "new")
	del(t, src, store.KindService, "shop/api")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.db")
	result, err := archiver.Restore(ctx, RestoreOptions{Target: target})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if result.Replayed == 0 {
		t.Fatal("nothing was replayed; the restore is only as good as the snapshot")
	}

	restored, err := store.Open(store.Options{Path: target})
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer func() { _ = restored.Close() }()

	if value, ok := get(t, restored, store.KindService, "shop/web"); !ok || value != "after" {
		t.Errorf("shop/web = %q (present=%v), want the post-snapshot value", value, ok)
	}
	if value, ok := get(t, restored, store.KindService, "shop/worker"); !ok || value != "new" {
		t.Errorf("shop/worker = %q (present=%v), want it restored", value, ok)
	}
	// A delete that happened after the snapshot has to survive the replay. This
	// is the direction that goes wrong quietly: a resurrected service is a
	// service the reconciler will start.
	if _, ok := get(t, restored, store.KindService, "shop/api"); ok {
		t.Error("shop/api came back from the dead: the delete was not replayed")
	}
}

func TestReplayPreservesTheIndexNumbering(t *testing.T) {
	// The Store stamps one index per Apply. Replaying change-by-change would
	// allocate one per change and drift the counter, so an index recorded
	// anywhere else would stop meaning what it meant.
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}

	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 21))
	rep := newReplicator(t, src, archiver)

	put(t, src, store.KindService, "shop/web", "one")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// A batch of three mutations under one index, then two more singles.
	if _, err := src.Apply(ctx,
		store.Mutation{Op: store.OpPut, Kind: store.KindService, Key: "p/a", Value: []byte("1")},
		store.Mutation{Op: store.OpPut, Kind: store.KindService, Key: "p/b", Value: []byte("2")},
		store.Mutation{Op: store.OpPut, Kind: store.KindService, Key: "p/c", Value: []byte("3")},
	); err != nil {
		t.Fatalf("batch apply: %v", err)
	}
	put(t, src, store.KindAlloc, "p/a/0", "x")
	final := put(t, src, store.KindAlloc, "p/b/0", "y")

	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.db")
	result, err := archiver.Restore(ctx, RestoreOptions{Target: target})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if result.Index != final {
		t.Errorf("restored index = %d, want %d; replay drifted the counter",
			result.Index, final)
	}

	restored, err := store.Open(store.Options{Path: target})
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer func() { _ = restored.Close() }()
	index, err := restored.Index(ctx)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if index != final {
		t.Errorf("the restored store's index is %d, want %d", index, final)
	}
}

func TestShipPrunesTheChangeLogOnlyAfterUploading(t *testing.T) {
	// The ordering the whole subsystem rests on. A change dropped from the log
	// before it is durably in the bucket is a change that exists nowhere.
	ctx := context.Background()
	src := openStore(t)
	archiver := newStoreArchiver(t, src, failingSink{}, testKeys(t, 22))
	rep := newReplicator(t, src, archiver)

	put(t, src, store.KindService, "shop/web", "one")
	if err := rep.ShipOnce(ctx); err == nil {
		t.Fatal("shipping to a broken sink reported success")
	}

	// The changes are still there to try again with.
	changes, err := src.Changes(ctx, 0, 100)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("the change log was pruned even though the upload failed")
	}
}

// failingSink refuses every write, standing in for an unreachable bucket.
type failingSink struct{}

func (failingSink) Put(context.Context, string, int64, io.Reader) error {
	return errors.New("the bucket is unreachable")
}
func (failingSink) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, ErrNotFound
}
func (failingSink) List(context.Context, string) ([]Object, error) { return nil, nil }
func (failingSink) Delete(context.Context, string) error           { return nil }
func (failingSink) Describe() string                               { return "a sink that is down" }

func TestShipSplitsALargeBacklogIntoSegments(t *testing.T) {
	// A burst must produce several objects rather than one enormous one: an
	// upload that fails is retried whole.
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 23))
	rep, err := NewReplicator(ReplicatorConfig{Archiver: archiver, Store: src, MaxChanges: 10})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}

	for i := range 35 {
		put(t, src, store.KindService, fmt.Sprintf("shop/svc-%02d", i), "x")
	}
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	segments, err := archiver.Segments(ctx)
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(segments) < 4 {
		t.Fatalf("35 changes at 10 per segment produced %d segments", len(segments))
	}
	// And the whole backlog went, not just the first batch: ShipOnce keeps
	// going while batches come back full.
	shipped, err := archiver.ShippedTo(ctx)
	if err != nil {
		t.Fatalf("shipped: %v", err)
	}
	index, err := src.Index(ctx)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if shipped != index {
		t.Errorf("shipped to %d but the store is at %d", shipped, index)
	}
}

func TestSegmentNamesSortByIndex(t *testing.T) {
	// Sinks list lexically. Unpadded names would put segment 10 before segment
	// 9, and a replay in that order applies a delete before the write it
	// removes.
	nine := segmentName(9, 9)
	ten := segmentName(10, 10)
	if nine >= ten {
		t.Fatalf("%q does not sort before %q", nine, ten)
	}
	parsed, err := parseSegmentName(ten)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.From != 10 || parsed.To != 10 {
		t.Errorf("parsed = %+v, want 10-10", parsed)
	}
}

func TestSegmentPruningKeepsAStraddlingSegment(t *testing.T) {
	// A segment spanning the snapshot index still holds changes newer than it.
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 24))

	// Two segments: 1-5 and 4-8. Pruning up to 5 must drop only the first.
	changes := func(from, to uint64) []store.Change {
		var out []store.Change
		for i := from; i <= to; i++ {
			out = append(out, store.Change{
				Index: i, Op: store.OpPut, Kind: store.KindService,
				Key: fmt.Sprintf("p/s%d", i), Value: []byte("x"),
			})
		}
		return out
	}
	if _, err := archiver.PutSegment(ctx, changes(1, 5)); err != nil {
		t.Fatalf("put segment: %v", err)
	}
	if _, err := archiver.PutSegment(ctx, changes(4, 8)); err != nil {
		t.Fatalf("put segment: %v", err)
	}

	removed, err := archiver.PruneSegments(ctx, 5)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d segments, want 1", removed)
	}
	left, err := archiver.Segments(ctx)
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(left) != 1 || left[0].To != 8 {
		t.Errorf("kept %+v, want the segment straddling the snapshot", left)
	}
}

func TestRestoreRefusesToOverwriteExistingState(t *testing.T) {
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 25))
	put(t, src, store.KindService, "shop/web", "one")
	if _, err := archiver.Create(ctx, "test", nil); err != nil {
		t.Fatalf("create: %v", err)
	}

	target := filepath.Join(t.TempDir(), "existing.db")
	if err := os.WriteFile(target, []byte("live state"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err = archiver.Restore(ctx, RestoreOptions{Target: target})
	if err == nil {
		t.Fatal("a restore overwrote an existing state file")
	}
	body, readErr := os.ReadFile(target) // #nosec G304; a test path
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(body) != "live state" {
		t.Error("the existing state was modified")
	}
}

func TestSkipReplayRestoresTheSnapshotAlone(t *testing.T) {
	// The escape hatch for a corrupt segment: older but intact beats nothing.
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 26))
	rep := newReplicator(t, src, archiver)

	put(t, src, store.KindService, "shop/web", "before")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	put(t, src, store.KindService, "shop/web", "after")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.db")
	result, err := archiver.Restore(ctx, RestoreOptions{Target: target, SkipReplay: true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if result.Replayed != 0 {
		t.Errorf("replayed %d changes despite SkipReplay", result.Replayed)
	}

	restored, err := store.Open(store.Options{Path: target})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = restored.Close() }()
	if value, _ := get(t, restored, store.KindService, "shop/web"); value != "before" {
		t.Errorf("shop/web = %q, want the snapshot's value", value)
	}
}

func TestReplayStopsAtAMissingSegmentRatherThanSkippingIt(t *testing.T) { // Replaying past a gap produces a state that never existed: a delete that
	// was in the missing segment never happens, and the record it removed comes
	// back.
	ctx := context.Background()
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 27))
	rep, err := NewReplicator(ReplicatorConfig{Archiver: archiver, Store: src, MaxChanges: 1})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}

	put(t, src, store.KindService, "shop/web", "one")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	del(t, src, store.KindService, "shop/web")
	put(t, src, store.KindService, "shop/api", "two")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	segments, err := archiver.Segments(ctx)
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(segments) < 2 {
		t.Fatalf("expected at least two segments, got %d", len(segments))
	}
	// Damage the first one so it cannot be read.
	damaged := filepath.Join(root, filepath.FromSlash(segments[0].Name))
	if err := os.WriteFile(damaged, []byte("not an archive"), 0o600); err != nil {
		t.Fatalf("damage: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.db")
	if _, err := archiver.Restore(ctx, RestoreOptions{Target: target}); err == nil {
		t.Fatal("a restore replayed past a segment it could not read")
	} else if !errors.Is(err, ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestReplayRefusesADeletedSegment(t *testing.T) {
	// A segment *unreadable* stops the replay (the test above); a segment
	// *deleted from the bucket* is the quieter half of the same attack: the
	// chain must refuse rather than skip, or a delete in the gap resurrects.
	ctx := context.Background()
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 28))
	rep, err := NewReplicator(ReplicatorConfig{Archiver: archiver, Store: src, MaxChanges: 1})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}

	put(t, src, store.KindService, "shop/web", "one")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	put(t, src, store.KindService, "shop/api", "two")
	put(t, src, store.KindService, "shop/worker", "three")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	segments, err := archiver.Segments(ctx)
	if err != nil {
		t.Fatalf("segments: %v", err)
	}
	if len(segments) < 2 {
		t.Fatalf("expected at least two segments, got %d", len(segments))
	}
	// Delete the middle one: nothing is "unreadable"; the chain just has a hole.
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(segments[0].Name))); err != nil {
		t.Fatalf("delete: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.db")
	_, err = archiver.Restore(ctx, RestoreOptions{Target: target})
	if err == nil {
		t.Fatal("a restore replayed across a deleted segment")
	} else if !errors.Is(err, ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestATamperedManifestIsRefused(t *testing.T) {
	// Everything a restore trusts comes from the manifest: the key id, the
	// index, the snapshot's name and hash. A bucket-write attacker editing any
	// of them must fail authentication (v1.74).
	ctx := context.Background()
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 29))
	put(t, src, store.KindService, "shop/web", "one")
	m, err := archiver.Create(ctx, "test", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	manifestPath := filepath.Join(root, "manifests", m.ID+".json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var tampered Manifest
	if err := json.Unmarshal(raw, &tampered); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The rollback shape: an older index, so a restore replays nothing recent.
	tampered.Index = 1 << 40
	edited, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(manifestPath, edited, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := archiver.Find(ctx, m.ID); err == nil {
		t.Fatal("a tampered manifest passed authentication")
	} else if !errors.Is(err, ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestAPreMACManifestIsAccepted(t *testing.T) {
	// An archive written before v1.74 has no MAC: the snapshot is still
	// AEAD-verified at decrypt, so the restore proceeds - with the warning
	// that says its metadata is unauthenticated.
	ctx := context.Background()
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 31))
	put(t, src, store.KindService, "shop/web", "one")
	m, err := archiver.Create(ctx, "test", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	manifestPath := filepath.Join(root, "manifests", m.ID+".json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var legacy Manifest
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("decode: %v", err)
	}
	legacy.MAC = ""
	rewritten, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(manifestPath, rewritten, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.db")
	if _, err := archiver.Restore(ctx, RestoreOptions{Target: target}); err != nil {
		t.Fatalf("a pre-MAC archive did not restore: %v", err)
	}
}

func TestReplicationEventsFireOnTransitionsOnly(t *testing.T) {
	// A destination that has been unreachable since yesterday is one fact, not
	// one per minute. Two events is the right number: it broke, it came back.
	var events []string
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 30))
	rep, err := NewReplicator(ReplicatorConfig{
		Archiver: archiver, Store: src,
		Emit: func(e notify.Event) { events = append(events, e.Name) },
	})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}

	broken := errors.New("the bucket is unreachable")
	rep.report(broken, "shipping")
	rep.report(broken, "shipping")
	rep.report(broken, "shipping")
	if len(events) != 1 || events[0] != notify.EventBackupFailed {
		t.Fatalf("events = %v, want one %s", events, notify.EventBackupFailed)
	}

	rep.report(nil, "shipping")
	rep.report(nil, "shipping")
	if len(events) != 2 || events[1] != notify.EventBackupSucceeded {
		t.Fatalf("events = %v, want a recovery event", events)
	}

	// A healthy replicator that has never failed says nothing at all: there is
	// no news in "the backup worked", every minute, forever.
	fresh, err := NewReplicator(ReplicatorConfig{
		Archiver: archiver, Store: src,
		Emit: func(notify.Event) { t.Error("a first success emitted an event") },
	})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}
	fresh.report(nil, "shipping")
}

func TestResumeDerivesTimestampsFromTheSink(t *testing.T) {
	// The last-success timestamps follow the cursor's rule: the sink already
	// knows when it last received something, and anything Kanea stored would
	// be state whose update needs shipping (v1.37).
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 40))
	rep := newReplicator(t, src, archiver)

	put(t, src, store.KindService, "shop/web", "one")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	put(t, src, store.KindService, "shop/web", "two")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	shipped, lastSegmentAt, lastSnapshotAt, err := archiver.Resume(ctx)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	index, err := src.Index(ctx)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if shipped != index {
		t.Errorf("resume shipped = %d, want the store's index %d", shipped, index)
	}
	if lastSegmentAt.IsZero() {
		t.Error("a sink holding a segment reported no last-segment time")
	}
	if lastSnapshotAt.IsZero() {
		t.Error("a sink holding a snapshot reported no last-snapshot time")
	}
	manifests, err := archiver.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !lastSnapshotAt.Equal(manifests[0].CreatedAt) {
		t.Errorf("last snapshot = %v, want the newest manifest's %v", lastSnapshotAt, manifests[0].CreatedAt)
	}
}

func TestResumeOnAnEmptySinkReportsNever(t *testing.T) {
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 41))

	shipped, lastSegmentAt, lastSnapshotAt, err := archiver.Resume(ctx)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if shipped != 0 || !lastSegmentAt.IsZero() || !lastSnapshotAt.IsZero() {
		t.Errorf("an empty sink resumed to shipped=%d segment=%v snapshot=%v, want zeroes",
			shipped, lastSegmentAt, lastSnapshotAt)
	}
}

// readOnlySink serves reads from a real sink and refuses writes, standing in
// for a restart during a sink outage: history is listable, uploads fail.
type readOnlySink struct{ Sink }

func (readOnlySink) Put(context.Context, string, int64, io.Reader) error {
	return errors.New("the bucket refuses writes")
}

func TestStatusTimestampsSurviveARestart(t *testing.T) {
	// Before v1.37 a restarted daemon reported "never" for the one number that
	// decides whether a backup strategy is real. A second replicator over the
	// same sink must report the first one's successes.
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, testKeys(t, 42))
	rep := newReplicator(t, src, archiver)

	put(t, src, store.KindService, "shop/web", "one")
	if err := rep.Snapshot(ctx, "test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	put(t, src, store.KindService, "shop/web", "two")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}

	// "The restart": a fresh replicator over the same bucket. The sink refuses
	// writes so nothing the new process does can set the timestamps itself,
	// and Run exits immediately on the already-cancelled context.
	restarted := newReplicator(t, openStore(t),
		newStoreArchiver(t, src, readOnlySink{sink}, testKeys(t, 42)))
	done, cancel := context.WithCancel(context.Background())
	cancel()
	restarted.Run(done)

	status := restarted.Status()
	if status.LastSegmentAt.IsZero() {
		t.Error("the restarted replicator forgot when the last segment shipped")
	}
	if status.LastSnapshotAt.IsZero() {
		t.Error("the restarted replicator forgot when the last snapshot was taken")
	}
	if status.ShippedTo == 0 {
		t.Error("the restarted replicator forgot the cursor")
	}
}
