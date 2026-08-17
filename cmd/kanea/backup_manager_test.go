package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/store"
)

// The backup manager's one non-negotiable property (PRD v1.46): a bad new
// destination can never stop a working old one. These tests exercise the swap
// in both directions: refusal leaves the old pipeline untouched, success
// ships the old destination's final segment before the new one starts.

// writeMasterKey puts a usable master key under dataDir, the way `kanea init`
// would have. assembleReplication goes through secrets.LoadKey, which refuses
// to create one (a restore-on-a-fresh-node safety) so the tests provide it.
func writeMasterKey(t *testing.T, dataDir string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, secrets.KeyFileName), key, 0o600); err != nil {
		t.Fatalf("write master key: %v", err)
	}
}

// nopResolver fails every resolve. A dir sink never names a secret reference,
// so a test reaching this has wired something wrong and should hear about it.
type nopResolver struct{}

func (nopResolver) Resolve(context.Context, string) ([]byte, error) {
	return nil, errors.New("no secrets in this test")
}

// newDirBackupService assembles a real pipeline over a FileSink, through the
// same assembleReplication the daemon uses at startup.
func newDirBackupService(t *testing.T, st store.Store, dataDir, dir string) *backupService {
	t.Helper()
	svc, err := assembleReplication(context.Background(), replicationSettings{
		sink:    sinkOptions{dir: dir},
		dataDir: dataDir,
		store:   st,
	}, nopResolver{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("assembleReplication: %v", err)
	}
	return svc
}

// failingSink is a destination whose writes always fail: the shape of a
// bucket with revoked credentials or a typo'd endpoint. Probe fails on its
// first Put, which is exactly what the swap must survive.
type failingSink struct{}

func (failingSink) Put(context.Context, string, int64, io.Reader) error {
	return errors.New("the destination refused the write")
}
func (failingSink) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("the destination refused the read")
}
func (failingSink) List(context.Context, string) ([]backup.Object, error) {
	return nil, errors.New("the destination refused the listing")
}
func (failingSink) Delete(context.Context, string) error { return nil }
func (failingSink) Describe() string                     { return "failing://sink" }

// newFailingBackupService builds a pipeline over the failing sink directly:
// assembleReplication only builds real sinks, and the point here is a
// destination that accepts construction and refuses traffic.
func newFailingBackupService(t *testing.T, st store.Store) *backupService {
	t.Helper()
	keys, err := backup.DeriveKeys(make([]byte, 32))
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	archiver, err := backup.New(backup.Config{
		Sink: failingSink{}, Keys: keys,
		Snapshotter: backup.StoreSnapshotter{Store: st},
		WorkDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	replicator, err := backup.NewReplicator(backup.ReplicatorConfig{
		Archiver: archiver, Store: st,
	})
	if err != nil {
		t.Fatalf("new replicator: %v", err)
	}
	return &backupService{
		archiver: archiver, replicator: replicator,
		dataDir: t.TempDir(), log: slog.New(slog.DiscardHandler),
	}
}

// startManager adopts svc and runs the manager as the daemon would, cleaning
// the goroutine up when the test ends.
func startManager(t *testing.T, m *backupManager, svc *backupService, source string) {
	t.Helper()
	m.adopt(svc, source)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the manager did not shut down")
		}
	})
}

// pollUntil waits for a filesystem condition the pipeline reaches on its own
// schedule (a startup snapshot, a shipped segment).
func pollUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func globCount(t *testing.T, pattern string) int {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	return len(matches)
}

func TestManagerAnswersNotConfigured(t *testing.T) {
	// The manager is always non-nil (a node can go unconfigured → configured at
	// runtime), so "nothing behind it" must be ErrNotConfigured from every
	// method rather than a nil-interface panic: the API maps it to the 503 an
	// absent backup subsystem always answered with.
	ctx := context.Background()
	m := newBackupManager(slog.New(slog.DiscardHandler))

	if _, err := m.List(ctx); !errors.Is(err, backup.ErrNotConfigured) {
		t.Errorf("List = %v, want ErrNotConfigured", err)
	}
	if _, err := m.Create(ctx, "test"); !errors.Is(err, backup.ErrNotConfigured) {
		t.Errorf("Create = %v, want ErrNotConfigured", err)
	}
	if err := m.Verify(ctx, "any"); !errors.Is(err, backup.ErrNotConfigured) {
		t.Errorf("Verify = %v, want ErrNotConfigured", err)
	}
	if _, err := m.Stage(ctx, "any", false, "tester"); !errors.Is(err, backup.ErrNotConfigured) {
		t.Errorf("Stage = %v, want ErrNotConfigured", err)
	}
	if got := m.Status(); got != (backup.Status{}) {
		t.Errorf("Status = %+v, want the zero status", got)
	}
	if m.configured() {
		t.Error("configured() = true on a fresh manager")
	}
	if got := m.Source(); got != sourceNone {
		t.Errorf("Source = %q, want %q", got, sourceNone)
	}
}

func TestSwapToAFailingDestinationLeavesTheOldReplicationRunning(t *testing.T) {
	// The swap's order (probe, commit, stop, start) exists for this test's
	// property: a refused destination costs the operator nothing but the
	// retype. The old replicator never stops and the record is never written.
	ctx := context.Background()
	st := openScalingStore(t)
	dataDir := t.TempDir()
	writeMasterKey(t, dataDir)
	oldDir := t.TempDir()

	oldSvc := newDirBackupService(t, st, dataDir, oldDir)
	m := newBackupManager(slog.New(slog.DiscardHandler))
	startManager(t, m, oldSvc, sourceFlags)

	committed := false
	err := m.swap(ctx, newFailingBackupService(t, st), sourceStore, func() error {
		committed = true
		return nil
	})
	if err == nil {
		t.Fatal("swap accepted a destination whose probe failed")
	}
	// ErrInvalidSettings is what maps the refusal to a 400 in front of whoever
	// typed the endpoint, rather than a 500 that reads as Kanea's fault.
	if !errors.Is(err, api.ErrInvalidSettings) {
		t.Errorf("swap error = %v, want it to wrap api.ErrInvalidSettings", err)
	}
	// Commit never ran: a record for a destination that cannot take a write
	// would survive a restart and quietly become the configuration.
	if committed {
		t.Error("the commit ran for a destination that failed its probe")
	}
	if got := m.Source(); got != sourceFlags {
		t.Errorf("Source = %q after a refused swap, want %q unchanged", got, sourceFlags)
	}
	// And the old pipeline still answers: through the manager, the way the
	// API reaches it.
	if _, err := m.List(ctx); err != nil {
		t.Errorf("the old destination stopped serving after a refused swap: %v", err)
	}
}

func TestSwapShipsTheFinalSegmentToTheOldDestination(t *testing.T) {
	// stopLocked waits for the outgoing replicator's final ship, which lands in
	// the *old* destination: a change written just before the swap must not
	// fall into the gap between two pipelines.
	ctx := context.Background()
	st := openScalingStore(t)
	dataDir := t.TempDir()
	writeMasterKey(t, dataDir)
	oldDir, newDir := t.TempDir(), t.TempDir()

	m := newBackupManager(slog.New(slog.DiscardHandler))
	startManager(t, m, newDirBackupService(t, st, dataDir, oldDir), sourceFlags)

	// Wait out the old pipeline's startup snapshot first, so the change below
	// is provably *after* it: the final ship is then the only thing that can
	// carry it to oldDir.
	pollUntil(t, "the old destination's startup snapshot", func() bool {
		return globCount(t, filepath.Join(oldDir, "manifests", "*.json")) > 0
	})

	if _, err := st.Apply(ctx, store.Mutation{
		Op: store.OpPut, Kind: store.KindKV, Key: "swap-test/marker", Value: []byte(`"pending"`),
	}); err != nil {
		t.Fatalf("write the change: %v", err)
	}

	committed := false
	newSvc := newDirBackupService(t, st, dataDir, newDir)
	if err := m.swap(ctx, newSvc, sourceStore, func() error { committed = true; return nil }); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if !committed {
		t.Error("the commit did not run on a successful swap")
	}
	if got := m.Source(); got != sourceStore {
		t.Errorf("Source = %q after the swap, want %q", got, sourceStore)
	}

	// swap returns only after the old replicator's shutdown ship completed, so
	// the segment covering the change is already on disk; no polling here, and
	// none would be honest: after the swap nothing writes to oldDir again.
	if got := globCount(t, filepath.Join(oldDir, "segments", "*.seg")); got == 0 {
		t.Error("the old destination holds no segment; the pre-swap change was lost to the swap")
	}

	// The new pipeline starts with its own snapshot, so the new destination is
	// restorable without waiting six hours for the first scheduled one.
	pollUntil(t, "the new destination's startup snapshot", func() bool {
		return globCount(t, filepath.Join(newDir, "manifests", "*.json")) > 0
	})
}

func TestSwapToNilStopsReplication(t *testing.T) {
	// A nil svc is the deliberate transition to unconfigured (ResetBackup on a
	// node whose unit never named a destination), not an error, and not a
	// leak: the old pipeline is stopped and waited for.
	ctx := context.Background()
	st := openScalingStore(t)
	dataDir := t.TempDir()
	writeMasterKey(t, dataDir)

	m := newBackupManager(slog.New(slog.DiscardHandler))
	startManager(t, m, newDirBackupService(t, st, dataDir, t.TempDir()), sourceFlags)

	committed := false
	if err := m.swap(ctx, nil, sourceNone, func() error { committed = true; return nil }); err != nil {
		t.Fatalf("swap to nil: %v", err)
	}
	if !committed {
		t.Error("the commit did not run for the transition to unconfigured")
	}
	if m.configured() {
		t.Error("configured() = true after swapping to nil")
	}
	if got := m.Source(); got != sourceNone {
		t.Errorf("Source = %q, want %q", got, sourceNone)
	}
	if _, err := m.List(ctx); !errors.Is(err, backup.ErrNotConfigured) {
		t.Errorf("List after the stop = %v, want ErrNotConfigured", err)
	}
}

// A compile-time reminder that the manager is the api.Backups the daemon
// wires: the delegation surface must not drift from the interface.
var _ api.Backups = (*backupManager)(nil)
