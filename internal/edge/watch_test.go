package edge

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// applied collects the tables a watcher hands over.
type applied struct {
	mu     sync.Mutex
	tables []*Table
}

func (a *applied) apply(t *Table) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tables = append(a.tables, t)
}

func (a *applied) last() *Table {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.tables) == 0 {
		return nil
	}
	return a.tables[len(a.tables)-1]
}

func (a *applied) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.tables)
}

func newTestWatcher(t *testing.T, path string) (*Watcher, *applied) {
	t.Helper()
	seen := &applied{}
	w, err := NewWatcher(WatcherConfig{
		Path:   path,
		Logger: slog.New(slog.DiscardHandler),
		Apply:  seen.apply,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	return w, seen
}

func TestWatcherLoadsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := Publish(path, Snapshot{Index: 1, Routes: []Route{testRoute()}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	w, seen := newTestWatcher(t, path)

	w.reload()
	if seen.count() != 1 {
		t.Fatalf("applied %d tables, want 1", seen.count())
	}

	// An unchanged file must not cost a rebuild: the edge polls once a second
	// forever, and a reload log line per tick is noise that hides real ones.
	w.reload()
	if seen.count() != 1 {
		t.Errorf("an unchanged snapshot was applied again (%d times)", seen.count())
	}

	next := testRoute()
	next.Domains = []string{"other.example.com"}
	if err := Publish(path, Snapshot{Index: 2, Routes: []Route{next}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	w.reload()
	if seen.count() != 2 {
		t.Fatalf("a changed snapshot was not applied (%d)", seen.count())
	}
	if _, ok := seen.last().Lookup("other.example.com"); !ok {
		t.Error("the new table does not hold the new domain")
	}
}

// "kanead is down" must not become "the site is down".
func TestWatcherKeepsTheLastGoodTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := Publish(path, Snapshot{Index: 1, Routes: []Route{testRoute()}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	w, seen := newTestWatcher(t, path)
	w.reload()

	for _, corruption := range []string{"{not json", `{"routes":[{"project":"x"}]}`, ""} {
		if err := os.WriteFile(path, []byte(corruption), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		w.reload()
		if seen.count() != 1 {
			t.Fatalf("a rejected snapshot (%q) replaced the table", corruption)
		}
	}

	// And the same when the file vanishes entirely.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	w.reload()
	if seen.count() != 1 {
		t.Error("a missing snapshot replaced the table")
	}

	// A file that becomes valid again is picked up; a rejected one must not
	// have been remembered as "seen".
	if err := Publish(path, Snapshot{Index: 3, Routes: []Route{testRoute()}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	w.reload()
	if seen.count() != 2 {
		t.Errorf("recovery was not applied (%d tables)", seen.count())
	}
}

// A node whose kanead has not started yet must come up serving nothing, not
// refuse to start.
func TestWatcherToleratesAMissingSnapshot(t *testing.T) {
	w, seen := newTestWatcher(t, filepath.Join(t.TempDir(), "absent.json"))
	w.reload()
	w.reload()
	if seen.count() != 0 {
		t.Errorf("applied %d tables for a file that does not exist", seen.count())
	}
}

func TestWatcherRunStopsWithTheContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := Publish(path, Snapshot{Routes: []Route{testRoute()}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	seen := &applied{}
	w, err := NewWatcher(WatcherConfig{
		Path:     path,
		Interval: 5 * time.Millisecond,
		Logger:   slog.New(slog.DiscardHandler),
		Apply:    seen.apply,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for seen.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("the watcher never loaded the snapshot")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()

	select {
	case err := <-done:
		if !isContextCanceled(err) {
			t.Errorf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher did not stop")
	}
}

func isContextCanceled(err error) bool { return errors.Is(err, context.Canceled) }

func TestNewWatcherRequiresItsInputs(t *testing.T) {
	if _, err := NewWatcher(WatcherConfig{Apply: func(*Table) {}}); err == nil {
		t.Error("accepted an empty path")
	}
	if _, err := NewWatcher(WatcherConfig{Path: "/tmp/x.json"}); err == nil {
		t.Error("accepted a nil Apply")
	}
}

// A snapshot that stays broken must be reported once, not once per poll. At the
// default interval an unnoticed corrupt file would otherwise write an error a
// second for as long as it sits there.
func TestWatcherReportsABadSnapshotOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := Publish(path, Snapshot{Index: 1, Routes: []Route{testRoute()}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var errs int
	seen := &applied{}
	w, err := NewWatcher(WatcherConfig{
		Path:   path,
		Logger: slog.New(countingHandler{count: &errs}),
		Apply:  seen.apply,
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.reload()

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for range 5 {
		w.reload()
	}
	if errs != 1 {
		t.Errorf("logged %d errors for one unchanged bad file, want 1", errs)
	}

	// A *different* bad file is a new fact and is reported again.
	if err := os.WriteFile(path, []byte("{also not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.reload()
	if errs != 2 {
		t.Errorf("logged %d errors, want a second for the changed file", errs)
	}
}

// countingHandler counts error-level records and discards everything else.
type countingHandler struct{ count *int }

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h countingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		*h.count++
	}
	return nil
}

func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }
