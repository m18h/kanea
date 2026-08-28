package reconciler

// Internal for the reason plan_internal_test.go is: initSpecFor has no
// exported surface, and exporting one so a test could reach it would make a
// private decision part of the package's API.

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/runtime"
)

// TestInitSpecWritesItsOwnLogFile pins where an init step's output lands: its
// own file, keyed by the init container's ID, beside the task's. Nothing
// pinned this before, and everything downstream leans on it - the shim appends
// there across retries, `kanea logs -c` and the dashboard both compose the
// same path, and teardown never deletes it. Losing the LogPath would lose the
// one transcript that says why a migration failed.
func TestInitSpecWritesItsOwnLogFile(t *testing.T) {
	task := runtime.AllocSpec{ID: "shop-web-0", Image: "app:v1"}
	step := InitContainer{Name: "migrate", Image: "app:v1", Command: []string{"alembic"}}
	d := Desired{Project: "shop", Service: "web", Init: []InitContainer{step}}

	spec := initSpecFor(task, d, 0, step, nil, nil, "/var/log/kanea/allocs")
	want := filepath.Join("/var/log/kanea/allocs", "shop-web-0.init.0.migrate.log")
	if spec.LogPath != want {
		t.Errorf("LogPath = %q, want %q", spec.LogPath, want)
	}

	// No log dir configured means no file, not a file at the cwd.
	spec = initSpecFor(task, d, 0, step, nil, nil, "")
	if spec.LogPath != "" {
		t.Errorf("LogPath with no log dir = %q, want empty", spec.LogPath)
	}
}

// TestTheAttemptMarkerLandsOnItsOwnLine pins markInitAttempt's newline
// semantics (PRD v1.102): a first attempt opens the file without a blank
// line, a previous attempt that died mid-line still yields a separator at
// column zero, and a marker that cannot be written costs nothing.
func TestTheAttemptMarkerLandsOnItsOwnLine(t *testing.T) {
	r := &Reconciler{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now: func() time.Time { return time.Date(2026, 8, 28, 1, 13, 4, 0, time.UTC) },
	}
	path := filepath.Join(t.TempDir(), "shop-web-0.init.0.migrate.log")

	// First attempt: the file does not exist yet; no leading blank line.
	r.markInitAttempt(path, "migrate")
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	want := `----- kanea: init "migrate" attempt started 2026-08-28T01:13:04Z -----` + "\n"
	if string(first) != want {
		t.Errorf("first marker = %q, want %q", first, want)
	}

	// The attempt dies mid-line; the next marker must still start a line.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("half a li"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r.markInitAttempt(path, "migrate")
	both, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read markers: %v", err)
	}
	if !strings.Contains(string(both), "half a li\n----- kanea: init") {
		t.Errorf("second marker did not start its own line:\n%s", both)
	}
	if got := strings.Count(string(both), "----- kanea: init"); got != 2 {
		t.Errorf("marker count = %d, want 2", got)
	}

	// An empty path (no log dir configured) and an unwritable one are both
	// silent no-ops: a log nicety must never fail a migration.
	r.markInitAttempt("", "migrate")
	r.markInitAttempt(filepath.Join(t.TempDir(), "missing", "dir", "x.log"), "migrate")
}
