package reconciler

// Internal for the reason plan_internal_test.go is: initSpecFor has no
// exported surface, and exporting one so a test could reach it would make a
// private decision part of the package's API.

import (
	"path/filepath"
	"testing"

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
