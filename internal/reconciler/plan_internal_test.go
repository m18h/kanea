package reconciler

import (
	"path/filepath"
	"testing"
)

func TestWithinBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "volumes")

	for _, tc := range []struct {
		path string
		want bool
	}{
		{filepath.Join(base, "shop", "web", "0", "data"), true},
		{base, true},
		{filepath.Join(base, "..", "etc"), false},
		{filepath.Join(base, "shop", "..", "..", "etc"), false},
		{"/etc/cron.d/x", false},
	} {
		if got := withinBase(base, tc.path); got != tc.want {
			t.Errorf("withinBase(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}

	// The composition the assertion guards: a traversal-shaped name joined
	// the way VolumeHostPath joins must read as an escape, never as a path
	// under the volume directory.
	escape := VolumeHostPath(base, "../../etc", "x", 0, "v")
	if withinBase(base, escape) {
		t.Errorf("withinBase(%q) = true for a traversal-composed path", escape)
	}
}
