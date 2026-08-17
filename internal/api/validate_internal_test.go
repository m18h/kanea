package api

import (
	"strings"
	"testing"
)

func TestLogPathForRefusesATraversalAllocID(t *testing.T) {
	// The defense-in-depth half of the apply seam's name validation: even
	// with a traversal-shaped ID already in the Store (a record written
	// before the seam existed, or by a third route), the read path refuses
	// to leave the log directory. Shapes that clean *into* the directory
	// ("..", "a/b") are harmless and stay allowed.
	for _, id := range []string{"../../etc/passwd-0", "a/../../etc/passwd-0", "../../../../root/.ssh/id-0"} {
		if _, err := logPathFor(t.TempDir(), id); err == nil {
			t.Errorf("logPathFor(%q) = nil error, want the escape refused", id)
		}
	}

	dir := t.TempDir()
	got, err := logPathFor(dir, "shop-web-0")
	if err != nil {
		t.Fatalf("logPathFor(shop-web-0): %v", err)
	}
	if !strings.HasPrefix(got, dir) || !strings.HasSuffix(got, "shop-web-0.log") {
		t.Errorf("logPathFor = %q, want %s/shop-web-0.log", got, dir)
	}
}
