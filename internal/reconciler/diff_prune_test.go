package reconciler_test

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
)

func svc(project, service, image string, count int) reconciler.Desired {
	return reconciler.Desired{Project: project, Service: service, Image: image, Count: count}
}

// TestDiffWithoutAScopeShowsNoDestroy is the guard for every caller that cannot
// prune: MCP's plan_spec and the dashboard's spec editor share Diff, and a
// destroy line where no prune will happen is worse than none - the reader has
// no way to tell a warning from a plan.
func TestDiffWithoutAScopeShowsNoDestroy(t *testing.T) {
	current := []reconciler.Desired{svc("shop", "web", "web:v1", 1), svc("shop", "gone", "old:v1", 1)}
	desired := []reconciler.Desired{svc("shop", "web", "web:v2", 1)}

	for _, line := range reconciler.Diff(current, desired) {
		if strings.HasPrefix(line, "- destroy") {
			t.Errorf("Diff produced %q with no prune scope", line)
		}
	}
	// And DiffScoped with an empty scope must agree with Diff exactly.
	plain, scoped := reconciler.Diff(current, desired), reconciler.DiffScoped(current, desired, nil)
	if strings.Join(plain, "\n") != strings.Join(scoped, "\n") {
		t.Errorf("Diff and DiffScoped(nil) disagree:\n%v\n%v", plain, scoped)
	}
}

func TestDiffScopedRendersDestroyForOrphans(t *testing.T) {
	current := []reconciler.Desired{
		svc("shop", "web", "web:v1", 1),
		svc("shop", "legacy", "legacy:v1", 2),
	}
	desired := []reconciler.Desired{svc("shop", "web", "web:v1", 1)}

	lines := reconciler.DiffScoped(current, desired, []string{"shop"})
	var found bool
	for _, line := range lines {
		if strings.Contains(line, "- destroy shop/legacy") {
			found = true
			if !strings.Contains(line, "count 2") || !strings.Contains(line, "legacy:v1") {
				t.Errorf("destroy line does not say what would go: %q", line)
			}
		}
	}
	if !found {
		t.Errorf("no destroy line for the orphan; got %v", lines)
	}
}

// TestDiffScopedLeavesOtherProjectsAlone is the failure that would matter most:
// a spec for one project must never propose deleting another's services.
func TestDiffScopedLeavesOtherProjectsAlone(t *testing.T) {
	current := []reconciler.Desired{
		svc("shop", "web", "web:v1", 1),
		svc("data", "postgres", "pg:16", 1),
	}
	desired := []reconciler.Desired{svc("shop", "web", "web:v1", 1)}

	for _, line := range reconciler.DiffScoped(current, desired, []string{"shop"}) {
		if strings.Contains(line, "data/postgres") {
			t.Fatalf("a spec owning only shop proposed touching data: %q", line)
		}
	}
}

// TestDiffScopedPrefersTheRunningImage: a destroy line should name what is
// actually running, which for an auto-updated service is the pinned digest
// rather than the tag its spec declares.
func TestDiffScopedPrefersTheRunningImage(t *testing.T) {
	pinned := svc("shop", "legacy", "legacy:latest", 1)
	pinned.PinnedImage = "legacy@sha256:abc"
	lines := reconciler.DiffScoped([]reconciler.Desired{pinned}, nil, []string{"shop"})
	if len(lines) != 1 || !strings.Contains(lines[0], "sha256:abc") {
		t.Errorf("destroy line = %v, want the running (pinned) image", lines)
	}
}
