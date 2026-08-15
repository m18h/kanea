package reconciler_test

import (
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/storage"
)

// The R23 guard for v1.69's two new volume fields, in two halves that fail for
// different reasons.
//
// Half one is the upgrade: `Volume` is hashed *whole* by SpecHash, so a new
// field without `omitempty` changes the hash of every service that has a
// volume — and upgrading kanead would roll every one of them on the node.
//
// Half two is the edit: a budget is measured out of band and a `create` flag
// has already been acted on by the time a container exists, so neither is
// container state. Declaring one must not restart a database.
func TestAVolumeBudgetIsNotSpecHashMaterial(t *testing.T) {
	base := desired(3)
	base.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}

	// The digest TestSpecHashIsUnchangedForASpecWithNoUserOrOwnership pins:
	// the exact bytes this Desired hashed to before R23, and therefore long
	// before R31.
	before := reconciler.SpecHash(base)

	withBudget := desired(3)
	withBudget.Volumes = []reconciler.Volume{
		{Name: "data", MountPath: "/data", SizeBytes: 10 << 30},
	}
	if got := reconciler.SpecHash(withBudget); got != before {
		t.Errorf("declaring a volume size changed the spec hash (%s -> %s).\n"+
			"A budget is not baked into a container; hashing it would roll a "+
			"database to change a monitoring threshold.", before, got)
	}

	withCreate := desired(3)
	withCreate.Volumes = []reconciler.Volume{{
		Name: "data", MountPath: "/data",
		Resource: storage.Resource{Name: "h", Type: storage.TypeHost, Path: "/srv/d", Create: true},
	}}
	withoutCreate := desired(3)
	withoutCreate.Volumes = []reconciler.Volume{{
		Name: "data", MountPath: "/data",
		Resource: storage.Resource{Name: "h", Type: storage.TypeHost, Path: "/srv/d"},
	}}
	if a, b := reconciler.SpecHash(withCreate), reconciler.SpecHash(withoutCreate); a != b {
		t.Errorf("create = true changed the spec hash (%s vs %s).\n"+
			"By the time a container exists the directory question is already "+
			"answered; flipping the flag changes nothing about what is running.", a, b)
	}
}

// The projection must not corrupt the caller's desired state. It runs on every
// planning pass, and a SpecHash that quietly zeroed a budget would leave the
// usage sampler with nothing to compare against — a feature that silently
// stopped working, with the hash function to blame.
func TestHashingAVolumeDoesNotMutateIt(t *testing.T) {
	d := desired(1)
	d.Volumes = []reconciler.Volume{{
		Name: "data", MountPath: "/data", SizeBytes: 10 << 30,
		Resource: storage.Resource{Name: "h", Type: storage.TypeHost, Path: "/srv/d", Create: true},
	}}

	reconciler.SpecHash(d)

	if got := d.Volumes[0].SizeBytes; got != 10<<30 {
		t.Errorf("SizeBytes = %d after hashing, want it untouched", got)
	}
	if !d.Volumes[0].Resource.Create {
		t.Error("Create was cleared by hashing")
	}
}

// Everything else about a volume still rolls the alloc, because everything
// else about a volume *is* baked into the container: the mount is created with
// it. This is the other side of the projection, and without it the strip could
// quietly widen to fields that matter.
func TestVolumeChangesThatAreContainerStateStillRoll(t *testing.T) {
	base := desired(1)
	base.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}
	before := reconciler.SpecHash(base)

	for _, tc := range []struct {
		name   string
		volume reconciler.Volume
	}{
		{"mount path", reconciler.Volume{Name: "data", MountPath: "/elsewhere"}},
		{"read only", reconciler.Volume{Name: "data", MountPath: "/data", ReadOnly: true}},
		{"storage", reconciler.Volume{Name: "data", MountPath: "/data", Storage: "other"}},
		{"host path", reconciler.Volume{
			Name: "data", MountPath: "/data",
			Resource: storage.Resource{Type: storage.TypeHost, Path: "/srv/other"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := desired(1)
			d.Volumes = []reconciler.Volume{tc.volume}
			if got := reconciler.SpecHash(d); got == before {
				t.Errorf("changing the %s did not change the spec hash", tc.name)
			}
		})
	}
}

// A local volume exists once per alloc, so each is measured — and judged —
// separately. Summing them would hide the case a budget is for: one alloc
// filling its disk while two healthy siblings average the number down.
func TestVolumeTargetsCoverEveryLocalAlloc(t *testing.T) {
	d := desired(3)
	d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data", SizeBytes: 1 << 30}}

	targets := reconciler.VolumeTargetsFor(d, "/vol")

	if len(targets) != 3 {
		t.Fatalf("got %d targets for a 3-alloc local volume, want 3", len(targets))
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		seen[tg.Path] = true
		if tg.SizeBytes != 1<<30 {
			t.Errorf("target %s has budget %d, want the declared one", tg.Key, tg.SizeBytes)
		}
	}
	for i := range 3 {
		want := reconciler.VolumeHostPath("/vol", "shop", "web", i, "data")
		if !seen[want] {
			t.Errorf("no target for alloc %d at %s", i, want)
		}
	}
}

// A mounted volume is one mount per service by design, and a host volume is
// the operator's single directory. Both are one target however many allocs
// there are — measuring N times would be N walks of the same bytes.
func TestSharedVolumesAreMeasuredOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource storage.Resource
		wantPath string
	}{
		{
			name:     "nfs is shared per service",
			resource: storage.Resource{Name: "nas", Type: storage.TypeNFS, Server: "10.0.0.5"},
			wantPath: reconciler.SharedVolumeHostPath("/vol", "shop", "web", "data"),
		},
		{
			name:     "host is the operator's own directory",
			resource: storage.Resource{Name: "h", Type: storage.TypeHost, Path: "/srv/media"},
			wantPath: "/srv/media",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := desired(3)
			d.Volumes = []reconciler.Volume{
				{Name: "data", MountPath: "/data", Resource: tc.resource},
			}

			targets := reconciler.VolumeTargetsFor(d, "/vol")

			if len(targets) != 1 {
				t.Fatalf("got %d targets, want 1", len(targets))
			}
			if targets[0].Path != tc.wantPath {
				t.Errorf("path = %q, want %q", targets[0].Path, tc.wantPath)
			}
		})
	}
}
