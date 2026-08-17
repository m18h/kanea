package api_test

// GET /v1/volumes (PRD v1.69, §8, R31).

import (
	"context"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/storage"
)

// fakeUsage serves fixed readings, keyed the way the sampler keys them.
type fakeUsage map[string]storage.Usage

func (f fakeUsage) Snapshot() map[string]storage.Usage { return f }

func withVolumes(project, service string, count int, vols ...reconciler.Volume) reconciler.Desired {
	return reconciler.Desired{
		Project: project, Service: service, Count: count,
		Image: "nginx:1.27-alpine", Volumes: vols,
	}
}

func nfsVolume(name string) reconciler.Volume {
	return reconciler.Volume{
		Name: name, Storage: "nas", MountPath: "/" + name,
		Resource: storage.Resource{
			Name: "nas", Type: storage.TypeNFS, Server: "10.0.0.5", Export: "/tank",
		},
	}
}

// Two services mounting one resource land under one storage entry. A flat list
// would repeat the export's address twice and still not say they were the same
// export, which is the question being asked when it fills up.
func TestVolumesNestMountsUnderTheirStorage(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) { cfg.VolumeDir = "/vol" })
	h.putDesired(t, withVolumes("shop", "web", 1, nfsVolume("media")))
	h.putDesired(t, withVolumes("shop", "scan", 1, nfsVolume("media")))

	resp, err := h.client.Volumes(context.Background())
	if err != nil {
		t.Fatalf("volumes: %v", err)
	}
	if len(resp.Storages) != 1 {
		t.Fatalf("storages = %d, want 1; both services mount the same resource", len(resp.Storages))
	}
	st := resp.Storages[0]
	if st.Name != "nas" || st.Type != storage.TypeNFS {
		t.Errorf("storage = %s/%s, want nas/nfs", st.Name, st.Type)
	}
	if st.Target != "10.0.0.5:/tank" {
		t.Errorf("target = %q, want the export address", st.Target)
	}
	if len(st.Mounts) != 2 {
		t.Fatalf("mounts = %d, want 2", len(st.Mounts))
	}
}

// The §9.2 rule, on the surface where it is most tempting to break: a volume
// nobody has measured must not render as 0 bytes, which would say it is empty.
func TestAnUnmeasuredVolumeReportsAbsenceNotZero(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) { cfg.VolumeDir = "/vol" })
	h.putDesired(t, withVolumes("shop", "web", 1,
		reconciler.Volume{Name: "data", MountPath: "/data", SizeBytes: 10 << 30}))

	resp, err := h.client.Volumes(context.Background())
	if err != nil {
		t.Fatalf("volumes: %v", err)
	}
	mount := resp.Storages[0].Mounts[0]
	if mount.UsedBytes != nil {
		t.Errorf("used = %d for an unmeasured volume, want absent", *mount.UsedBytes)
	}
	if mount.State != api.MountUnmeasured {
		t.Errorf("state = %q, want %q", mount.State, api.MountUnmeasured)
	}
	// The declared budget is still shown: it is a fact about the spec, not a
	// measurement.
	if mount.SizeBytes == nil || *mount.SizeBytes != 10<<30 {
		t.Errorf("size = %v, want the declared budget", mount.SizeBytes)
	}
}

func TestAVolumeOverItsBudgetSaysSo(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.VolumeDir = "/vol"
		cfg.Usage = fakeUsage{
			"shop/web/data[0]": {Bytes: 20 << 30, Known: true},
			"shop/web/logs[0]": {Bytes: 1 << 30, Known: true},
		}
	})
	h.putDesired(t, withVolumes("shop", "web", 1,
		reconciler.Volume{Name: "data", MountPath: "/data", SizeBytes: 10 << 30},
		reconciler.Volume{Name: "logs", MountPath: "/logs", SizeBytes: 10 << 30}))

	resp, err := h.client.Volumes(context.Background())
	if err != nil {
		t.Fatalf("volumes: %v", err)
	}
	states := map[string]string{}
	for _, st := range resp.Storages {
		for _, m := range st.Mounts {
			states[m.Volume] = m.State
		}
	}
	if states["data[0]"] != api.MountOver {
		t.Errorf("data state = %q, want %q", states["data[0]"], api.MountOver)
	}
	if states["logs[0]"] != api.MountOK {
		t.Errorf("logs state = %q, want %q", states["logs[0]"], api.MountOK)
	}
}

// A volume with no budget is measured and reported, and never judged: there is
// nothing for it to be over.
func TestAVolumeWithNoBudgetIsNeverOver(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.VolumeDir = "/vol"
		cfg.Usage = fakeUsage{"shop/web/data[0]": {Bytes: 900 << 30, Known: true}}
	})
	h.putDesired(t, withVolumes("shop", "web", 1,
		reconciler.Volume{Name: "data", MountPath: "/data"}))

	resp, err := h.client.Volumes(context.Background())
	if err != nil {
		t.Fatalf("volumes: %v", err)
	}
	mount := resp.Storages[0].Mounts[0]
	if mount.State != api.MountOK {
		t.Errorf("state = %q, want %q", mount.State, api.MountOK)
	}
	if mount.SizeBytes != nil {
		t.Errorf("size = %d, want absent for an undeclared budget", *mount.SizeBytes)
	}
	if mount.UsedBytes == nil || *mount.UsedBytes != 900<<30 {
		t.Errorf("used = %v, want the measurement", mount.UsedBytes)
	}
}

// A local volume exists once per alloc, so a 3-alloc service has three of them:
// each with its own contents, and each worth seeing separately.
func TestALocalVolumeIsListedPerAlloc(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) { cfg.VolumeDir = "/vol" })
	h.putDesired(t, withVolumes("shop", "web", 3,
		reconciler.Volume{Name: "data", MountPath: "/data"}))

	resp, err := h.client.Volumes(context.Background())
	if err != nil {
		t.Fatalf("volumes: %v", err)
	}
	if len(resp.Storages) != 1 {
		t.Fatalf("storages = %d, want 1", len(resp.Storages))
	}
	if got := len(resp.Storages[0].Mounts); got != 3 {
		t.Errorf("mounts = %d for a 3-alloc local volume, want 3", got)
	}
}

// A host volume is the operator's own directory, shared by every alloc: one
// row, at the path they named.
func TestAHostVolumeIsListedOnceAtItsOwnPath(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) { cfg.VolumeDir = "/vol" })
	h.putDesired(t, withVolumes("shop", "web", 3, reconciler.Volume{
		Name: "media", Storage: "m", MountPath: "/media",
		Resource: storage.Resource{Name: "m", Type: storage.TypeHost, Path: "/srv/media"},
	}))

	resp, err := h.client.Volumes(context.Background())
	if err != nil {
		t.Fatalf("volumes: %v", err)
	}
	st := resp.Storages[0]
	if len(st.Mounts) != 1 {
		t.Fatalf("mounts = %d for a host volume, want 1", len(st.Mounts))
	}
	if st.Target != "/srv/media" || st.Mounts[0].Path != "/srv/media" {
		t.Errorf("target = %q, path = %q, want /srv/media", st.Target, st.Mounts[0].Path)
	}
}
