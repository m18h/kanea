package api

// GET /v1/volumes (PRD v1.69, §8, §16.1): the volume view.
//
// A derived view, like the functions list beside it: storage resources with
// their mounts nested underneath, reconstructed from the volume records
// services already carry, plus the usage sampler's in-memory readings. There is
// no Store kind for a storage resource and this route does not add one.
//
// That has one honest consequence, stated here rather than left to be
// discovered: `toDesired` inlines a storage block into every volume that
// references it, and nothing on the node remembers the rest, so a storage
// resource **nothing references does not appear**. It is the same fact that
// makes §16.2's generator refuse to regenerate a spec with volume blocks.
//
// There are deliberately no mutation routes. A volume's existence is decided by
// the spec that declares it, and a "delete volume" verb here would be a second
// way to change desired state that the reconciler would immediately undo.

import (
	"net/http"
	"sort"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/storage"
	"github.com/m18h/kanea/internal/store"
)

// PathVolumes lists volumes.
const PathVolumes = "/v1/volumes"

// UsageSource reports measured volume usage. Interface at the consumer; the
// implementation is *storage.UsageSampler.
type UsageSource interface {
	Snapshot() map[string]storage.Usage
}

// Mount states, as an operator reads them.
const (
	// MountOK: present, and inside its budget if it declared one.
	MountOK = "ok"
	// MountOver: measured above its declared budget. Still serving (a budget
	// is not a quota (R31)) which is exactly why it needs saying.
	MountOver = "over"
	// MountUnmeasured: nothing has been measured yet, or the walk did not come
	// back, or the driver is not walked. Never rendered as zero (§9.2).
	MountUnmeasured = "unmeasured"
)

// VolumeMount is one service's use of a storage resource.
type VolumeMount struct {
	Project string `json:"project"`
	Service string `json:"service"`
	// Volume is the volume's name within the service, carrying the alloc index
	// for a local volume: those exist once per alloc, each with its own
	// contents.
	Volume    string `json:"volume"`
	MountPath string `json:"mount_path,omitempty"`
	ReadOnly  bool   `json:"read_only,omitempty"`
	// Path is the host directory backing it.
	Path string `json:"path,omitempty"`
	// UsedBytes is the measured usage, absent when unmeasured: a gap, never a
	// zero, because "empty" and "not looked at" are different facts.
	UsedBytes *int64 `json:"used_bytes,omitempty"`
	// SizeBytes is the declared budget (R31), absent when none was declared.
	SizeBytes *int64 `json:"size_bytes,omitempty"`
	State     string `json:"state"`
}

// VolumeStorage is one storage resource with everything mounting it.
type VolumeStorage struct {
	Project string `json:"project"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	// Target names where the storage comes from, in the driver's own terms:
	// an NFS export, a bucket, a host directory.
	Target string        `json:"target,omitempty"`
	Mounts []VolumeMount `json:"mounts"`
}

// VolumesResponse is the route's body.
type VolumesResponse struct {
	Storages []VolumeStorage `json:"storages"`
}

func (s *Server) handleListVolumes(w http.ResponseWriter, r *http.Request) {
	services, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var usage map[string]storage.Usage
	if s.usage != nil {
		usage = s.usage.Snapshot()
	}

	// Group by (project, storage name). Two services referencing one resource
	// carry identical copies of it, so either copy describes the group.
	groups := map[string]*VolumeStorage{}
	for _, d := range services {
		for _, target := range reconciler.VolumeTargetsFor(d, s.volumeDir) {
			name := storageNameOf(target)
			key := d.Project + "/" + name
			group, ok := groups[key]
			if !ok {
				group = &VolumeStorage{
					Project: d.Project,
					Name:    name,
					Type:    displayType(target.Type()),
					Target:  storageTarget(target.Resource),
				}
				groups[key] = group
			}
			group.Mounts = append(group.Mounts, mountView(target, usage))
		}
	}

	out := VolumesResponse{Storages: make([]VolumeStorage, 0, len(groups))}
	for _, g := range groups {
		sort.Slice(g.Mounts, func(i, j int) bool {
			a, b := g.Mounts[i], g.Mounts[j]
			if a.Service != b.Service {
				return a.Service < b.Service
			}
			return a.Volume < b.Volume
		})
		out.Storages = append(out.Storages, *g)
	}
	sort.Slice(out.Storages, func(i, j int) bool {
		a, b := out.Storages[i], out.Storages[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Name < b.Name
	})
	writeJSON(w, http.StatusOK, out)
}

// mountView renders one mount, resolving its usage against its budget.
func mountView(t reconciler.VolumeTarget, usage map[string]storage.Usage) VolumeMount {
	out := VolumeMount{
		Project: t.Project, Service: t.Service, Volume: t.Volume,
		MountPath: t.MountPath, ReadOnly: t.ReadOnly, Path: t.Path,
		State: MountUnmeasured,
	}
	if t.SizeBytes > 0 {
		size := t.SizeBytes
		out.SizeBytes = &size
	}

	measured, ok := usage[t.Key]
	if !ok || !measured.Known {
		// Absent, deliberately: an unmeasured volume must not render as 0,
		// which would say it is empty (§9.2).
		return out
	}
	used := measured.Bytes
	out.UsedBytes = &used
	out.State = MountOK
	if t.SizeBytes > 0 && used > t.SizeBytes {
		out.State = MountOver
	}
	return out
}

// storageNameOf answers what to group a volume under. A volume that names no
// storage resource is a local one, and local storage is the default that needs
// no declaration, so it groups under its own name rather than under "".
func storageNameOf(t reconciler.VolumeTarget) string {
	if t.Storage != "" {
		return t.Storage
	}
	return t.Resource.Name
}

// displayType names the driver. A local volume leaves Resource zero-valued, so
// an empty type is local rather than unknown.
func displayType(t string) string {
	if t == "" {
		return storage.TypeLocal
	}
	return t
}

// storageTarget describes where a resource's bytes actually live, in whatever
// terms that driver uses.
func storageTarget(r storage.Resource) string {
	switch r.Type {
	case storage.TypeHost:
		return r.Path
	case storage.TypeS3:
		if r.Endpoint != "" {
			return r.Endpoint + "/" + r.Bucket
		}
		return "s3://" + r.Bucket
	case storage.TypeNFS:
		return r.Server + ":" + r.Export
	case storage.TypeSMB:
		return "//" + r.Server + "/" + r.Share
	default:
		return ""
	}
}
