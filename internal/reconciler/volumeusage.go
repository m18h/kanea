package reconciler

import (
	"strconv"

	"github.com/m18h/kanea/internal/storage"
)

// VolumeTarget is one volume as it exists on disk (PRD v1.69, §8, R31).
//
// It is the join of what the spec declared and where the reconciler actually
// put it, and it has two consumers: the usage sampler, which measures it, and
// `GET /v1/volumes`, which lists it. One derivation for both, so the thing that
// gets measured and the thing that gets shown cannot drift apart.
type VolumeTarget struct {
	// Key identifies this volume across passes, stable across a redeploy so a
	// volume keeps its measurement — and its over-budget verdict — when the
	// service it belongs to is updated.
	Key     string
	Project string
	Service string
	// Volume is the volume's name, carrying the alloc index for a local one.
	Volume string
	// Storage is the storage resource it was declared against.
	Storage   string
	MountPath string
	ReadOnly  bool
	// Path is the host directory backing it.
	Path string
	// SizeBytes is R31's declared budget, 0 for none.
	SizeBytes int64
	// Resource is the resolved storage resource, for its driver and address.
	Resource storage.Resource
}

// Type is the storage driver backing this volume.
func (t VolumeTarget) Type() string { return t.Resource.Type }

// usage projects the target onto what the sampler needs.
func (t VolumeTarget) usage() storage.UsageTarget {
	return storage.UsageTarget{
		Key: t.Key, Project: t.Project, Service: t.Service, Volume: t.Volume,
		Path: t.Path, Type: t.Resource.Type, BudgetBytes: t.SizeBytes,
	}
}

// VolumeTargetsFor derives one service's volumes.
//
// The shape follows the storage layout rather than the spec's, because that is
// what actually exists on disk:
//
//   - a **host** volume is the operator's own directory, mounted straight
//     through, so there is one of it however many allocs there are. The
//     declared path is used rather than the resolved one: resolution happens on
//     the node just before an alloc starts, and a service that has never
//     started yet still has a directory worth listing.
//   - a **mounted** volume (nfs, smb, s3) is one mount per service by design —
//     mounting a bucket once per alloc would be N mounts of the same bytes — so
//     it too is a single target. s3 is dropped by the sampler itself, which is
//     where the reason lives.
//   - a **local** volume is per alloc: `<volumeDir>/<p>/<s>/<index>/<name>`.
//     Each index is a distinct directory with distinct contents, so each is
//     listed and judged separately. One alloc filling its disk is exactly the
//     case a budget should catch, and summing them would hide it behind two
//     healthy siblings.
func VolumeTargetsFor(d Desired, volumeDir string) []VolumeTarget {
	var out []VolumeTarget
	for _, v := range d.Volumes {
		switch {
		case v.Resource.IsHost():
			out = append(out, volumeTarget(d, v, v.Name, v.Resource.Path))

		case v.Resource.NeedsMount():
			out = append(out, volumeTarget(d, v, v.Name,
				SharedVolumeHostPath(volumeDir, d.Project, d.Service, v.Name)))

		default:
			for i := range d.Count {
				name := v.Name + "[" + strconv.Itoa(i) + "]"
				out = append(out, volumeTarget(d, v, name,
					VolumeHostPath(volumeDir, d.Project, d.Service, i, v.Name)))
			}
		}
	}
	return out
}

// volumeTargets flattens every service's volumes into what the sampler wants.
func volumeTargets(desired []Desired, volumeDir string) []storage.UsageTarget {
	var out []storage.UsageTarget
	for _, d := range desired {
		for _, t := range VolumeTargetsFor(d, volumeDir) {
			out = append(out, t.usage())
		}
	}
	return out
}

func volumeTarget(d Desired, v Volume, name, path string) VolumeTarget {
	return VolumeTarget{
		Key:       d.Project + "/" + d.Service + "/" + name,
		Project:   d.Project,
		Service:   d.Service,
		Volume:    name,
		Storage:   v.Storage,
		MountPath: v.MountPath,
		ReadOnly:  v.ReadOnly,
		Path:      path,
		SizeBytes: v.SizeBytes,
		Resource:  v.Resource,
	}
}
