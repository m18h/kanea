package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/kanea-dev/kanea/internal/jobspec"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
)

// NominalCoreMHz maps the job spec's `resources.cpu` (MHz, PRD §6.1) onto the
// millicores the runtime needs for a CFS quota.
//
// The spec expresses CPU in MHz, Nomad-style, but a CFS quota is a fraction of
// a core — so a conversion factor is unavoidable. 1000 MHz = one core is the
// nominal figure used here, which makes `cpu = 500` half a core on every host.
// The alternative (measuring real core frequency at startup) would make the
// same spec mean different things on different machines, which is worse for a
// declarative system.
const NominalCoreMHz = 1000

// DefaultPidsLimit is applied to every alloc; the job spec has no field for it
// yet, and PRD §5.2.11 requires one on every container.
const DefaultPidsLimit = 256

// toDesired converts a validated job spec into the reconciler's desired state.
// It is the only place that knows both vocabularies.
func toDesired(spec *jobspec.Spec) ([]reconciler.Desired, error) {
	out := make([]reconciler.Desired, 0, len(spec.Services))

	for _, svc := range spec.Services {
		if svc.Task == nil {
			return nil, fmt.Errorf("service %s/%s has no task", svc.Project, svc.Name)
		}
		image := svc.Task.Image
		if image == "" {
			// R8 allows a build block with no image, but M1 has no pipeline: the
			// image would never materialise, so say so rather than fail later
			// with a confusing pull error.
			return nil, fmt.Errorf("service %s/%s has no task.image; building from source "+
				"arrives in M7, so an image reference is required for now", svc.Project, svc.Name)
		}

		desired := reconciler.Desired{
			Project:      svc.Project,
			Service:      svc.Name,
			Count:        svc.Count,
			Image:        image,
			Command:      svc.Task.Command,
			Capabilities: jobspec.NormalizeCapabilities(svc.Task.Capabilities),
			Env:          svc.Task.Env,
			Resources: runtime.Resources{
				CPUMillis:   svc.Task.Resources.CPU * 1000 / NominalCoreMHz,
				MemoryBytes: int64(svc.Task.Resources.Memory) << 20,
				PidsLimit:   DefaultPidsLimit,
			},
		}
		if svc.Network != nil {
			for _, p := range svc.Network.Ports {
				desired.Ports = append(desired.Ports, reconciler.Port{
					Name: p.Name, Container: p.Container,
				})
			}
			for _, peer := range svc.Network.Policy.Peers() {
				desired.AllowFrom = append(desired.AllowFrom, reconciler.PeerRef{
					Project: peer.Project, Service: peer.Service,
				})
			}
		}

		for _, v := range svc.Volumes {
			st := spec.StorageByName(v.Storage)
			// Validation guarantees the reference resolves; the type check is
			// what M1 can actually honour.
			if st != nil && st.Type != jobspec.StorageLocal {
				return nil, fmt.Errorf("service %s/%s: volume %q uses %s storage %q; "+
					"only local volumes are implemented in M1 (S3/NFS/SMB arrive in M2)",
					svc.Project, svc.Name, v.Name, st.Type, v.Storage)
			}
			desired.Volumes = append(desired.Volumes, reconciler.Volume{
				Name: v.Name, Storage: v.Storage, MountPath: v.MountPath, ReadOnly: v.ReadOnly,
			})
		}
		if svc.Restart != nil {
			desired.Restart.Attempts = svc.Restart.Attempts
			backoff, err := parseBackoff(svc.Restart.Backoff)
			if err != nil {
				return nil, fmt.Errorf("service %s/%s: restart backoff: %w", svc.Project, svc.Name, err)
			}
			desired.Restart.Backoff = backoff
		}
		out = append(out, desired)
	}
	return out, nil
}

// parseBackoff reads the spec's comma-separated schedule ("10s,30s,1m,5m").
func parseBackoff(s string) ([]time.Duration, error) {
	if s == "" {
		return nil, nil
	}
	var out []time.Duration
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		d, err := jobspec.ParseDuration(part)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", part, err)
		}
		out = append(out, d)
	}
	return out, nil
}
