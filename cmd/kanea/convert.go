package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/kanea-dev/kanea/internal/edge"
	"github.com/kanea-dev/kanea/internal/jobspec"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/storage"
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
		if image == "" && svc.Build == nil {
			// R8 allows a build block with no image — the first successful build
			// pins the digest (§10.2). Without one, nothing will ever fill it
			// in, so say so here rather than fail later with a confusing pull
			// error for an empty reference.
			return nil, fmt.Errorf("service %s/%s has no task.image and no build block; "+
				"give it an image to pull, or a build block to produce one",
				svc.Project, svc.Name)
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
		desired.Scaling = convertScaling(svc)
		desired.DependsOn = append(desired.DependsOn, svc.Dependencies...)
		if check := convertHealthCheck(svc); check != nil {
			desired.Check = check
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
		if expose := convertExpose(svc); expose != nil {
			desired.Expose = expose
		}

		for _, v := range svc.Volumes {
			// Validation guarantees the reference resolves (§8), so a nil here
			// would be a bug rather than a user error.
			st := spec.StorageByName(v.Storage)
			if st == nil {
				return nil, fmt.Errorf("service %s/%s: volume %q references undeclared storage %q",
					svc.Project, svc.Name, v.Name, v.Storage)
			}
			desired.Volumes = append(desired.Volumes, reconciler.Volume{
				Name: v.Name, Storage: v.Storage, MountPath: v.MountPath, ReadOnly: v.ReadOnly,
				Resource: storageResource(st),
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

// convertExpose carries the spec's ingress declaration into desired state.
//
// The domains are left exactly as declared, including empty. Generating the
// auto-FQDN needs the server's base_domain, which lives in node configuration —
// so it is the agent's to fill in, not the CLI's, and baking a name in here
// would make the same spec mean different things depending on which machine
// parsed it.
//
// The middleware travels verbatim. It is validated at plan time (R16) and again
// when the edge compiles it, so there is nothing to interpret in between.
func convertExpose(svc *jobspec.Service) *reconciler.Expose {
	if svc.Expose == nil {
		return nil
	}
	port := svc.EdgePort()
	if port == nil {
		// R16 rejects this at validation, so reaching it means an unvalidated
		// spec got here. A route with no upstream port is worse than no route.
		return nil
	}
	out := &reconciler.Expose{Domains: svc.Expose.Domains, Port: port.Container}
	if svc.Expose.TLS != nil {
		out.LetsEncrypt = svc.Expose.TLS.LetsEncrypt
	}
	if r := svc.Expose.IPRestriction; r != nil {
		out.IPRestriction = &edge.IPRestriction{Allow: r.Allow, Deny: r.Deny}
	}
	if rl := svc.Expose.RateLimit; rl != nil {
		out.RateLimit = &edge.RateLimit{
			Requests: rl.Requests, Window: rl.Window, Per: rl.Per, Burst: rl.Burst,
		}
	}
	if h := svc.Expose.Headers; h != nil {
		out.Headers = &edge.Headers{
			RequestSet: h.RequestSet, RequestRemove: h.RequestRemove,
			ResponseSet: h.ResponseSet, ResponseRemove: h.ResponseRemove,
		}
	}
	return out
}

// convertHealthCheck turns the first declared health check into the
// reconciler's form, resolving the named port to a number.
//
// Only the first is used. The spec allows several blocks, but "healthy" is one
// bit and combining checks needs a rule (all? any?) the PRD does not state —
// inventing one here would be a stealth spec decision.
// convertScaling carries the `scaling` block onto the desired state.
func convertScaling(svc *jobspec.Service) *reconciler.ScalingPolicy {
	if svc.Scaling == nil {
		return nil
	}
	policy := &reconciler.ScalingPolicy{
		Min:      svc.Scaling.Min,
		Max:      svc.Scaling.Max,
		Cooldown: svc.Scaling.Cooldown,
	}
	for _, m := range svc.Scaling.Metrics {
		policy.Metrics = append(policy.Metrics, reconciler.ScalingMetric{
			Name: m.Name, Target: float64(m.Target),
		})
	}
	return policy
}

func convertHealthCheck(svc *jobspec.Service) *reconciler.HealthCheck {
	if len(svc.HealthChecks) == 0 {
		return nil
	}
	hc := svc.HealthChecks[0]

	out := &reconciler.HealthCheck{
		Type:     hc.Type,
		Path:     hc.Path,
		Command:  hc.Command,
		Failures: hc.Failures,
	}
	if d, err := time.ParseDuration(hc.Interval); err == nil {
		out.Interval = d
	}
	if d, err := time.ParseDuration(hc.Timeout); err == nil {
		out.Timeout = d
	}

	// The check names a port; the datapath needs the number. jobspec has
	// already validated that the name exists (R7).
	if hc.Port != "" && svc.Network != nil {
		for _, p := range svc.Network.Ports {
			if p.Name == hc.Port {
				out.Port = p.Container
				break
			}
		}
	}
	return out
}

// storageResource converts a declared storage resource into the form the mount
// manager consumes.
func storageResource(st *jobspec.Storage) storage.Resource {
	return storage.Resource{
		Name:     st.Name,
		Type:     st.Type,
		Bucket:   st.Bucket,
		Endpoint: st.Endpoint,
		AuthRef:  st.AuthRef,
		Mode:     st.Mode,
		Server:   st.Server,
		Export:   st.Export,
		Share:    st.Share,
		Options:  st.Options,
		Path:     st.Path,
	}
}
