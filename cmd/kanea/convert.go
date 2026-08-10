package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/certsource"
	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/storage"
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
			// The pull credential is a reference the node resolves, never a
			// value: a resolved credential here would travel into the Store.
			RegistryAuthRef: svc.Task.RegistryAuthRef,
			User:            convertUser(svc.Task.User),
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

		// A lowered function carries the wasm runtime and its trigger set
		// (R25/R26). The runtime is set here and nowhere else: the `function`
		// block is the only way a spec obtains it.
		if fn := svc.Function; fn != nil {
			desired.Runtime = runtime.RuntimeWasmtime
			desired.Function = &reconciler.FunctionMeta{HTTP: fn.HTTP, SigningRef: fn.SigningRef}
			for _, ev := range fn.Events {
				desired.Function.Events = append(desired.Function.Events, reconciler.EventTrigger{
					On: ev.On, Path: ev.Path,
				})
			}
			for _, cr := range fn.Crons {
				desired.Function.Crons = append(desired.Function.Crons, reconciler.CronTrigger{
					Schedule: cr.Schedule, Path: cr.Path,
				})
			}
		}

		if svc.Network != nil {
			for _, p := range svc.Network.Ports {
				desired.Ports = append(desired.Ports, reconciler.Port{
					Name: p.Name, Container: p.Container,
				})
			}
			for _, p := range svc.Network.Publish {
				// The middleware travels verbatim, as the expose block's does.
				// It is validated at plan time (R21) and again when the edge
				// compiles it, so there is nothing to interpret in between.
				desired.Publish = append(desired.Publish, reconciler.PublishedPort{
					Port: p.Port, Host: p.Host, Mode: p.ResolvedMode(),
					MaxConns:      p.MaxConns,
					IPRestriction: convertIPRestriction(p.IPRestriction),
					RateLimit:     convertRateLimit(p.RateLimit),
					Headers:       convertHeaders(p.Headers),
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
			mode, err := convertMode(v.Mode)
			if err != nil {
				return nil, fmt.Errorf("service %s/%s: volume %q: %w",
					svc.Project, svc.Name, v.Name, err)
			}
			desired.Volumes = append(desired.Volumes, reconciler.Volume{
				Name: v.Name, Storage: v.Storage, MountPath: v.MountPath, ReadOnly: v.ReadOnly,
				Resource: storageResource(st),
				// Ownership arrives already resolved against task.user: the
				// inheritance is spec-internal, so jobspec did it at conversion
				// and `kanea plan` shows what will actually be applied (R24).
				UID: convertID(v.UID), GID: convertID(v.GID), Mode: mode,
			})
		}
		// Grants cross as names. There is nothing to resolve here and nowhere to
		// resolve it from: the mapping lives on the node, and this runs wherever
		// the spec was written (R17, R18).
		if svc.Task != nil {
			for _, d := range svc.Task.Devices {
				desired.Devices = append(desired.Devices, reconciler.DeviceRequest{
					Name: d.Name, Grant: d.Grant,
				})
			}
			for _, s := range svc.Task.Sockets {
				desired.Sockets = append(desired.Sockets, reconciler.SocketRequest{
					Name: s.Name, Grant: s.Grant, MountPath: s.MountPath, ReadOnly: s.ReadOnly,
				})
			}
		}
		if svc.Restart != nil {
			desired.Restart.Attempts = svc.Restart.Attempts
			backoff, err := parseBackoff(svc.Restart.Backoff)
			if err != nil {
				return nil, fmt.Errorf("service %s/%s: restart backoff: %w", svc.Project, svc.Name, err)
			}
			desired.Restart.Backoff = backoff
		}
		if svc.Update != nil {
			desired.Update.Strategy = svc.Update.Strategy
			desired.Update.MaxParallel = svc.Update.MaxParallel
			if svc.Update.MinHealthy != "" {
				minHealthy, err := jobspec.ParseDuration(svc.Update.MinHealthy)
				if err != nil {
					return nil, fmt.Errorf("service %s/%s: update min_healthy: %w",
						svc.Project, svc.Name, err)
				}
				desired.Update.MinHealthy = minHealthy
			}
			desired.Update.Auto = svc.Update.Auto
			for _, d := range []struct {
				field string
				raw   string
				into  *time.Duration
			}{
				{"interval", svc.Update.Interval, &desired.Update.Interval},
				{"deadline", svc.Update.Deadline, &desired.Update.Deadline},
			} {
				if d.raw == "" {
					continue
				}
				parsed, err := jobspec.ParseDuration(d.raw)
				if err != nil {
					return nil, fmt.Errorf("service %s/%s: update %s: %w",
						svc.Project, svc.Name, d.field, err)
				}
				*d.into = parsed
			}
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
	out := &reconciler.Expose{
		Domains: svc.Expose.Domains, Port: port.Container,
		// Already normalized at parse: "" or "grpc" (R28).
		Protocol: svc.Expose.Protocol,
	}
	if t := svc.Expose.TLS; t != nil {
		out.TLSMode, out.TLSName = t.Mode, t.Name
		// The pre-v1.33 spelling, translated at the boundary rather than
		// carried inward: a stored record names a certificate source (R20), and
		// `letsencrypt = true` names exactly one of them. Only true translates
		// — false was indistinguishable from an absent block before v1.33 and
		// still defers to the node's --tls-default.
		//
		// The mode itself is *not* resolved here. toDesired runs client-side —
		// `kanea run`, the MCP server, the pipeline — so baking a node's
		// --tls-default in at conversion would make one spec mean different
		// things on two machines. An empty mode on a stored record means "the
		// node decides", and the node decides it in ResolveTLSMode.
		//nolint:staticcheck // reading the deprecated field is the point: this is
		// the one place the old spelling is translated, so nothing inward has to.
		if out.TLSMode == "" && t.LetsEncrypt != nil && *t.LetsEncrypt {
			out.TLSMode = string(certsource.ModeACME)
		}
	}
	out.IPRestriction = convertIPRestriction(svc.Expose.IPRestriction)
	out.RateLimit = convertRateLimit(svc.Expose.RateLimit)
	out.Headers = convertHeaders(svc.Expose.Headers)
	out.Auth = convertAuthPolicy(svc.Expose.Auth)
	return out
}

// convertAuthPolicy carries the R27 auth block into desired state as the
// references it declares. Resolution to verifier material happens on the
// node, in the reconciler's projection — never here, and never in the Store.
func convertAuthPolicy(a *jobspec.Auth) *reconciler.AuthPolicy {
	if a == nil {
		return nil
	}
	out := &reconciler.AuthPolicy{BasicRef: a.BasicRef, BearerRef: a.BearerRef}
	if j := a.JWT; j != nil {
		out.JWT = &reconciler.JWTAuthPolicy{
			Algorithm: j.Algorithm, SecretRef: j.SecretRef, PublicKeyRef: j.PublicKeyRef,
			Issuer: j.Issuer, Audience: j.Audience,
		}
	}
	return out
}

// The three middleware converters. Shared by expose and publish rather than
// duplicated: two translations of one rule are two things that can disagree.

func convertIPRestriction(r *jobspec.IPRestriction) *edge.IPRestriction {
	if r == nil {
		return nil
	}
	return &edge.IPRestriction{Allow: r.Allow, Deny: r.Deny}
}

func convertRateLimit(rl *jobspec.RateLimit) *edge.RateLimit {
	if rl == nil {
		return nil
	}
	return &edge.RateLimit{
		Requests: rl.Requests, Window: rl.Window, Per: rl.Per, Burst: rl.Burst,
	}
}

func convertHeaders(h *jobspec.Headers) *edge.Headers {
	if h == nil {
		return nil
	}
	return &edge.Headers{
		RequestSet: h.RequestSet, RequestRemove: h.RequestRemove,
		ResponseSet: h.ResponseSet, ResponseRemove: h.ResponseRemove,
	}
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

// convertUser narrows a validated user block to the runtime's numeric form
// (R23).
//
// jobspec carries these as ints so that validateUser can report an
// out-of-range value as written; this is where they become the uint32s the OCI
// spec uses, after validation has refused the ones that would not survive it.
// It is the same boundary Resources is narrowed at, a few lines up.
func convertUser(u *jobspec.User) *runtime.User {
	if u == nil {
		return nil
	}
	out := &runtime.User{UID: uint32(u.UID), GID: uint32(u.GID)} // #nosec G115 — bounded by validateUser
	for _, g := range u.Groups {
		out.AdditionalGIDs = append(out.AdditionalGIDs, uint32(g)) // #nosec G115 — same bound
	}
	return out
}

// convertID narrows one validated uid or gid, preserving "undeclared".
func convertID(id *int) *uint32 {
	if id == nil {
		return nil
	}
	v := uint32(*id) // #nosec G115 — bounded by validateVolumeOwnership
	return &v
}

// convertMode parses a validated volume mode. The error is unreachable after
// validation and returned rather than dropped, because "unreachable" is a claim
// about a caller and this function has more than one.
func convertMode(mode *string) (*uint32, error) {
	if mode == nil {
		return nil, nil
	}
	v, err := jobspec.ParseMode(*mode)
	if err != nil {
		return nil, err
	}
	return &v, nil
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
