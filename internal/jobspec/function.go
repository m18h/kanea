package jobspec

// The `function` block (PRD v1.39, §6.2 R25–R26): a wasm module run as a
// long-running wasi-http service on the wasmtime shim.
//
// A function lowers, at parse time, to an ordinary Service — one Store kind,
// one reconcile path, so deploys, pin carry-over, the autoscaler's listing and
// the spec editor are inherited rather than reimplemented. What makes it a
// function afterwards is Service.Function, which carries the triggers the
// invokers read live.
//
// R25's refusals are mostly structural: hclFunction simply has no field for a
// volume, device, socket, capabilities, user or scaling block, so declaring
// one is an HCL "block not expected here" error at the exact line. The two
// refusals that need naming — an exec health check, and function.* event
// patterns — are validated here.

import (
	"fmt"
	"path"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/m18h/kanea/internal/functions/cron"
	"github.com/m18h/kanea/internal/notify"
)

// DefaultFunctionPort is the wasi-http listen port when the block omits one.
const DefaultFunctionPort = 8080

// DefaultFunctionMemory is the memory default for functions, in MiB. Smaller
// than a container's DefaultMemory because a wasm module's baseline is
// kilobytes, and R11's point is a ceiling, not a grant.
const DefaultFunctionMemory = 64

// Trigger kinds (R26).
const (
	TriggerHTTP  = "http"
	TriggerEvent = "event"
	TriggerCron  = "cron"
)

// Function is what survives lowering: the trigger set and the listen port.
// It hangs off Service and is nil for every ordinary service.
type Function struct {
	// Port is the wasi-http server's listen port (the lowered service's sole
	// declared port, named "http").
	Port int
	// HTTP records that a `trigger "http"` was declared. Its detail — domains,
	// tls, middleware — lowers onto Service.Expose, exactly as for a service.
	HTTP bool
	// Events and Crons are read live by the invokers; they are deliberately
	// not part of the reconciler's spec hash (a cron edit must not roll the
	// alloc).
	Events []*EventTrigger
	Crons  []*CronTrigger
	// SigningRef MACs event/cron invocations (R26, v1.40).
	SigningRef string
	// DefRange is where the function block was declared, for diagnostics.
	DefRange hcl.Range
}

// EventTrigger fires a POST to the function on matching internal events (R26).
type EventTrigger struct {
	On       []string
	Path     string
	DefRange hcl.Range
}

// CronTrigger fires a POST to the function on a five-field UTC schedule (R26).
type CronTrigger struct {
	Schedule string
	Path     string
	DefRange hcl.Range
}

type hclFunction struct {
	Name        string `hcl:"name,label"`
	Project     string `hcl:"project,optional"`
	Description string `hcl:"description,optional"`
	// Module names an OCI image whose entrypoint is the wasm module. R8
	// applies: a function with a build block and no module is legal and waits
	// for its first build to pin a digest.
	Module string `hcl:"module,optional"`
	Port   *int   `hcl:"port,optional"`
	Count  *int   `hcl:"count,optional"`
	// RegistryAuthRef is the pull credential (R19), R5-scoped like every
	// other reference.
	RegistryAuthRef string `hcl:"registry_auth_ref,optional"`
	// SigningRef names the secret event/cron invocations are MACed with
	// (R26, v1.40). The function holds the same reference to verify.
	SigningRef string `hcl:"signing_ref,optional"`
	DependsOn       []string       `hcl:"depends_on,optional"`
	Env             hcl.Expression `hcl:"env,optional"`
	Build           *hclBuild      `hcl:"build,block"`
	Resources       *hclResources  `hcl:"resources,block"`
	Triggers        []hclTrigger   `hcl:"trigger,block"`
	HealthChecks    []hclHealthCheck `hcl:"health_check,block"`
	Update          *hclUpdate     `hcl:"update,block"`
	Restart         *hclRestart    `hcl:"restart,block"`
	DefRange        hcl.Range      `hcl:",def_range"`
}

// hclTrigger is one way of reaching the function's endpoint. The label picks
// the kind; which fields mean anything depends on it, and validateFunction
// refuses the ones that do not.
type hclTrigger struct {
	Kind string `hcl:"kind,label"`
	// http — the expose sub-schema, verbatim (R16/R20 apply unchanged).
	Domains       []string          `hcl:"domains,optional"`
	TLS           *hclTLS           `hcl:"tls,block"`
	IPRestriction *hclIPRestriction `hcl:"ip_restriction,block"`
	RateLimit     *hclRateLimit     `hcl:"rate_limit,block"`
	Headers       *hclHeaders       `hcl:"headers,block"`
	Auth          *hclAuth          `hcl:"auth,block"`
	// event
	On []string `hcl:"on,optional"`
	// cron
	Schedule string `hcl:"schedule,optional"`
	// event and cron
	Path     string    `hcl:"path,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

// convertFunction lowers a function block to a Service (R25).
func convertFunction(f *hclFunction) (*Service, hcl.Diagnostics) {
	var diags hcl.Diagnostics

	port := DefaultFunctionPort
	if f.Port != nil {
		port = *f.Port
	}

	svc := &Service{
		DefRange:    f.DefRange,
		Name:        f.Name,
		Project:     f.Project,
		Description: f.Description,
		Count:       DefaultCount,
		DependsOn:   f.DependsOn,
		Function:    &Function{Port: port, SigningRef: f.SigningRef, DefRange: f.DefRange},
	}
	if f.Count != nil {
		svc.Count = *f.Count
	}

	// The synthetic task: the module is the image, and the function's name is
	// the task's — there is no second name to invent and nothing to review in
	// one.
	svc.Task = &Task{
		DefRange:        f.DefRange,
		Name:            f.Name,
		Image:           f.Module,
		RegistryAuthRef: f.RegistryAuthRef,
		Env:             map[string]string{},
		Resources:       Resources{CPU: DefaultCPU, Memory: DefaultFunctionMemory},
	}
	if f.Resources != nil {
		svc.Task.ResourcesDeclared = true
		if f.Resources.CPU != nil {
			svc.Task.Resources.CPU = *f.Resources.CPU
		}
		if f.Resources.Memory != nil {
			svc.Task.Resources.Memory = *f.Resources.Memory
		}
	}

	if f.Build != nil {
		svc.Build = &Build{
			Context:         f.Build.Context,
			Dockerfile:      f.Build.Dockerfile,
			Target:          f.Build.Target,
			Tag:             f.Build.Tag,
			CacheRepo:       f.Build.CacheRepo,
			RegistryAuthRef: f.Build.RegistryAuthRef,
			DefRange:        f.DefRange,
		}
	}

	// The sole declared port. Named "http" so R16's unambiguous-port rule and
	// the edge's port selection work on the lowered service untouched.
	svc.Network = &Network{Ports: []*Port{{Name: "http", Container: port, DefRange: f.DefRange}}}

	for i := range f.Triggers {
		tr := &f.Triggers[i]
		switch tr.Kind {
		case TriggerHTTP:
			if svc.Function.HTTP {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Duplicate http trigger",
					Detail: fmt.Sprintf("Function %q already declares an http trigger. One route per function; "+
						"extra domains belong in its domains list.", f.Name),
					Subject: tr.DefRange.Ptr(),
				})
				continue
			}
			svc.Function.HTTP = true
			svc.Expose = convertExpose(&hclExpose{
				Domains: tr.Domains, TLS: tr.TLS,
				IPRestriction: tr.IPRestriction, RateLimit: tr.RateLimit, Headers: tr.Headers,
				Auth:     tr.Auth,
				DefRange: tr.DefRange,
			})
		case TriggerEvent:
			svc.Function.Events = append(svc.Function.Events, &EventTrigger{
				On: tr.On, Path: tr.Path, DefRange: tr.DefRange,
			})
		case TriggerCron:
			svc.Function.Crons = append(svc.Function.Crons, &CronTrigger{
				Schedule: tr.Schedule, Path: tr.Path, DefRange: tr.DefRange,
			})
		default:
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unknown trigger kind",
				Detail: fmt.Sprintf("Trigger %q on function %q is not a kind this version knows; "+
					"expected %q, %q or %q.", tr.Kind, f.Name, TriggerHTTP, TriggerEvent, TriggerCron),
				Subject: tr.DefRange.Ptr(),
			})
		}
	}

	for i := range f.HealthChecks {
		h := &f.HealthChecks[i]
		svc.HealthChecks = append(svc.HealthChecks, &HealthCheck{
			Name: h.Name, Type: h.Type, Path: h.Path, Port: h.Port, Command: h.Command,
			Interval: h.Interval, Timeout: h.Timeout, Failures: h.Failures, DefRange: h.DefRange,
		})
	}
	if f.Update != nil {
		svc.Update = &Update{
			Strategy: f.Update.Strategy, MaxParallel: f.Update.MaxParallel, MinHealthy: f.Update.MinHealthy,
			Auto: f.Update.Auto, Interval: f.Update.Interval, Deadline: f.Update.Deadline,
		}
	}
	if f.Restart != nil {
		svc.Restart = &Restart{Attempts: f.Restart.Attempts, Backoff: f.Restart.Backoff}
	}
	return svc, diags
}

// validateFunction is R25's named refusals and all of R26, run from
// validateServices for every service that was lowered from a function block.
// The structural rules — no volumes, no devices, no user — need nothing here:
// the block has no field to write them into.
func validateFunction(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	fn := svc.Function

	if fn.Port < 1 || fn.Port > 65535 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid function port",
			Detail:   fmt.Sprintf("Function %q declares port = %d; it must be 1-65535.", svc.Name, fn.Port),
			Subject:  fn.DefRange.Ptr(),
		})
	}

	// R26 — a function with no trigger is an error, not a service nothing
	// calls: the silent-channel rule (v1.24), applied to compute.
	if !fn.HTTP && len(fn.Events) == 0 && len(fn.Crons) == 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Function has no trigger",
			Detail: fmt.Sprintf("Function %q declares no trigger block. Nothing would ever invoke it; "+
				"declare trigger \"http\", \"event\" or \"cron\".", svc.Name),
			Subject: fn.DefRange.Ptr(),
		})
	}

	for _, ev := range fn.Events {
		diags = append(diags, validateEventTrigger(svc, ev)...)
	}
	for _, cr := range fn.Crons {
		if cr.Schedule == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Cron trigger has no schedule",
				Detail:   fmt.Sprintf("Function %q has a cron trigger with no schedule.", svc.Name),
				Subject:  cr.DefRange.Ptr(),
			})
		} else if _, err := cron.Parse(cr.Schedule); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid cron schedule",
				Detail: fmt.Sprintf("Function %q: %s. Schedules are five fields "+
					"(minute hour day-of-month month day-of-week), evaluated in UTC.", svc.Name, err),
				Subject: cr.DefRange.Ptr(),
			})
		}
		diags = append(diags, validateTriggerPath(svc, cr.Path, cr.DefRange)...)
	}

	if fn.SigningRef != "" {
		diags = append(diags, checkSecretRef(fn.SigningRef, svc.Project, "signing_ref", fn.DefRange)...)
	}

	// R25 — the wasmtime shim has no exec primitive, so an exec probe on a
	// function would be a check that can never pass, refused here by name.
	for _, h := range svc.HealthChecks {
		if h.Type == HealthExec {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Exec health check on a function",
				Detail: fmt.Sprintf("Function %q declares an exec health check, and the wasm runtime has no "+
					"exec primitive (R25). Probe it over http or tcp instead.", svc.Name),
				Subject: h.DefRange.Ptr(),
			})
		}
	}
	return diags
}

func validateEventTrigger(svc *Service, ev *EventTrigger) hcl.Diagnostics {
	var diags hcl.Diagnostics

	// An empty `on` is the silent channel again: a trigger nobody has told
	// what to fire on fires on nothing, indistinguishable from working.
	if len(ev.On) == 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Event trigger has no patterns",
			Detail:   fmt.Sprintf("Function %q has an event trigger with no `on` list.", svc.Name),
			Subject:  ev.DefRange.Ptr(),
		})
	}

	for _, p := range ev.On {
		// One vocabulary, one matcher: the same validation the notifications
		// block runs, so a pattern that passes `plan` cannot match nothing at
		// runtime.
		if err := notify.ValidatePattern(p); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unknown event pattern",
				Detail:   fmt.Sprintf("Function %q: %s.", svc.Name, err),
				Subject:  ev.DefRange.Ptr(),
			})
			continue
		}
		// R26 — a pattern that would match a function.* event is a feedback
		// loop with no damping: this function's own invoke_failed would
		// invoke it. Checked with the same Filter the dispatcher uses, so
		// the refusal and the runtime matcher cannot drift. The invoker skips
		// function.* events at match time too — the two-layer discipline R23
		// uses for ownership refusals.
		filter, err := notify.NewFilter([]string{p}, notify.SeverityInfo)
		if err == nil && filter.Match(notify.Event{
			Name: notify.EventFunctionInvokeFailed, Severity: notify.SeverityError,
		}) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Event pattern matches function events",
				Detail: fmt.Sprintf("Function %q: pattern %q matches function.* events, and a function invoked "+
					"by a function failure is a feedback loop (R26). Name the events you want instead.",
					svc.Name, p),
				Subject: ev.DefRange.Ptr(),
			})
		}
	}

	diags = append(diags, validateTriggerPath(svc, ev.Path, ev.DefRange)...)
	return diags
}

// validateTriggerPath checks an invocation path: normalized, absolute, no
// traversal. Empty means "/" and is fine.
func validateTriggerPath(svc *Service, p string, rng hcl.Range) hcl.Diagnostics {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "..") {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid trigger path",
			Detail: fmt.Sprintf("Function %q: trigger path %q must be a normalized absolute path "+
				"with no \"..\" (e.g. \"/kanea/event\").", svc.Name, p),
			Subject: rng.Ptr(),
		}}
	}
	return nil
}
