package jobspec

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// InternalDomain is the suffix of Kanea's internal zone (PRD §7.1).
const InternalDomain = "kanea"

// ServiceHost is the internal DNS name a ${service.<name>.host} reference
// resolves to. Names, never IPs: LB reprogramming and alloc restarts must not
// invalidate configuration (R9).
func ServiceHost(project, service string) string {
	return fmt.Sprintf("%s.%s.%s", service, project, InternalDomain)
}

// resolveEnv evaluates every task's env with a context that exposes the other
// services in the same project, and records the reference edges it finds.
//
// This is the second pass: it needs the first pass's output (every service's
// name and ports) to build that context, which is exactly why references are
// order-independent across files (R9).
func resolveEnv(spec *Spec, root *hclRoot, opts Options) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for i := range root.Services {
		raw := &root.Services[i]
		svc := spec.ServiceByName(raw.Project, raw.Name)
		if svc == nil || svc.Task == nil || len(raw.Tasks) == 0 {
			continue // structural errors already reported
		}
		task := svc.Task
		targets := []envTarget{{
			expr:   raw.Tasks[0].Env,
			assign: func(env map[string]string) { task.Env = env },
		}}
		// An init container's env resolves under exactly the same rules (R32):
		// it shares the alloc's network namespace, so ${service.db.host} in a
		// wait-for-database step is a real address and therefore a real
		// dependency edge. Skipping these would let a step reference a service
		// that R10 then never orders it behind, which is the failure the edge
		// exists to prevent.
		for n := range raw.Inits {
			if n >= len(svc.Inits) {
				break // conversion reported the mismatch
			}
			init := svc.Inits[n]
			targets = append(targets, envTarget{
				expr:   raw.Inits[n].Env,
				assign: func(env map[string]string) { init.Env = env },
			})
		}
		diags = append(diags, resolveServiceEnv(spec, svc, targets, opts)...)
	}
	// A lowered function's env resolves under the same rules: it can reference
	// its project's services (${service.db.host} in a webhook fanout is the
	// obvious use), and each reference is a dependency edge like any other.
	for i := range root.Functions {
		raw := &root.Functions[i]
		svc := spec.ServiceByName(raw.Project, raw.Name)
		if svc == nil || svc.Task == nil {
			continue
		}
		task := svc.Task
		diags = append(diags, resolveServiceEnv(spec, svc, []envTarget{{
			expr:   raw.Env,
			assign: func(env map[string]string) { task.Env = env },
		}}, opts)...)
	}
	return diags
}

// envTarget is one env expression and where its evaluated value goes. A
// service has one for its task and one per init block, and every one of them
// contributes reference edges to the service as a whole.
type envTarget struct {
	expr   hcl.Expression
	assign func(map[string]string)
}

// resolveServiceEnv evaluates one service's env expression and records its
// reference edges.
func resolveServiceEnv(spec *Spec, svc *Service, targets []envTarget, opts Options) hcl.Diagnostics {
	var diags hcl.Diagnostics

	// Collect and check references before evaluating: our diagnostics name
	// the missing service and port, HCL's would say "unsupported attribute".
	// Every target contributes, because the edge set belongs to the service
	// rather than to whichever block happened to write the reference.
	var refs []ServiceRef
	var refDiags hcl.Diagnostics
	for _, t := range targets {
		if t.expr == nil {
			continue
		}
		found, d := collectRefs(spec, svc, t.expr)
		refs = append(refs, found...)
		refDiags = append(refDiags, d...)
	}
	diags = append(diags, refDiags...)
	svc.Refs = refs

	edges := append([]string{}, svc.DependsOn...)
	for _, ref := range refs {
		edges = append(edges, ref.Service)
	}
	svc.Dependencies = sortUnique(edges)

	if refDiags.HasErrors() {
		return diags // evaluating now would only add noise
	}

	ctx := varContext(opts.Vars)
	ctx.Variables["service"] = serviceContext(spec, svc.Project)

	for _, t := range targets {
		if t.expr == nil {
			continue
		}
		env, evalDiags := evalEnv(t.expr, ctx)
		diags = append(diags, evalDiags...)
		if !evalDiags.HasErrors() {
			t.assign(env)
		}
	}
	return diags
}

// serviceContext builds the `service` variable: every service in the project,
// with its internal host name and named ports.
func serviceContext(spec *Spec, project string) cty.Value {
	services := map[string]cty.Value{}
	for _, svc := range spec.ServicesInProject(project) {
		ports := map[string]cty.Value{}
		if svc.Network != nil {
			for _, p := range svc.Network.Ports {
				// A udp port is absent, not present-and-useless: the VIP the
				// .host reference resolves to has no udp frontend (v1.42), so
				// a reference would bake in a number that reaches nothing.
				if p.IsUDP() {
					continue
				}
				ports[p.Name] = cty.NumberIntVal(int64(p.Container))
			}
		}
		attrs := map[string]cty.Value{
			"host": cty.StringVal(ServiceHost(project, svc.Name)),
		}
		// An empty object is still an object: referencing .port.x on a service
		// with no ports must fail as "no such port", not as a type error.
		attrs["port"] = cty.ObjectVal(ports)
		if len(ports) == 0 {
			attrs["port"] = cty.EmptyObjectVal
		}
		services[svc.Name] = cty.ObjectVal(attrs)
	}
	if len(services) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(services)
}

// collectRefs walks the env expression for `service.*` traversals, validating
// each one against the applied set (R9).
func collectRefs(spec *Spec, svc *Service, envExpr hcl.Expression) ([]ServiceRef, hcl.Diagnostics) {
	var (
		refs  []ServiceRef
		diags hcl.Diagnostics
	)

	pairs, pairDiags := hcl.ExprMap(envExpr)
	if pairDiags.HasErrors() {
		// Not a literal map (e.g. a variable holding one). References inside it
		// cannot be checked statically; HCL still evaluates it below.
		return nil, nil
	}

	for _, pair := range pairs {
		envKey := ""
		if v, keyDiags := pair.Key.Value(nil); !keyDiags.HasErrors() && v.Type() == cty.String {
			envKey = v.AsString()
		}
		for _, traversal := range pair.Value.Variables() {
			if traversal.RootName() != "service" {
				continue
			}
			ref, refDiags := parseServiceRef(spec, svc, traversal, envKey)
			diags = append(diags, refDiags...)
			if !refDiags.HasErrors() {
				refs = append(refs, ref)
			}
		}
	}
	return refs, diags
}

// parseServiceRef validates one traversal's shape and target. The accepted
// forms are exactly service.<name>.host and service.<name>.port.<port-name>.
func parseServiceRef(spec *Spec, from *Service, tr hcl.Traversal, envKey string) (ServiceRef, hcl.Diagnostics) {
	rng := tr.SourceRange()
	bad := func(detail string) hcl.Diagnostics {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid service reference",
			Detail:   detail,
			Subject:  rng.Ptr(),
		}}
	}

	if len(tr) < 3 {
		return ServiceRef{}, bad("A service reference must be ${service.<name>.host} or " +
			"${service.<name>.port.<port-name>}.")
	}
	name, ok := traversalName(tr[1])
	if !ok {
		return ServiceRef{}, bad("The service name must be a literal, e.g. ${service.postgres.host}.")
	}
	field, ok := traversalName(tr[2])
	if !ok {
		return ServiceRef{}, bad("Expected .host or .port.<port-name> after the service name.")
	}

	// Same-project only in v1 (R9). The lookup is scoped to the referencing
	// service's project, so a cross-project name simply does not resolve:
	// say so explicitly rather than reporting a bare "unknown service".
	target := spec.ServiceByName(from.Project, name)
	if target == nil {
		detail := fmt.Sprintf("Service %q is not declared in project %q. "+
			"Service references are same-project only in v1.", name, from.Project)
		if other := findServiceAnyProject(spec, name); other != nil {
			detail = fmt.Sprintf("Service %q belongs to project %q, but %q is in project %q. "+
				"Service references are same-project only in v1.",
				name, other.Project, from.Name, from.Project)
		}
		return ServiceRef{}, bad(detail)
	}
	if target.Name == from.Name {
		return ServiceRef{}, bad(fmt.Sprintf("Service %q references itself.", from.Name))
	}

	switch field {
	case "host":
		if len(tr) > 3 {
			return ServiceRef{}, bad("Nothing may follow .host in a service reference.")
		}
		return ServiceRef{From: from.Name, Service: name, EnvKey: envKey}, nil

	case "port":
		if len(tr) != 4 {
			return ServiceRef{}, bad("A port reference needs a port name: ${service." + name + ".port.<port-name>}.")
		}
		portName, ok := traversalName(tr[3])
		if !ok {
			return ServiceRef{}, bad("The port name must be a literal.")
		}
		port := declaredPort(target, portName)
		if port == nil {
			return ServiceRef{}, bad(fmt.Sprintf("Service %q has no port named %q. Declared ports: %s.",
				name, portName, describePorts(target)))
		}
		if port.IsUDP() {
			return ServiceRef{}, bad(fmt.Sprintf("Port %q of service %q is udp, and udp ports have "+
				"no service frontend (v1.42); the address this reference pairs with would reach "+
				"nothing. A udp port is reachable only where it is published.", portName, name))
		}
		return ServiceRef{From: from.Name, Service: name, Port: portName, EnvKey: envKey}, nil

	default:
		return ServiceRef{}, bad(fmt.Sprintf("Unknown service attribute %q; expected host or port.", field))
	}
}

func traversalName(part hcl.Traverser) (string, bool) {
	switch t := part.(type) {
	case hcl.TraverseAttr:
		return t.Name, true
	case hcl.TraverseIndex:
		if t.Key.Type() == cty.String {
			return t.Key.AsString(), true
		}
	}
	return "", false
}

func findServiceAnyProject(spec *Spec, name string) *Service {
	for _, svc := range spec.Services {
		if svc.Name == name {
			return svc
		}
	}
	return nil
}

// declaredPort finds a declared port by name, or nil.
func declaredPort(svc *Service, name string) *Port {
	if svc.Network == nil {
		return nil
	}
	for _, p := range svc.Network.Ports {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func describePorts(svc *Service) string {
	if svc.Network == nil || len(svc.Network.Ports) == 0 {
		return "none"
	}
	out := ""
	for i, p := range svc.Network.Ports {
		if i > 0 {
			out += ", "
		}
		out += p.Name
		// Marked so a "declared ports" list explains why a udp name was
		// still refused wherever only tcp ports count.
		if p.IsUDP() {
			out += " (udp)"
		}
	}
	return out
}

// evalEnv evaluates the env expression to a string map. Numbers and bools are
// converted: `${service.db.port.pg}` is a number, and an env var is a string.
func evalEnv(expr hcl.Expression, ctx *hcl.EvalContext) (map[string]string, hcl.Diagnostics) {
	val, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return nil, diags
	}
	if val.IsNull() {
		return map[string]string{}, diags
	}
	if !val.CanIterateElements() {
		return nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid env block",
			Detail:   "env must be a map of names to values.",
			Subject:  expr.Range().Ptr(),
		})
	}

	out := map[string]string{}
	for it := val.ElementIterator(); it.Next(); {
		k, v := it.Element()
		key, err := convert.Convert(k, cty.String)
		if err != nil {
			return nil, append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid env key",
				Detail:   fmt.Sprintf("Environment variable names must be strings: %s.", err),
				Subject:  expr.Range().Ptr(),
			})
		}
		str, err := convert.Convert(v, cty.String)
		if err != nil {
			return nil, append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid env value",
				Detail: fmt.Sprintf("Value of %q cannot be used as an environment variable: %s.",
					key.AsString(), err),
				Subject: expr.Range().Ptr(),
			})
		}
		if str.IsNull() {
			continue
		}
		out[key.AsString()] = str.AsString()
	}
	return out, diags
}
