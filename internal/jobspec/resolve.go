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
		diags = append(diags, resolveServiceEnv(spec, svc, raw.Tasks[0].Env, opts)...)
		diags = append(diags, resolveServiceFiles(spec, svc, &root.Services[i], opts)...)
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
		diags = append(diags, resolveServiceEnv(spec, svc, raw.Env, opts)...)
	}
	return diags
}

// resolveServiceEnv evaluates one service's env expression and records its
// reference edges.
func resolveServiceEnv(spec *Spec, svc *Service, envExpr hcl.Expression, opts Options) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if envExpr == nil {
		return diags
	}

	// Collect and check references before evaluating: our diagnostics name
	// the missing service and port, HCL's would say "unsupported attribute".
	//
	// The env groups this service takes contribute too (R34): a group is
	// evaluated once *per consuming service*, so a ${service.db.host} inside
	// one is this service's reference and this service's dependency edge. A
	// group evaluated once for the whole spec could not be either, because the
	// reference namespace is project-scoped.
	refs, refDiags := collectRefs(spec, svc, envExpr)
	for _, g := range svc.EnvFrom {
		group := spec.EnvGroupByName(g)
		if group == nil {
			continue // validateEnvGroups reports the undeclared name
		}
		for _, expr := range envGroupExprs(group) {
			found, d := collectExprRefs(spec, svc, expr, "")
			refs = append(refs, found...)
			refDiags = append(refDiags, d...)
		}
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

	// Defaults then specialize, the R20/R30 shape: the groups in the order
	// env_from lists them, then the service's own env on top.
	merged := map[string]string{}
	for _, g := range svc.EnvFrom {
		group := spec.EnvGroupByName(g)
		if group == nil {
			continue
		}
		groupEnv, groupDiags := evalEnvGroup(group, ctx)
		diags = append(diags, groupDiags...)
		for k, v := range groupEnv {
			merged[k] = v
		}
	}

	env, evalDiags := evalEnv(envExpr, ctx)
	diags = append(diags, evalDiags...)
	if !evalDiags.HasErrors() {
		for k, v := range env {
			merged[k] = v
		}
		svc.Task.Env = merged
	}
	return diags
}

// resolveServiceFiles renders each `file` block's content (R35).
//
// It runs in pass 2 for two reasons: content may reference ${service.*}, which
// only exists here, and ${secret.*} needs the per-file reference table that
// secretContext builds. A reference in a file is a dependency edge like any
// other, for the reason an init container's is: the rendered file names a peer's
// address, and a service whose config points at something must start behind it.
func resolveServiceFiles(spec *Spec, svc *Service, raw *hclService, opts Options) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for i := range svc.Files {
		if i >= len(raw.Files) {
			break // conversion reported the mismatch
		}
		f, rawFile := svc.Files[i], &raw.Files[i]
		where := fmt.Sprintf("file %q of service %q", f.Name, svc.Name)

		// `source` bytes were already read into Content; only an inline
		// `content` expression needs rendering. gohcl leaves an unset optional
		// hcl.Expression as a *literal null* rather than nil, so a nil check
		// alone would try to render a source-backed file and fail converting
		// null to a string.
		if rawFile.Content == nil || exprIsNull(rawFile.Content) {
			continue
		}

		for _, ref := range collectFileRefs(spec, svc, rawFile.Content) {
			svc.Refs = append(svc.Refs, ref)
			svc.Dependencies = sortUnique(append(svc.Dependencies, ref.Service))
		}

		interp, err := newSecretInterp()
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Cannot render file content",
				Detail:   fmt.Sprintf("%s: %s", where, err),
				Subject:  f.DefRange.Ptr(),
			})
			continue
		}

		ctx := varContext(opts.Vars)
		ctx.Variables["service"] = serviceContext(spec, svc.Project)
		secretVal, secretDiags := secretContext(rawFile.Content, svc.Project, where, interp)
		diags = append(diags, secretDiags...)
		if secretDiags.HasErrors() {
			continue
		}
		ctx.Variables[SecretNamespace] = secretVal

		val, evalDiags := rawFile.Content.Value(ctx)
		diags = append(diags, evalDiags...)
		if evalDiags.HasErrors() {
			continue
		}
		text, convErr := convert.Convert(val, cty.String)
		if convErr != nil || text.IsNull() {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid file content",
				Detail:   fmt.Sprintf("%s: content must be a string.", where),
				Subject:  f.DefRange.Ptr(),
			})
			continue
		}

		f.Content = []byte(text.AsString())
		f.SecretRefs = interp.refs
		if len(interp.refs) > 0 {
			f.Nonce = interp.nonce
		}
	}
	return diags
}

// collectFileRefs is collectExprRefs with the diagnostics dropped.
//
// They are dropped deliberately: the expression is evaluated immediately
// afterwards, and HCL reports an unresolvable reference against the same range
// with the same information, so keeping both would put two errors on one line.
func collectFileRefs(spec *Spec, svc *Service, expr hcl.Expression) []ServiceRef {
	refs, _ := collectExprRefs(spec, svc, expr, "") //nolint:errcheck // see above
	return refs
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
		found, pairDiags := collectExprRefs(spec, svc, pair.Value, envKey)
		refs = append(refs, found...)
		diags = append(diags, pairDiags...)
	}
	return refs, diags
}

// collectExprRefs walks one expression for `service.*` traversals.
//
// It is the per-expression core collectRefs applies to each entry of an env
// map, and it is also what an env group's values and a file's content go
// through: those are single expressions rather than maps, so hcl.ExprMap would
// simply return nothing for them - which is how a group's reference silently
// stopped being a dependency edge the first time this was written.
func collectExprRefs(
	spec *Spec, svc *Service, expr hcl.Expression, envKey string,
) ([]ServiceRef, hcl.Diagnostics) {
	var (
		refs  []ServiceRef
		diags hcl.Diagnostics
	)
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != "service" {
			continue
		}
		ref, refDiags := parseServiceRef(spec, svc, traversal, envKey)
		diags = append(diags, refDiags...)
		if !refDiags.HasErrors() {
			refs = append(refs, ref)
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
