package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/zclconf/go-cty/cty"
)

// toHCL generates a job spec from desired state: the inverse of toDesired,
// for the dashboard's "edit spec" (v1.38).
//
// It is best-effort by design and honest about it: the output is marked
// generated, comments and variable interpolations from the original file are
// gone (resolved values appear as literals), and a field the generator cannot
// express refuses by name rather than emitting a spec that would apply as
// something other than what is running. The round-trip test pins the rest:
// toDesired(parse(toHCL(d))) must reproduce d minus the server-owned fields
// the apply path carries (Generation, the auto-update pin).
func toHCL(services []reconciler.Desired, pipelines []gitops.Config) (string, error) {
	file := hclwrite.NewEmptyFile()
	body := file.Body()

	body.AppendUnstructuredTokens(hclwrite.Tokens{{
		Type: 0,
		Bytes: []byte("# Generated from the running desired state. Comments and variable\n" +
			"# interpolations from the original file are not preserved; resolved values\n" +
			"# appear as literals.\n"),
	}})
	body.SetAttributeValue("spec_version", cty.NumberIntVal(1))
	body.AppendNewline()

	byProject := map[string]gitops.Config{}
	for _, cfg := range pipelines {
		byProject[cfg.Project] = cfg
	}

	projects := map[string]struct{}{}
	for _, svc := range services {
		projects[svc.Project] = struct{}{}
	}
	for _, cfg := range pipelines {
		projects[cfg.Project] = struct{}{}
	}
	names := make([]string, 0, len(projects))
	for name := range projects {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		block := body.AppendNewBlock("project", []string{name})
		cfg, ok := byProject[name]
		if ok {
			if cfg.Notifications != nil {
				return "", fmt.Errorf("cannot generate a spec for project %s: its notifications "+
					"block is not expressible by the generator; edit the original spec file", name)
			}
			if cfg.HasSource() {
				git := block.Body().AppendNewBlock("git", nil).Body()
				git.SetAttributeValue("url", cty.StringVal(cfg.Source.URL))
				setOptionalString(git, "branch", cfg.Source.Branch)
				setOptionalString(git, "path", cfg.Source.Path)
				setOptionalString(git, "auth_ref", cfg.Source.AuthRef)
				setOptionalString(git, "webhook_secret_ref", cfg.WebhookSecretRef)
				if cfg.PollInterval > 0 {
					git.SetAttributeValue("poll_interval", cty.StringVal(cfg.PollInterval.String()))
				}
				if cfg.RequireApproval {
					git.SetAttributeValue("require_approval", cty.True)
				}
			}
		}
		body.AppendNewline()
	}

	for i := range services {
		svc := &services[i]
		var err error
		if svc.Function != nil {
			// A lowered function regenerates as the block that produced it
			// (R25): a service block carrying runtime internals would apply as
			// something the parser cannot produce.
			err = writeFunction(body, svc, byProject[svc.Project])
		} else {
			err = writeService(body, svc, byProject[svc.Project])
		}
		if err != nil {
			return "", err
		}
		body.AppendNewline()
	}

	return string(hclwrite.Format(file.Bytes())), nil
}

// writeFunction renders one function block: the inverse of convertFunction's
// lowering.
func writeFunction(body *hclwrite.Body, svc *reconciler.Desired, cfg gitops.Config) error {
	refuse := func(field string) error {
		return fmt.Errorf("cannot generate a spec for function %s/%s: %s is not expressible by the "+
			"generator; edit the original spec file", svc.Project, svc.Service, field)
	}
	// A function's spec has no field for any of these (R25), so a desired
	// record carrying one did not come from the parser; refuse by name rather
	// than emit a block that would apply as something else.
	switch {
	case len(svc.Volumes) > 0:
		return refuse("its volume blocks")
	case len(svc.Devices) > 0 || len(svc.Sockets) > 0:
		return refuse("its passthrough grants")
	case svc.User != nil:
		return refuse("its user block")
	case len(svc.Capabilities) > 0:
		return refuse("its capability grants")
	case len(svc.Command) > 0:
		return refuse("its command override")
	case len(svc.Init) > 0:
		// A function block has no init field (R25/R32): the wasm runtime runs
		// one module, so there is no second container to run.
		return refuse("its init containers")
	case svc.Scaling != nil:
		return refuse("its scaling policy")
	case svc.ReadOnlyRootfs:
		return refuse("read_only_rootfs")
	case svc.Resources.PidsLimit != 0 && svc.Resources.PidsLimit != DefaultPidsLimit:
		return refuse("a non-default pids limit")
	}
	// The lowering declares exactly one port, named "http"; anything else
	// cannot round-trip through `port = N`.
	if len(svc.Ports) != 1 || svc.Ports[0].Name != jobspec.EdgePortName {
		return refuse("its port set (a function has exactly one, named \"http\")")
	}

	block := body.AppendNewBlock("function", []string{svc.Service}).Body()
	block.SetAttributeValue("project", cty.StringVal(svc.Project))
	// The declared tag, never PinnedImage: same rule as writeTask.
	setOptionalString(block, "module", svc.Image)
	block.SetAttributeValue("port", cty.NumberIntVal(int64(svc.Ports[0].Container)))
	block.SetAttributeValue("count", cty.NumberIntVal(int64(svc.Count)))
	setOptionalString(block, "registry_auth_ref", svc.RegistryAuthRef)
	setOptionalString(block, "signing_ref", svc.Function.SigningRef)
	if len(svc.DependsOn) > 0 {
		block.SetAttributeValue("depends_on", stringList(svc.DependsOn))
	}
	if len(svc.Env) > 0 {
		keys := make([]string, 0, len(svc.Env))
		for k := range svc.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make(map[string]cty.Value, len(keys))
		for _, k := range keys {
			pairs[k] = cty.StringVal(svc.Env[k])
		}
		block.SetAttributeValue("env", cty.ObjectVal(pairs))
	}
	block.AppendNewline()

	if build, ok := cfg.Builds[svc.Service]; ok {
		b := block.AppendNewBlock("build", nil).Body()
		b.SetAttributeValue("context", cty.StringVal(build.Context))
		setOptionalString(b, "dockerfile", build.Dockerfile)
		setOptionalString(b, "target", build.Target)
		setOptionalString(b, "tag", build.Tag)
		setOptionalString(b, "cache_repo", build.CacheRepo)
		setOptionalString(b, "registry_auth_ref", build.RegistryAuthRef)
		block.AppendNewline()
	}

	if writeResources(block, svc) {
		block.AppendNewline()
	}

	if svc.Function.HTTP {
		tr := block.AppendNewBlock("trigger", []string{jobspec.TriggerHTTP}).Body()
		if e := svc.Expose; e != nil {
			if len(e.Domains) > 0 {
				tr.SetAttributeValue("domains", stringList(e.Domains))
			}
			if e.TLSMode != "" || e.TLSName != "" {
				tls := tr.AppendNewBlock("tls", nil).Body()
				setOptionalString(tls, "mode", e.TLSMode)
				setOptionalString(tls, "name", e.TLSName)
			}
			writeMiddleware(tr, e.IPRestriction, e.RateLimit, e.Headers)
			writeAuth(tr, e.Auth)
		}
		block.AppendNewline()
	}
	for _, ev := range svc.Function.Events {
		tr := block.AppendNewBlock("trigger", []string{jobspec.TriggerEvent}).Body()
		tr.SetAttributeValue("on", stringList(ev.On))
		setOptionalString(tr, "path", ev.Path)
		block.AppendNewline()
	}
	for _, cr := range svc.Function.Crons {
		tr := block.AppendNewBlock("trigger", []string{jobspec.TriggerCron}).Body()
		tr.SetAttributeValue("schedule", cty.StringVal(cr.Schedule))
		setOptionalString(tr, "path", cr.Path)
		block.AppendNewline()
	}

	if svc.Check != nil {
		if err := writeHealthCheck(block, svc); err != nil {
			return err
		}
	}

	if u := svc.Update; u.Strategy != "" || u.MaxParallel != 0 || u.MinHealthy != 0 ||
		u.Auto || u.Interval != 0 || u.Deadline != 0 {
		update := block.AppendNewBlock("update", nil).Body()
		setOptionalString(update, "strategy", u.Strategy)
		if u.MaxParallel != 0 {
			update.SetAttributeValue("max_parallel", cty.NumberIntVal(int64(u.MaxParallel)))
		}
		setOptionalDuration(update, "min_healthy", u.MinHealthy)
		if u.Auto {
			update.SetAttributeValue("auto", cty.True)
		}
		setOptionalDuration(update, "interval", u.Interval)
		setOptionalDuration(update, "deadline", u.Deadline)
		block.AppendNewline()
	}

	if svc.Restart.Attempts != 0 || len(svc.Restart.Backoff) > 0 {
		restart := block.AppendNewBlock("restart", nil).Body()
		if svc.Restart.Attempts != 0 {
			restart.SetAttributeValue("attempts", cty.NumberIntVal(int64(svc.Restart.Attempts)))
		}
		if len(svc.Restart.Backoff) > 0 {
			parts := make([]string, 0, len(svc.Restart.Backoff))
			for _, d := range svc.Restart.Backoff {
				parts = append(parts, d.String())
			}
			restart.SetAttributeValue("backoff", cty.StringVal(strings.Join(parts, ",")))
		}
	}
	return nil
}

// writeService renders one service block.
func writeService(body *hclwrite.Body, svc *reconciler.Desired, cfg gitops.Config) error {
	refuse := func(field string) error {
		return fmt.Errorf("cannot generate a spec for %s/%s: %s is not expressible by the "+
			"generator; edit the original spec file", svc.Project, svc.Service, field)
	}
	// The refusal list. Each of these has spec syntax the generator does not
	// write yet; emitting a spec without them would apply as a service that
	// silently lost them.
	if len(svc.Volumes) > 0 {
		return refuse("its volume blocks (the storage declarations are not reconstructible)")
	}
	if svc.ReadOnlyRootfs {
		return refuse("read_only_rootfs")
	}
	if svc.Resources.PidsLimit != 0 && svc.Resources.PidsLimit != DefaultPidsLimit {
		return refuse("a non-default pids limit")
	}

	block := body.AppendNewBlock("service", []string{svc.Service}).Body()
	block.SetAttributeValue("project", cty.StringVal(svc.Project))
	block.SetAttributeValue("count", cty.NumberIntVal(int64(svc.Count)))
	if len(svc.DependsOn) > 0 {
		block.SetAttributeValue("depends_on", stringList(svc.DependsOn))
	}
	block.AppendNewline()

	if build, ok := cfg.Builds[svc.Service]; ok {
		b := block.AppendNewBlock("build", nil).Body()
		b.SetAttributeValue("context", cty.StringVal(build.Context))
		setOptionalString(b, "dockerfile", build.Dockerfile)
		setOptionalString(b, "target", build.Target)
		setOptionalString(b, "tag", build.Tag)
		setOptionalString(b, "cache_repo", build.CacheRepo)
		setOptionalString(b, "registry_auth_ref", build.RegistryAuthRef)
		block.AppendNewline()
	}

	writeInits(block, svc)
	if err := writeTask(block, svc); err != nil {
		return err
	}

	if len(svc.Ports) > 0 || len(svc.Publish) > 0 || len(svc.AllowFrom) > 0 {
		network := block.AppendNewBlock("network", nil).Body()
		for _, p := range svc.Ports {
			port := network.AppendNewBlock("port", []string{p.Name}).Body()
			port.SetAttributeValue("container", cty.NumberIntVal(int64(p.Container)))
			// "" is tcp, the default; only udp is stored, and only udp is
			// emitted: the round-trip depends on the generated spec
			// converting back to the same "" (v1.42).
			setOptionalString(port, "protocol", p.Protocol)
		}
		for i := range svc.Publish {
			p := &svc.Publish[i]
			pub := network.AppendNewBlock("publish", []string{p.Port}).Body()
			pub.SetAttributeValue("host", cty.NumberIntVal(int64(p.Host)))
			setOptionalString(pub, "mode", p.Mode)
			if p.MaxConns > 0 {
				pub.SetAttributeValue("max_conns", cty.NumberIntVal(int64(p.MaxConns)))
			}
			writeMiddleware(pub, p.IPRestriction, p.RateLimit, p.Headers)
		}
		if len(svc.AllowFrom) > 0 {
			peers := make([]string, 0, len(svc.AllowFrom))
			for _, peer := range svc.AllowFrom {
				peers = append(peers, peer.Project+"/"+peer.Service)
			}
			policy := network.AppendNewBlock("policy", nil).Body()
			policy.SetAttributeValue("allow_from", stringList(peers))
		}
		block.AppendNewline()
	}

	for _, e := range svc.AllExposes() {
		if err := writeExpose(block, svc, e); err != nil {
			return err
		}
	}

	if svc.Check != nil {
		if err := writeHealthCheck(block, svc); err != nil {
			return err
		}
	}

	if policy := svc.Scaling; policy != nil {
		scalingBlock := block.AppendNewBlock("scaling", nil).Body()
		scalingBlock.SetAttributeValue("min", cty.NumberIntVal(int64(policy.Min)))
		scalingBlock.SetAttributeValue("max", cty.NumberIntVal(int64(policy.Max)))
		for _, m := range policy.Metrics {
			if m.Target != float64(int64(m.Target)) {
				return refuse(fmt.Sprintf("the non-integer scaling target for %q", m.Name))
			}
			metric := scalingBlock.AppendNewBlock("metric", []string{m.Name}).Body()
			metric.SetAttributeValue("target", cty.NumberIntVal(int64(m.Target)))
		}
		setOptionalString(scalingBlock, "cooldown", policy.Cooldown)
		block.AppendNewline()
	}

	if u := svc.Update; u.Strategy != "" || u.MaxParallel != 0 || u.MinHealthy != 0 ||
		u.Auto || u.Interval != 0 || u.Deadline != 0 {
		update := block.AppendNewBlock("update", nil).Body()
		setOptionalString(update, "strategy", u.Strategy)
		if u.MaxParallel != 0 {
			update.SetAttributeValue("max_parallel", cty.NumberIntVal(int64(u.MaxParallel)))
		}
		setOptionalDuration(update, "min_healthy", u.MinHealthy)
		if u.Auto {
			update.SetAttributeValue("auto", cty.True)
		}
		setOptionalDuration(update, "interval", u.Interval)
		setOptionalDuration(update, "deadline", u.Deadline)
		block.AppendNewline()
	}

	if svc.Restart.Attempts != 0 || len(svc.Restart.Backoff) > 0 {
		restart := block.AppendNewBlock("restart", nil).Body()
		if svc.Restart.Attempts != 0 {
			restart.SetAttributeValue("attempts", cty.NumberIntVal(int64(svc.Restart.Attempts)))
		}
		if len(svc.Restart.Backoff) > 0 {
			parts := make([]string, 0, len(svc.Restart.Backoff))
			for _, d := range svc.Restart.Backoff {
				parts = append(parts, d.String())
			}
			restart.SetAttributeValue("backoff", cty.StringVal(strings.Join(parts, ",")))
		}
	}
	return nil
}

// writeResources emits a resources block with only the declared limits. A
// zero limit is unbounded (R11, v1.58) and regenerates as omission: emitting
// `cpu = 0` would be legal but would read as a declaration nobody made.
// Reports whether it wrote anything.
func writeResources(block *hclwrite.Body, svc *reconciler.Desired) bool {
	return writeResourceValues(block, svc.Resources)
}

func writeResourceValues(block *hclwrite.Body, r runtime.Resources) bool {
	cpu := int64(r.CPUMillis) * NominalCoreMHz / 1000
	mem := r.MemoryBytes >> 20
	if cpu <= 0 && mem <= 0 {
		return false
	}
	res := block.AppendNewBlock("resources", nil).Body()
	if cpu > 0 {
		res.SetAttributeValue("cpu", cty.NumberIntVal(cpu))
	}
	if mem > 0 {
		res.SetAttributeValue("memory", cty.NumberIntVal(mem))
	}
	return true
}

func writeTask(block *hclwrite.Body, svc *reconciler.Desired) error {
	task := block.AppendNewBlock("task", []string{"app"}).Body()
	// The declared tag, never PinnedImage: the pin is server-owned bookkeeping
	// the apply path carries (§6.2 R19), and writing it here would freeze the
	// digest into the spec and stop the tag being re-resolved.
	setOptionalString(task, "image", svc.Image)
	if len(svc.Command) > 0 {
		task.SetAttributeValue("command", stringList(svc.Command))
	}
	if len(svc.Capabilities) > 0 {
		task.SetAttributeValue("capabilities", stringList(svc.Capabilities))
	}
	setOptionalString(task, "registry_auth_ref", svc.RegistryAuthRef)
	// Empty means "the node decides" (R33) and must regenerate as an omission,
	// or a spec generated on one node would pin the other node's default.
	setOptionalString(task, "pull_policy", svc.PullPolicy)

	if len(svc.Env) > 0 {
		keys := make([]string, 0, len(svc.Env))
		for k := range svc.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make(map[string]cty.Value, len(keys))
		for _, k := range keys {
			pairs[k] = cty.StringVal(svc.Env[k])
		}
		task.SetAttributeValue("env", cty.ObjectVal(pairs))
	}

	writeResources(task, svc)

	if u := svc.User; u != nil {
		user := task.AppendNewBlock("user", nil).Body()
		user.SetAttributeValue("uid", cty.NumberIntVal(int64(u.UID)))
		user.SetAttributeValue("gid", cty.NumberIntVal(int64(u.GID)))
		if len(u.AdditionalGIDs) > 0 {
			groups := make([]cty.Value, 0, len(u.AdditionalGIDs))
			for _, g := range u.AdditionalGIDs {
				groups = append(groups, cty.NumberIntVal(int64(g)))
			}
			user.SetAttributeValue("groups", cty.ListVal(groups))
		}
	}

	for _, d := range svc.Devices {
		device := task.AppendNewBlock("device", []string{d.Name}).Body()
		device.SetAttributeValue("grant", cty.StringVal(d.Grant))
	}
	for _, s := range svc.Sockets {
		socket := task.AppendNewBlock("socket", []string{s.Name}).Body()
		socket.SetAttributeValue("grant", cty.StringVal(s.Grant))
		socket.SetAttributeValue("mount_path", cty.StringVal(s.MountPath))
		if s.ReadOnly {
			socket.SetAttributeValue("read_only", cty.True)
		}
	}
	block.AppendNewline()
	return nil
}

func writeExpose(block *hclwrite.Body, svc *reconciler.Desired, e *reconciler.Expose) error {
	// The record holds a container port number; the block names a port. A
	// number matching nothing declared cannot round-trip and refuses by name
	// (the v1.38 rule).
	matched := ""
	for _, p := range svc.Ports {
		if p.Container == e.Port {
			matched = p.Name
			break
		}
	}
	if matched == "" {
		return fmt.Errorf("cannot generate a spec for %s/%s: the exposed port %d matches no "+
			"declared container port", svc.Project, svc.Service, e.Port)
	}
	// `port` is emitted exactly when the conventions would pick differently
	// (R16, v1.49): a spec the conventions already serve regenerates
	// byte-identically to its pre-v1.49 output, and everything else says what
	// it means. The convention is EdgePort's, mirrored over the record: a grpc
	// route's port named "grpc" (R28), then the port named "http", then the
	// sole stream port.
	convention := ""
	var streamNames []string
	for _, p := range svc.Ports {
		if p.Protocol != reconciler.PortProtocolUDP {
			streamNames = append(streamNames, p.Name)
		}
	}
	if e.Protocol == jobspec.ExposeProtocolGRPC {
		for _, n := range streamNames {
			if n == jobspec.ExposeProtocolGRPC {
				convention = n
				break
			}
		}
	}
	if convention == "" {
		for _, n := range streamNames {
			if n == jobspec.EdgePortName {
				convention = n
				break
			}
		}
	}
	if convention == "" && len(streamNames) == 1 {
		convention = streamNames[0]
	}
	reSelected := convention == matched

	expose := block.AppendNewBlock("expose", nil).Body()
	if domains := e.Domains; len(domains) > 0 {
		expose.SetAttributeValue("domains", stringList(domains))
	}
	if !reSelected {
		expose.SetAttributeValue("port", cty.StringVal(matched))
	}
	setOptionalString(expose, "protocol", e.Protocol)
	if e.TLSMode != "" || e.TLSName != "" {
		tls := expose.AppendNewBlock("tls", nil).Body()
		setOptionalString(tls, "mode", e.TLSMode)
		setOptionalString(tls, "name", e.TLSName)
	}
	writeMiddleware(expose, e.IPRestriction, e.RateLimit, e.Headers)
	writeAuth(expose, e.Auth)
	block.AppendNewline()
	return nil
}

// writeAuth renders an R27 auth block (v1.40): references only, matching what
// convertAuthPolicy stored.
func writeAuth(body *hclwrite.Body, a *reconciler.AuthPolicy) {
	if a == nil {
		return
	}
	auth := body.AppendNewBlock("auth", nil).Body()
	setOptionalString(auth, "basic_ref", a.BasicRef)
	setOptionalString(auth, "bearer_ref", a.BearerRef)
	if j := a.JWT; j != nil {
		jwt := auth.AppendNewBlock("jwt", nil).Body()
		jwt.SetAttributeValue("algorithm", cty.StringVal(j.Algorithm))
		setOptionalString(jwt, "secret_ref", j.SecretRef)
		setOptionalString(jwt, "public_key_ref", j.PublicKeyRef)
		setOptionalString(jwt, "issuer", j.Issuer)
		setOptionalString(jwt, "audience", j.Audience)
	}
}

func writeHealthCheck(block *hclwrite.Body, svc *reconciler.Desired) error {
	check := svc.Check
	portName := ""
	if check.Port != 0 {
		for _, p := range svc.Ports {
			if p.Container == check.Port {
				portName = p.Name
				break
			}
		}
		if portName == "" {
			return fmt.Errorf("cannot generate a spec for %s/%s: the health check probes port "+
				"%d, which matches no declared container port", svc.Project, svc.Service, check.Port)
		}
	}

	hc := block.AppendNewBlock("health_check", []string{check.Type}).Body()
	hc.SetAttributeValue("type", cty.StringVal(check.Type))
	setOptionalString(hc, "path", check.Path)
	setOptionalString(hc, "port", portName)
	if len(check.Command) > 0 {
		hc.SetAttributeValue("command", stringList(check.Command))
	}
	setOptionalDurationString(hc, "interval", check.Interval)
	setOptionalDurationString(hc, "timeout", check.Timeout)
	if check.Failures != 0 {
		hc.SetAttributeValue("failures", cty.NumberIntVal(int64(check.Failures)))
	}
	block.AppendNewline()
	return nil
}

func writeMiddleware(body *hclwrite.Body, ip *edge.IPRestriction, rl *edge.RateLimit, h *edge.Headers) {
	if ip != nil {
		b := body.AppendNewBlock("ip_restriction", nil).Body()
		if len(ip.Allow) > 0 {
			b.SetAttributeValue("allow", stringList(ip.Allow))
		}
		if len(ip.Deny) > 0 {
			b.SetAttributeValue("deny", stringList(ip.Deny))
		}
	}
	if rl != nil {
		b := body.AppendNewBlock("rate_limit", nil).Body()
		b.SetAttributeValue("requests", cty.NumberIntVal(int64(rl.Requests)))
		b.SetAttributeValue("window", cty.StringVal(rl.Window))
		setOptionalString(b, "per", rl.Per)
		if rl.Burst > 0 {
			b.SetAttributeValue("burst", cty.NumberIntVal(int64(rl.Burst)))
		}
	}
	if h != nil {
		b := body.AppendNewBlock("headers", nil).Body()
		if len(h.RequestSet) > 0 {
			b.SetAttributeValue("request_set", stringMap(h.RequestSet))
		}
		if len(h.RequestRemove) > 0 {
			b.SetAttributeValue("request_remove", stringList(h.RequestRemove))
		}
		if len(h.ResponseSet) > 0 {
			b.SetAttributeValue("response_set", stringMap(h.ResponseSet))
		}
		if len(h.ResponseRemove) > 0 {
			b.SetAttributeValue("response_remove", stringList(h.ResponseRemove))
		}
	}
}

func setOptionalString(body *hclwrite.Body, name, value string) {
	if value != "" {
		body.SetAttributeValue(name, cty.StringVal(value))
	}
}

func setOptionalDuration(body *hclwrite.Body, name string, d time.Duration) {
	if d != 0 {
		body.SetAttributeValue(name, cty.StringVal(d.String()))
	}
}

// setOptionalDurationString is setOptionalDuration for fields whose zero is
// "use the default" rather than "absent".
func setOptionalDurationString(body *hclwrite.Body, name string, d time.Duration) {
	if d > 0 {
		body.SetAttributeValue(name, cty.StringVal(d.String()))
	}
}

func stringList(values []string) cty.Value {
	out := make([]cty.Value, 0, len(values))
	for _, v := range values {
		out = append(out, cty.StringVal(v))
	}
	if len(out) == 0 {
		return cty.ListValEmpty(cty.String)
	}
	return cty.ListVal(out)
}

func stringMap(m map[string]string) cty.Value {
	out := make(map[string]cty.Value, len(m))
	for k, v := range m {
		out[k] = cty.StringVal(v)
	}
	return cty.ObjectVal(out)
}

// writeInits regenerates a service's init blocks, in order (PRD §6.2 R32).
//
// They go before the task because that is the order they run in, and a spec is
// read by people. Everything here round-trips: the fields an init block has are
// exactly the fields the record carries, which is why there is no refusal case
// for one the way there is for volumes.
func writeInits(block *hclwrite.Body, svc *reconciler.Desired) {
	for i := range svc.Init {
		step := svc.Init[i]
		body := block.AppendNewBlock("init", []string{step.Name}).Body()
		setOptionalString(body, "image", step.Image)
		if len(step.Command) > 0 {
			body.SetAttributeValue("command", stringList(step.Command))
		}
		if len(step.Capabilities) > 0 {
			body.SetAttributeValue("capabilities", stringList(step.Capabilities))
		}
		setOptionalString(body, "registry_auth_ref", step.RegistryAuthRef)
		setOptionalString(body, "pull_policy", step.PullPolicy)
		if step.Timeout > 0 {
			body.SetAttributeValue("timeout", cty.StringVal(step.Timeout.String()))
		}
		if len(step.Env) > 0 {
			keys := make([]string, 0, len(step.Env))
			for k := range step.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make(map[string]cty.Value, len(keys))
			for _, k := range keys {
				pairs[k] = cty.StringVal(step.Env[k])
			}
			body.SetAttributeValue("env", cty.ObjectVal(pairs))
		}
		writeResourceValues(body, step.Resources)
		if u := step.User; u != nil {
			user := body.AppendNewBlock("user", nil).Body()
			user.SetAttributeValue("uid", cty.NumberIntVal(int64(u.UID)))
			user.SetAttributeValue("gid", cty.NumberIntVal(int64(u.GID)))
			if len(u.AdditionalGIDs) > 0 {
				groups := make([]cty.Value, 0, len(u.AdditionalGIDs))
				for _, g := range u.AdditionalGIDs {
					groups = append(groups, cty.NumberIntVal(int64(g)))
				}
				user.SetAttributeValue("groups", cty.ListVal(groups))
			}
		}
		block.AppendNewline()
	}
}
