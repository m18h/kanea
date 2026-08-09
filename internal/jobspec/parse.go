package jobspec

import (
	"fmt"
	"os"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// Options configures parsing.
type Options struct {
	// Vars are ${VAR} substitutions from -var-file and built-ins such as
	// GIT_SHA_SHORT and KANEA_PROJECT (R2).
	Vars map[string]string
	// BaseDomain is the server's `base_domain` (§15.1). An expose block that
	// omits `domains` gets <service>.<project>.<base_domain> (§7.2).
	//
	// Optional: a spec is parseable without it — `kanea plan` run against a file
	// alone has no server config to read — and the auto-FQDN is then left for
	// the agent to fill in. What it costs is the R16 collision check between a
	// generated domain and an explicitly declared one, which is only possible
	// when the generated name is known.
	BaseDomain string
}

// ---- HCL schema structs -------------------------------------------------
//
// These mirror PRD §6.1 one-to-one and exist only to carry hcl tags; the
// exported types in types.go are what the rest of Kanea sees. Env is captured
// as an unevaluated expression on purpose: ${service.<name>.host} cannot be
// evaluated until every service's ports are known (R9).

type hclRoot struct {
	SpecVersion *int         `hcl:"spec_version,optional"`
	Projects    []hclProject `hcl:"project,block"`
	Services    []hclService `hcl:"service,block"`
	Storages    []hclStorage `hcl:"storage,block"`
	Remain      hcl.Body     `hcl:",remain"`
}

type hclStorage struct {
	Name     string    `hcl:"name,label"`
	Type     string    `hcl:"type"`
	Bucket   string    `hcl:"bucket,optional"`
	Endpoint string    `hcl:"endpoint,optional"`
	AuthRef  string    `hcl:"auth_ref,optional"`
	Mode     string    `hcl:"mode,optional"`
	Server   string    `hcl:"server,optional"`
	Export   string    `hcl:"export,optional"`
	Share    string    `hcl:"share,optional"`
	Options  string    `hcl:"options,optional"`
	Path     string    `hcl:"path,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclProject struct {
	Name          string            `hcl:"name,label"`
	DefRange      hcl.Range         `hcl:",def_range"`
	Description   string            `hcl:"description,optional"`
	Git           *hclGit           `hcl:"git,block"`
	Notifications *hclNotifications `hcl:"notifications,block"`
}

type hclGit struct {
	URL              string `hcl:"url"`
	Branch           string `hcl:"branch,optional"`
	Path             string `hcl:"path,optional"`
	AuthRef          string `hcl:"auth_ref,optional"`
	WebhookSecretRef string `hcl:"webhook_secret_ref,optional"`
	PollInterval     string `hcl:"poll_interval,optional"`
	RequireApproval  bool   `hcl:"require_approval,optional"`
}

type hclNotifications struct {
	Telegram *hclTelegram `hcl:"telegram,block"`
	Webhook  *hclWebhook  `hcl:"webhook,block"`
	Slack    *hclSlack    `hcl:"slack,block"`
	Ntfy     *hclNtfy     `hcl:"ntfy,block"`
	SMTP     *hclSMTP     `hcl:"smtp,block"`
	On       []string     `hcl:"on,optional"`
	// Severity is a floor: nothing below it is sent whatever `on` says.
	Severity string    `hcl:"severity,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclTelegram struct {
	ChatID string `hcl:"chat_id"`
	// TokenRef names the bot token. §11 always said it comes from the secrets
	// store; this is the field that says which secret.
	TokenRef string `hcl:"token_ref"`
}

type hclWebhook struct {
	URL string `hcl:"url"`
	// SecretRef signs the payload. Optional — a receiver that authenticates by
	// URL alone is legitimate.
	SecretRef string `hcl:"secret_ref,optional"`
}

type hclSlack struct {
	// URLRef, never a url. An incoming-webhook URL is a credential in path
	// form: anyone holding it can post as the app.
	URLRef string `hcl:"url_ref"`
}

type hclNtfy struct {
	URL      string `hcl:"url"`
	TokenRef string `hcl:"token_ref,optional"`
}

type hclSMTP struct {
	Host        string   `hcl:"host"`
	Port        string   `hcl:"port,optional"`
	From        string   `hcl:"from"`
	To          []string `hcl:"to"`
	Username    string   `hcl:"username,optional"`
	PasswordRef string   `hcl:"password_ref,optional"`
}

type hclService struct {
	Name         string           `hcl:"name,label"`
	Project      string           `hcl:"project,optional"`
	Description  string           `hcl:"description,optional"`
	Count        *int             `hcl:"count,optional"`
	DependsOn    []string         `hcl:"depends_on,optional"`
	Build        *hclBuild        `hcl:"build,block"`
	Tasks        []hclTask        `hcl:"task,block"`
	Network      *hclNetwork      `hcl:"network,block"`
	Expose       *hclExpose       `hcl:"expose,block"`
	HealthChecks []hclHealthCheck `hcl:"health_check,block"`
	Volumes      []hclVolume      `hcl:"volume,block"`
	Scaling      *hclScaling      `hcl:"scaling,block"`
	Update       *hclUpdate       `hcl:"update,block"`
	Restart      *hclRestart      `hcl:"restart,block"`
	DefRange     hcl.Range        `hcl:",def_range"`
}

type hclBuild struct {
	Context    string `hcl:"context"`
	Dockerfile string `hcl:"dockerfile,optional"`
	Target     string `hcl:"target,optional"`
	Tag        string `hcl:"tag,optional"`
	CacheRepo  string `hcl:"cache_repo,optional"`
	// RegistryAuthRef is the push credential. §10.2 requires the registry
	// credential to come from the secrets store as a materialised
	// config.json; this is the reference that names it.
	RegistryAuthRef string `hcl:"registry_auth_ref,optional"`
}

type hclTask struct {
	Name         string         `hcl:"name,label"`
	Image        string         `hcl:"image,optional"`
	Command      []string       `hcl:"command,optional"`
	Capabilities []string       `hcl:"capabilities,optional"`
	Env          hcl.Expression `hcl:"env,optional"`
	Resources    *hclResources  `hcl:"resources,block"`
	// RegistryAuthRef is the *pull* credential (R19). Distinct from the build
	// block's field of the same name, which pushes: a project may well read a
	// public base image and push to a private registry, or the reverse.
	RegistryAuthRef string      `hcl:"registry_auth_ref,optional"`
	Devices         []hclDevice `hcl:"device,block"`
	Sockets         []hclSocket `hcl:"socket,block"`
	DefRange        hcl.Range   `hcl:",def_range"`
}

type hclResources struct {
	CPU    *int `hcl:"cpu,optional"`
	Memory *int `hcl:"memory,optional"`
}

// hclDevice and hclSocket name a grant, never a path (R17, R18). There is
// deliberately no field to write a device node or a socket path into: whether
// a path may be given to a container is the node's decision, and a spec that
// could name its own would be making it.
type hclDevice struct {
	Name     string    `hcl:"name,label"`
	Grant    string    `hcl:"grant"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclSocket struct {
	Name      string    `hcl:"name,label"`
	Grant     string    `hcl:"grant"`
	MountPath string    `hcl:"mount_path"`
	ReadOnly  bool      `hcl:"read_only,optional"`
	DefRange  hcl.Range `hcl:",def_range"`
}

type hclNetwork struct {
	Ports  []hclPort         `hcl:"port,block"`
	Policy *hclNetworkPolicy `hcl:"policy,block"`
}

type hclNetworkPolicy struct {
	AllowFrom []string  `hcl:"allow_from,optional"`
	DefRange  hcl.Range `hcl:",def_range"`
}

type hclPort struct {
	Name      string    `hcl:"name,label"`
	Container int       `hcl:"container"`
	DefRange  hcl.Range `hcl:",def_range"`
}

type hclExpose struct {
	Domains       []string          `hcl:"domains,optional"`
	TLS           *hclTLS           `hcl:"tls,block"`
	IPRestriction *hclIPRestriction `hcl:"ip_restriction,block"`
	RateLimit     *hclRateLimit     `hcl:"rate_limit,block"`
	Headers       *hclHeaders       `hcl:"headers,block"`
	DefRange      hcl.Range         `hcl:",def_range"`
}

type hclTLS struct {
	LetsEncrypt bool `hcl:"letsencrypt,optional"`
}

type hclIPRestriction struct {
	Allow    []string  `hcl:"allow,optional"`
	Deny     []string  `hcl:"deny,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclRateLimit struct {
	Requests int       `hcl:"requests"`
	Window   string    `hcl:"window"`
	Per      string    `hcl:"per,optional"`
	Burst    int       `hcl:"burst,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclHeaders struct {
	RequestSet     map[string]string `hcl:"request_set,optional"`
	RequestRemove  []string          `hcl:"request_remove,optional"`
	ResponseSet    map[string]string `hcl:"response_set,optional"`
	ResponseRemove []string          `hcl:"response_remove,optional"`
	DefRange       hcl.Range         `hcl:",def_range"`
}

type hclHealthCheck struct {
	Name     string    `hcl:"name,label"`
	Type     string    `hcl:"type,optional"`
	Path     string    `hcl:"path,optional"`
	Port     string    `hcl:"port,optional"`
	Command  []string  `hcl:"command,optional"`
	Interval string    `hcl:"interval,optional"`
	Timeout  string    `hcl:"timeout,optional"`
	Failures int       `hcl:"failures,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclVolume struct {
	Name      string    `hcl:"name,label"`
	Storage   string    `hcl:"storage"`
	MountPath string    `hcl:"mount_path"`
	ReadOnly  bool      `hcl:"read_only,optional"`
	DefRange  hcl.Range `hcl:",def_range"`
}

type hclScaling struct {
	Min      int         `hcl:"min,optional"`
	Max      int         `hcl:"max,optional"`
	Metrics  []hclMetric `hcl:"metric,block"`
	Cooldown string      `hcl:"cooldown,optional"`
}

type hclMetric struct {
	Name   string `hcl:"name,label"`
	Target int    `hcl:"target"`
}

type hclUpdate struct {
	Strategy    string `hcl:"strategy,optional"`
	MaxParallel int    `hcl:"max_parallel,optional"`
	MinHealthy  string `hcl:"min_healthy,optional"`
	// Auto follows the tag task.image declares (R19). Off unless written.
	Auto     bool   `hcl:"auto,optional"`
	Interval string `hcl:"interval,optional"`
	Deadline string `hcl:"deadline,optional"`
}

type hclRestart struct {
	Attempts int    `hcl:"attempts,optional"`
	Backoff  string `hcl:"backoff,optional"`
}

// ---- parsing ------------------------------------------------------------

// ParseFiles reads and parses the given .hcl files as one applied set, then
// validates them together (R9: file order is irrelevant).
//
// Diagnostics carry file/line/column. Use FormatDiagnostics to render them.
func ParseFiles(opts Options, paths ...string) (*Spec, hcl.Diagnostics) {
	parser := hclparse.NewParser()
	var diags hcl.Diagnostics
	files := make([]*hcl.File, 0, len(paths))

	for _, path := range paths {
		src, err := os.ReadFile(path) // #nosec G304 — operator-supplied spec path
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Cannot read job spec",
				Detail:   fmt.Sprintf("Reading %s: %s.", path, err),
			})
			continue
		}
		file, fileDiags := parser.ParseHCL(src, path)
		diags = append(diags, fileDiags...)
		if file != nil {
			files = append(files, file)
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}
	return parseFiles(opts, files, diags)
}

// ParseSource parses one in-memory spec. filename is used in diagnostics.
func ParseSource(opts Options, filename string, src []byte) (*Spec, hcl.Diagnostics) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}
	return parseFiles(opts, []*hcl.File{file}, diags)
}

func parseFiles(opts Options, files []*hcl.File, diags hcl.Diagnostics) (*Spec, hcl.Diagnostics) {
	if len(files) == 0 {
		return nil, append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "No job spec provided",
			Detail:   "At least one .hcl file is required.",
		})
	}

	// Pass 1 — structure. Only variables are in scope, so a ${service.*}
	// reference stays an unevaluated expression (Env is typed hcl.Expression).
	var root hclRoot
	body := hcl.MergeFiles(files)
	structDiags := gohcl.DecodeBody(body, varContext(opts.Vars), &root)
	diags = append(diags, structDiags...)
	if diags.HasErrors() {
		return nil, diags
	}

	spec := &Spec{BaseDomain: opts.BaseDomain}
	if root.SpecVersion != nil {
		spec.SpecVersion = *root.SpecVersion
	}
	for i := range root.Projects {
		spec.Projects = append(spec.Projects, convertProject(&root.Projects[i]))
	}
	for i := range root.Storages {
		st := &root.Storages[i]
		spec.Storages = append(spec.Storages, &Storage{
			Name: st.Name, Type: st.Type, Bucket: st.Bucket, Endpoint: st.Endpoint,
			AuthRef: st.AuthRef, Mode: st.Mode, Server: st.Server, Export: st.Export,
			Share: st.Share, Options: st.Options, Path: st.Path, DefRange: st.DefRange,
		})
	}
	for i := range root.Services {
		svc, svcDiags := convertService(&root.Services[i])
		diags = append(diags, svcDiags...)
		if svc != nil {
			spec.Services = append(spec.Services, svc)
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}

	// Pass 2 — evaluate env with a context that knows every service's DNS name
	// and ports, and record the reference edges while doing it (R9, R10).
	diags = append(diags, resolveEnv(spec, &root, opts)...)
	if diags.HasErrors() {
		return nil, diags
	}

	diags = append(diags, Validate(spec)...)
	if diags.HasErrors() {
		return nil, diags
	}
	return spec, diags
}

// varContext exposes -var-file values and built-ins as ${NAME} variables (R2).
func varContext(vars map[string]string) *hcl.EvalContext {
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	// The build-time built-ins resolve to themselves when nobody supplied them.
	//
	// R2 lists GIT_SHA_SHORT among the built-in variables, but the value only
	// exists once a commit has been checked out — which is the pipeline runner,
	// long after the file is parsed. Without this, the PRD's own §6.1 example
	// (`tag = "${GIT_SHA_SHORT}"`) fails to parse everywhere: `kanea plan`,
	// `kanea run` and every GitOps sync. Passing the reference through unchanged
	// leaves it for gitops.ExpandTag, and a caller that *does* know the value —
	// `-var-file`, or a sync that has the checkout — still overrides it here.
	for _, name := range BuildTimeVars {
		ctx.Variables[name] = cty.StringVal("${" + name + "}")
	}
	for k, v := range vars {
		ctx.Variables[k] = cty.StringVal(v)
	}
	return ctx
}

// BuildTimeVars are the built-ins whose value is only known once a commit is
// checked out (R2). They survive parsing as literal references.
var BuildTimeVars = []string{"GIT_SHA_SHORT", "GIT_SHA", "GIT_BRANCH"}

func convertProject(p *hclProject) *Project {
	out := &Project{Name: p.Name, Description: p.Description, DefRange: p.DefRange}
	if p.Git != nil {
		out.Git = &Git{
			URL: p.Git.URL, Branch: p.Git.Branch, Path: p.Git.Path, AuthRef: p.Git.AuthRef,
			WebhookSecretRef: p.Git.WebhookSecretRef,
			PollInterval:     p.Git.PollInterval,
			RequireApproval:  p.Git.RequireApproval,
		}
	}
	if n := p.Notifications; n != nil {
		out.Notifications = &Notifications{
			On: n.On, Severity: n.Severity, DefRange: n.DefRange,
		}
		if t := n.Telegram; t != nil {
			out.Notifications.Telegram = &TelegramChannel{ChatID: t.ChatID, TokenRef: t.TokenRef}
		}
		if w := n.Webhook; w != nil {
			out.Notifications.Webhook = &WebhookChannel{URL: w.URL, SecretRef: w.SecretRef}
		}
		if sl := n.Slack; sl != nil {
			out.Notifications.Slack = &SlackChannel{URLRef: sl.URLRef}
		}
		if nt := n.Ntfy; nt != nil {
			out.Notifications.Ntfy = &NtfyChannel{URL: nt.URL, TokenRef: nt.TokenRef}
		}
		if sm := n.SMTP; sm != nil {
			out.Notifications.SMTP = &SMTPChannel{
				Host: sm.Host, Port: sm.Port, From: sm.From, To: sm.To,
				Username: sm.Username, PasswordRef: sm.PasswordRef,
			}
		}
	}
	return out
}

func convertService(s *hclService) (*Service, hcl.Diagnostics) {
	var diags hcl.Diagnostics

	out := &Service{
		DefRange:    s.DefRange,
		Name:        s.Name,
		Project:     s.Project,
		Description: s.Description,
		Count:       DefaultCount,
		DependsOn:   s.DependsOn,
	}
	if s.Count != nil {
		out.Count = *s.Count
	}

	// v1 allows exactly one task per service: the alloc model is 1:1 with a
	// container (PRD §4.3), and a silent "first task wins" would be worse.
	switch len(s.Tasks) {
	case 0:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Service has no task",
			Detail:   fmt.Sprintf("Service %q must declare exactly one task block.", s.Name),
			Subject:  s.DefRange.Ptr(),
		})
	case 1:
		out.Task = convertTask(&s.Tasks[0])
	default:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Multiple tasks in one service",
			Detail: fmt.Sprintf("Service %q declares %d task blocks; v1 supports exactly one. "+
				"Split them into separate services.", s.Name, len(s.Tasks)),
			Subject: s.Tasks[1].DefRange.Ptr(),
		})
	}

	if s.Build != nil {
		out.Build = &Build{
			Context:         s.Build.Context,
			Dockerfile:      s.Build.Dockerfile,
			Target:          s.Build.Target,
			Tag:             s.Build.Tag,
			CacheRepo:       s.Build.CacheRepo,
			RegistryAuthRef: s.Build.RegistryAuthRef,
			DefRange:        s.DefRange,
		}
	}
	if s.Network != nil {
		out.Network = &Network{}
		for i := range s.Network.Ports {
			p := &s.Network.Ports[i]
			out.Network.Ports = append(out.Network.Ports, &Port{Name: p.Name, Container: p.Container, DefRange: p.DefRange})
		}
		if s.Network.Policy != nil {
			out.Network.Policy = &NetworkPolicy{
				AllowFrom: s.Network.Policy.AllowFrom,
				DefRange:  s.Network.Policy.DefRange,
			}
		}
	}
	if s.Expose != nil {
		out.Expose = convertExpose(s.Expose)
	}
	for i := range s.HealthChecks {
		h := &s.HealthChecks[i]
		out.HealthChecks = append(out.HealthChecks, &HealthCheck{
			Name: h.Name, Type: h.Type, Path: h.Path, Port: h.Port, Command: h.Command,
			Interval: h.Interval, Timeout: h.Timeout, Failures: h.Failures, DefRange: h.DefRange,
		})
	}
	for i := range s.Volumes {
		v := &s.Volumes[i]
		out.Volumes = append(out.Volumes, &Volume{
			Name: v.Name, Storage: v.Storage, MountPath: v.MountPath, ReadOnly: v.ReadOnly,
			DefRange: v.DefRange,
		})
	}
	if s.Scaling != nil {
		out.Scaling = &Scaling{Min: s.Scaling.Min, Max: s.Scaling.Max, Cooldown: s.Scaling.Cooldown}
		for i := range s.Scaling.Metrics {
			m := &s.Scaling.Metrics[i]
			out.Scaling.Metrics = append(out.Scaling.Metrics, &ScalingMetric{Name: m.Name, Target: m.Target})
		}
	}
	if s.Update != nil {
		out.Update = &Update{
			Strategy: s.Update.Strategy, MaxParallel: s.Update.MaxParallel, MinHealthy: s.Update.MinHealthy,
			Auto: s.Update.Auto, Interval: s.Update.Interval, Deadline: s.Update.Deadline,
		}
	}
	if s.Restart != nil {
		out.Restart = &Restart{Attempts: s.Restart.Attempts, Backoff: s.Restart.Backoff}
	}
	return out, diags
}

func convertTask(t *hclTask) *Task {
	out := &Task{
		DefRange:        t.DefRange,
		Name:            t.Name,
		Image:           t.Image,
		Command:         t.Command,
		Capabilities:    t.Capabilities,
		RegistryAuthRef: t.RegistryAuthRef,
		Env:             map[string]string{},
		Resources:       Resources{CPU: DefaultCPU, Memory: DefaultMemory},
	}
	if t.Resources != nil {
		out.ResourcesDeclared = true
		if t.Resources.CPU != nil {
			out.Resources.CPU = *t.Resources.CPU
		}
		if t.Resources.Memory != nil {
			out.Resources.Memory = *t.Resources.Memory
		}
	}
	for i := range t.Devices {
		d := &t.Devices[i]
		out.Devices = append(out.Devices, &Device{
			Name: d.Name, Grant: d.Grant, DefRange: d.DefRange,
		})
	}
	for i := range t.Sockets {
		s := &t.Sockets[i]
		out.Sockets = append(out.Sockets, &Socket{
			Name: s.Name, Grant: s.Grant, MountPath: s.MountPath,
			ReadOnly: s.ReadOnly, DefRange: s.DefRange,
		})
	}
	return out
}

func convertExpose(e *hclExpose) *Expose {
	out := &Expose{Domains: e.Domains, DefRange: e.DefRange}
	if e.TLS != nil {
	}
	if e.IPRestriction != nil {
		out.IPRestriction = &IPRestriction{
			Allow: e.IPRestriction.Allow, Deny: e.IPRestriction.Deny,
			DefRange: e.IPRestriction.DefRange,
		}
	}
	if e.RateLimit != nil {
		out.RateLimit = &RateLimit{
			Requests: e.RateLimit.Requests, Window: e.RateLimit.Window,
			Per: e.RateLimit.Per, Burst: e.RateLimit.Burst,
			DefRange: e.RateLimit.DefRange,
		}
	}
	if e.Headers != nil {
		out.Headers = &Headers{
			RequestSet: e.Headers.RequestSet, RequestRemove: e.Headers.RequestRemove,
			ResponseSet: e.Headers.ResponseSet, ResponseRemove: e.Headers.ResponseRemove,
			DefRange: e.Headers.DefRange,
		}
	}
	return out
}

// sortUnique returns the sorted, deduplicated input.
func sortUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ParseContents parses a set of in-memory job specs as one applied set.
//
// It exists for GitOps (§10.1): a sync reads the specs out of the repository
// object database and never writes them to disk, so there is no path to hand
// ParseFiles. Keeping them in memory is the point — a checkout materialised
// under a temp directory is one more place a spec, and whatever a spec quotes,
// can be read from.
//
// Keys are the paths the content came from and are used in diagnostics, so an
// error still points at `.kanea/web.hcl` line 12.
func ParseContents(opts Options, files map[string][]byte) (*Spec, hcl.Diagnostics) {
	parser := hclparse.NewParser()
	var diags hcl.Diagnostics

	// Sorted, so a diagnostic set from two files comes out in the same order
	// every time and a repeated sync does not look like a changing error.
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	parsed := make([]*hcl.File, 0, len(paths))
	for _, path := range paths {
		file, fileDiags := parser.ParseHCL(files[path], path)
		diags = append(diags, fileDiags...)
		if file != nil {
			parsed = append(parsed, file)
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}
	return parseFiles(opts, parsed, diags)
}
