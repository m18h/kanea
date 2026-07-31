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
	// BaseDomain is used when an expose block omits `domains`. Optional here:
	// the default is applied by the edge, not the parser.
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
	Remain      hcl.Body     `hcl:",remain"`
}

type hclProject struct {
	Name          string            `hcl:"name,label"`
	DefRange      hcl.Range         `hcl:",def_range"`
	Description   string            `hcl:"description,optional"`
	Git           *hclGit           `hcl:"git,block"`
	Notifications *hclNotifications `hcl:"notifications,block"`
}

type hclGit struct {
	URL     string `hcl:"url"`
	Branch  string `hcl:"branch,optional"`
	Path    string `hcl:"path,optional"`
	AuthRef string `hcl:"auth_ref,optional"`
}

type hclNotifications struct {
	Telegram *hclTelegram `hcl:"telegram,block"`
	Webhook  *hclWebhook  `hcl:"webhook,block"`
	On       []string     `hcl:"on,optional"`
}

type hclTelegram struct {
	ChatID string `hcl:"chat_id"`
}

type hclWebhook struct {
	URL string `hcl:"url"`
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
}

type hclTask struct {
	Name         string         `hcl:"name,label"`
	Image        string         `hcl:"image,optional"`
	Command      []string       `hcl:"command,optional"`
	Capabilities []string       `hcl:"capabilities,optional"`
	Env          hcl.Expression `hcl:"env,optional"`
	Resources    *hclResources  `hcl:"resources,block"`
	DefRange     hcl.Range      `hcl:",def_range"`
}

type hclResources struct {
	CPU    *int `hcl:"cpu,optional"`
	Memory *int `hcl:"memory,optional"`
}

type hclNetwork struct {
	Ports []hclPort `hcl:"port,block"`
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
}

type hclTLS struct {
	LetsEncrypt bool `hcl:"letsencrypt,optional"`
}

type hclIPRestriction struct {
	Allow []string `hcl:"allow,optional"`
	Deny  []string `hcl:"deny,optional"`
}

type hclRateLimit struct {
	Requests int    `hcl:"requests"`
	Window   string `hcl:"window"`
	Per      string `hcl:"per,optional"`
	Burst    int    `hcl:"burst,optional"`
}

type hclHeaders struct {
	RequestSet     map[string]string `hcl:"request_set,optional"`
	RequestRemove  []string          `hcl:"request_remove,optional"`
	ResponseSet    map[string]string `hcl:"response_set,optional"`
	ResponseRemove []string          `hcl:"response_remove,optional"`
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

	spec := &Spec{}
	if root.SpecVersion != nil {
		spec.SpecVersion = *root.SpecVersion
	}
	for i := range root.Projects {
		spec.Projects = append(spec.Projects, convertProject(&root.Projects[i]))
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
	for k, v := range vars {
		ctx.Variables[k] = cty.StringVal(v)
	}
	return ctx
}

func convertProject(p *hclProject) *Project {
	out := &Project{Name: p.Name, Description: p.Description, DefRange: p.DefRange}
	if p.Git != nil {
		out.Git = &Git{URL: p.Git.URL, Branch: p.Git.Branch, Path: p.Git.Path, AuthRef: p.Git.AuthRef}
	}
	if p.Notifications != nil {
		out.Notifications = &Notifications{On: p.Notifications.On}
		if t := p.Notifications.Telegram; t != nil {
			out.Notifications.Telegram = &TelegramChannel{ChatID: t.ChatID}
		}
		if w := p.Notifications.Webhook; w != nil {
			out.Notifications.Webhook = &WebhookChannel{URL: w.URL}
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
			Context:    s.Build.Context,
			Dockerfile: s.Build.Dockerfile,
			Target:     s.Build.Target,
			Tag:        s.Build.Tag,
			CacheRepo:  s.Build.CacheRepo,
		}
	}
	if s.Network != nil {
		out.Network = &Network{}
		for i := range s.Network.Ports {
			p := &s.Network.Ports[i]
			out.Network.Ports = append(out.Network.Ports, &Port{Name: p.Name, Container: p.Container, DefRange: p.DefRange})
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
		}
	}
	if s.Restart != nil {
		out.Restart = &Restart{Attempts: s.Restart.Attempts, Backoff: s.Restart.Backoff}
	}
	return out, diags
}

func convertTask(t *hclTask) *Task {
	out := &Task{
		DefRange:     t.DefRange,
		Name:         t.Name,
		Image:        t.Image,
		Command:      t.Command,
		Capabilities: t.Capabilities,
		Env:          map[string]string{},
		Resources:    Resources{CPU: DefaultCPU, Memory: DefaultMemory},
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
	return out
}

func convertExpose(e *hclExpose) *Expose {
	out := &Expose{Domains: e.Domains}
	if e.TLS != nil {
		out.TLS = &TLS{LetsEncrypt: e.TLS.LetsEncrypt}
	}
	if e.IPRestriction != nil {
		out.IPRestriction = &IPRestriction{Allow: e.IPRestriction.Allow, Deny: e.IPRestriction.Deny}
	}
	if e.RateLimit != nil {
		out.RateLimit = &RateLimit{
			Requests: e.RateLimit.Requests, Window: e.RateLimit.Window,
			Per: e.RateLimit.Per, Burst: e.RateLimit.Burst,
		}
	}
	if e.Headers != nil {
		out.Headers = &Headers{
			RequestSet: e.Headers.RequestSet, RequestRemove: e.Headers.RequestRemove,
			ResponseSet: e.Headers.ResponseSet, ResponseRemove: e.Headers.ResponseRemove,
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
