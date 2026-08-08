package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/kanea-dev/kanea/internal/gitops"
	"github.com/kanea-dev/kanea/internal/reconciler"
)

// The tool set (PRD §16.3).
//
// Every tool is a translation: arguments in, one or more requests against the
// API, a rendered answer out. None of them reach past the Backend, which is
// what makes the tier system honest — a tool cannot be more privileged than the
// credential its caller presented, because the credential is the only thing it
// has.

// API paths the tools call. Named here rather than imported from internal/api,
// so that this package depends on the API's *wire* surface and not on its
// implementation — the stdio transport talks to a daemon that may be a
// different build.
const (
	pathSession   = "/v1/auth/session"
	pathHealth    = "/v1/healthz"
	pathServices  = "/v1/services"
	pathAllocs    = "/v1/allocs"
	pathLogs      = "/v1/logs"
	pathEvents    = "/v1/events"
	pathStats     = "/v1/stats"
	pathProjects  = "/v1/projects"
	pathPipelines = "/v1/pipelines"
	pathAudit     = "/v1/audit"
	pathBackups   = "/v1/backups"
)

// tier is how much authority a tool needs (§16.3's three groups).
type tier int

const (
	// tierRead is the viewer role: it observes and changes nothing.
	tierRead tier = iota
	// tierMutate is the admin role: it changes the platform's state.
	tierMutate
	// tierDestructive is admin plus an explicit confirm argument. The
	// distinction is not about authorization — an admin may do all of it — but
	// about intent: these are the ones with no undo.
	tierDestructive
)

// tool is one entry in the registry.
type tool struct {
	name        string
	tier        tier
	description string
	schema      inputSchema
	// destructive marks the annotation. It tracks tier, and is separate only
	// because MCP's annotation vocabulary is advisory and the tier is not.
	run func(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error)
}

func (t *tool) describe() toolDescriptor {
	return toolDescriptor{
		Name: t.name, Description: t.description, InputSchema: t.schema,
		Annotations: &hints{
			ReadOnlyHint:    t.tier == tierRead,
			DestructiveHint: t.tier == tierDestructive,
			IdempotentHint:  t.tier == tierRead,
			// The tools reach a daemon whose state changes underneath them, so
			// the same call can legitimately return different answers.
			OpenWorldHint: true,
		},
	}
}

// arguments is a tool call's arguments, read defensively: a model produces
// these, and it produces numbers as strings, strings as numbers and absent
// fields as null often enough that strict decoding would fail calls that were
// perfectly clear about what they wanted.
type arguments map[string]any

func (a arguments) text(key string) string {
	switch v := a[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return ""
	}
}

func (a arguments) number(key string, fallback int) int {
	switch v := a[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

func (a arguments) boolean(key string) bool {
	switch v := a[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	default:
		return false
	}
}

// has reports whether an argument was supplied at all, which is different from
// it being empty — scale_service with count 0 is a real request.
func (a arguments) has(key string) bool {
	v, ok := a[key]
	return ok && v != nil
}

// require checks the arguments a tool cannot work without, so a missing one is
// a clear sentence rather than a request for "" that 404s.
func (a arguments) require(names ...string) error {
	var missing []string
	for _, name := range names {
		if a.text(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("missing required argument(s): %s", strings.Join(missing, ", "))
}

// Result caps. §16.3 fixes the log tail at 500 lines by default; the byte cap
// is what stops a service with very long lines from spending the same budget in
// one of them.
const (
	defaultLogTail = 200
	maxLogTail     = 500
	maxResultBytes = 64 << 10
)

// common schema fragments, so thirteen tools describe a project the same way.
var (
	projectProp = property{Type: "string", Description: "Project name."}
	serviceProp = property{Type: "string", Description: "Service name within the project."}
)

// registry is the whole tool set. It is a function rather than a package
// variable so that the list is built fresh per server and cannot be mutated by
// anything holding a reference to it.
func registry() []*tool {
	return []*tool{
		// ---- read (viewer) ----
		{
			name: "list_projects", tier: tierRead,
			description: "List projects with their service and alloc counts, git source and " +
				"configured notification channels. Start here when you do not know what is deployed.",
			schema: object(nil),
			run:    runListProjects,
		},
		{
			name: "get_project", tier: tierRead,
			description: "Describe one project: counts, git source, notification channels.",
			schema:      object(map[string]property{"project": projectProp}, "project"),
			run:         runGetProject,
		},
		{
			name: "list_services", tier: tierRead,
			description: "List declared services with their image, replica count and resource limits. " +
				"Optionally filtered to one project.",
			schema: object(map[string]property{"project": projectProp}),
			run:    runListServices,
		},
		{
			name: "get_service", tier: tierRead,
			description: "Show one service's full declared state: image, count, environment " +
				"variable names, resources, ports, health check, scaling policy and ingress. " +
				"Environment values are shown; secrets are references, never values.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
			}, "project", "service"),
			run: runGetService,
		},
		{
			name: "list_allocs", tier: tierRead,
			description: "List allocation (container) records with state, restarts and health. " +
				"This is what is actually running, as opposed to what is declared.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
			}),
			run: runListAllocs,
		},
		{
			name: "get_logs", tier: tierRead,
			description: "Read the tail of a service's container logs. Not a stream: it returns " +
				"the last N lines and comes back. Use it to diagnose a crash or a failing health check.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
				"alloc": {Type: "string", Description: "Restrict to one alloc id."},
				"tail": {Type: "integer", Default: defaultLogTail,
					Description: fmt.Sprintf("Lines to return (max %d).", maxLogTail)},
			}, "project", "service"),
			run: runGetLogs,
		},
		{
			name: "get_events", tier: tierRead,
			description: "Read the platform event feed newest-first: deploys, crashes, health " +
				"transitions, scaling decisions, certificate issuance, builds.",
			schema: object(map[string]property{
				"project": projectProp,
				"limit":   {Type: "integer", Default: 50, Description: "Events to return."},
			}),
			run: runGetEvents,
		},
		{
			name: "get_node_stats", tier: tierRead,
			description: "Summarise the node: version, how much is declared, how much is " +
				"running, how much is failing, the machine's own CPU, memory and load, the " +
				"metrics pipeline's health and whether the circuit breaker is open. A missing " +
				"value means no reading, which is not the same as zero.",
			schema: object(nil),
			run:    runNodeStats,
		},
		{
			name: "get_service_stats", tier: tierRead,
			description: "Current CPU, memory, request rate and p95 latency for a service and its " +
				"allocs. A missing value means no recent data, which is not the same as zero.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
			}, "project", "service"),
			run: runServiceStats,
		},
		{
			name: "list_pipelines", tier: tierRead,
			description: "List build and deploy runs newest-first, with state, commit and duration.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
				"limit": {Type: "integer", Default: 20, Description: "Runs to return."},
			}),
			run: runListPipelines,
		},
		{
			name: "list_storage", tier: tierRead,
			description: "List the volumes services declare, with their backing storage type and " +
				"which services mount them.",
			schema: object(map[string]property{"project": projectProp}),
			run:    runListStorage,
		},
		{
			name: "list_backups", tier: tierRead,
			description: "List state archives newest-first, with when each was taken, the " +
				"index it covers and what it holds. Also reports whether replication is " +
				"actually working, which is the number that matters before an incident.",
			schema: object(nil),
			run:    runListBackups,
		},
		{
			name: "get_audit", tier: tierRead,
			description: "Read the audit log: who did what, when, from where, and whether it was " +
				"allowed. Requires the admin role — the daemon enforces that.",
			schema: object(map[string]property{
				"actor":  {Type: "string", Description: "Filter by the acting subject."},
				"action": {Type: "string", Description: "Filter by action, e.g. service.apply."},
				"limit":  {Type: "integer", Default: 50, Description: "Entries to return."},
			}),
			run: runGetAudit,
		},

		// ---- mutate (admin) ----
		{
			name: "plan_spec", tier: tierMutate,
			description: "Parse an HCL job spec and report what applying it would change. " +
				"Changes nothing. Always prefer this before apply_spec.",
			schema: object(map[string]property{
				"spec": {Type: "string", Description: "The job spec, as HCL source text."},
			}, "spec"),
			run: runPlanSpec,
		},
		{
			name: "apply_spec", tier: tierMutate,
			description: "Apply an HCL job spec. Services it names are created or updated; " +
				"services it does not name are left alone. A changed image or environment " +
				"rolls the service through its update policy.",
			schema: object(map[string]property{
				"spec": {Type: "string", Description: "The job spec, as HCL source text."},
			}, "spec"),
			run: runApplySpec,
		},
		{
			name: "scale_service", tier: tierMutate,
			description: "Set a service's replica count. The reconciler converges; this returns " +
				"immediately.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
				"count": {Type: "integer", Description: "Desired replica count, zero or more."},
			}, "project", "service", "count"),
			run: runScale,
		},
		{
			name: "restart_service", tier: tierMutate,
			description: "Roll a service's containers without changing its spec. Honours the " +
				"service's update policy, so replicas are replaced a few at a time.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
			}, "project", "service"),
			run: runRestart,
		},
		{
			name: "stop_service", tier: tierMutate,
			description: "Stop a service by scaling it to zero. The declaration is kept, so " +
				"scale_service brings it back without re-applying a spec.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
			}, "project", "service"),
			run: runStop,
		},
		{
			name: "deploy_service", tier: tierMutate,
			description: "Deploy a specific image to an existing service, leaving everything " +
				"else as declared. Use a digest-pinned reference when you have one.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
				"image": {Type: "string", Description: "Image reference to deploy."},
			}, "project", "service", "image"),
			run: runDeploy,
		},
		{
			name: "run_pipeline", tier: tierMutate,
			description: "Queue a build for a service that declares a build block. Builds are " +
				"serialised; the run is returned as soon as it is queued, not when it finishes.",
			schema: object(map[string]property{
				"project": projectProp, "service": serviceProp,
				"deploy": {Type: "boolean", Default: true,
					Description: "Deploy the built digest when the build succeeds."},
			}, "project", "service"),
			run: runPipeline,
		},
		{
			name: "create_backup", tier: tierMutate,
			description: "Take an on-demand state snapshot and ship it to the configured " +
				"backup destination. Returns when the archive is durable.",
			schema: object(map[string]property{
				"reason": {Type: "string", Description: "Recorded in the archive manifest."},
			}),
			run: runCreateBackup,
		},
		{
			name: "test_notification", tier: tierMutate,
			description: "Send a test message through a project's notification channels, " +
				"bypassing their event filters. Use it to prove a channel is wired up.",
			schema: object(map[string]property{
				"project": projectProp,
				"channel": {Type: "string",
					Description: "One channel kind (telegram, webhook, slack, ntfy, smtp). " +
						"Omit for all of the project's channels."},
			}, "project"),
			run: runTestNotification,
		},

		// ---- destructive (admin + confirm) ----
		{
			name: "restore_backup", tier: tierDestructive,
			description: "Stage a restore of the platform's entire state from an archive. " +
				"It does NOT restore immediately — a restore happens on a stopped node, so " +
				"this verifies the archive and records the request, and an operator restarts " +
				"the daemon to apply it. Everything currently on the node is replaced. " +
				"Requires confirm=true.",
			schema: object(map[string]property{
				"archive": {Type: "string",
					Description: "Archive id from list_backups. Omit for the newest."},
				"skip_replay": {Type: "boolean",
					Description: "Restore the snapshot without its change segments. This " +
						"discards everything that happened after the snapshot; only use it " +
						"when a segment is itself damaged."},
				"confirm": {Type: "boolean",
					Description: "Must be true. Confirms the operator asked for this."},
			}, "confirm"),
			run: runRestoreBackup,
		},
		{
			name: "delete_project", tier: tierDestructive,
			description: "Delete every service in a project and stop everything it is running. " +
				"There is no undo. Requires confirm=true, and should only be called when an " +
				"operator has explicitly asked for it.",
			schema: object(map[string]property{
				"project": projectProp,
				"confirm": {Type: "boolean",
					Description: "Must be true. Confirms the operator asked for this."},
			}, "project", "confirm"),
			run: runDeleteProject,
		},
	}
}

// ---- read implementations ----

func runListProjects(ctx context.Context, s *Server, sess *Session, _ arguments) (callToolResult, error) {
	var out struct {
		Projects []json.RawMessage `json:"projects"`
	}
	if err := s.call(ctx, sess, http.MethodGet, pathProjects, nil, &out); err != nil {
		return callToolResult{}, err
	}
	if len(out.Projects) == 0 {
		return textResult("No projects are declared on this node."), nil
	}
	return jsonResult(out.Projects)
}

func runGetProject(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project"); err != nil {
		return callToolResult{}, err
	}
	var out json.RawMessage
	if err := s.call(ctx, sess, http.MethodGet,
		pathProjects+"/"+escape(args.text("project")), nil, &out); err != nil {
		return callToolResult{}, err
	}
	return jsonResult(out)
}

func runListServices(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	services, err := s.services(ctx, sess)
	if err != nil {
		return callToolResult{}, err
	}
	project := args.text("project")

	rows := make([]map[string]any, 0, len(services))
	for _, svc := range services {
		if project != "" && svc.Project != project {
			continue
		}
		rows = append(rows, map[string]any{
			"project": svc.Project, "service": svc.Service,
			"count": svc.Count, "image": svc.Image,
			"cpu_millis": svc.Resources.CPUMillis, "memory_bytes": svc.Resources.MemoryBytes,
		})
	}
	if len(rows) == 0 {
		if project != "" {
			return textResult(fmt.Sprintf("Project %q declares no services.", project)), nil
		}
		return textResult("No services are declared on this node."), nil
	}
	return jsonResult(rows)
}

func runGetService(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	svc, err := s.service(ctx, sess, args.text("project"), args.text("service"))
	if err != nil {
		return callToolResult{}, err
	}
	return jsonResult(svc)
}

func runListAllocs(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	var out struct {
		Allocs []allocRecord `json:"allocs"`
	}
	path := query(pathAllocs, "project", args.text("project"), "service", args.text("service"))
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &out); err != nil {
		return callToolResult{}, err
	}
	if len(out.Allocs) == 0 {
		return textResult("No allocations match. Nothing is running for that scope."), nil
	}
	return jsonResult(out.Allocs)
}

func runGetLogs(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	tail := min(max(args.number("tail", defaultLogTail), 1), maxLogTail)

	path := query(pathLogs,
		"project", args.text("project"), "service", args.text("service"),
		"alloc", args.text("alloc"), "tail", fmt.Sprint(tail))
	body, err := s.callText(ctx, sess, path)
	if err != nil {
		return callToolResult{}, err
	}
	if strings.TrimSpace(body) == "" {
		return textResult("No log output. The service may not have started, or may write " +
			"nothing to stdout/stderr."), nil
	}
	return textResult(trimTo(body, maxResultBytes)), nil
}

func runGetEvents(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	var out struct {
		Events  []json.RawMessage `json:"events"`
		Dropped int64             `json:"dropped"`
	}
	path := query(pathEvents,
		"project", args.text("project"), "limit", fmt.Sprint(args.number("limit", 50)))
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &out); err != nil {
		return callToolResult{}, err
	}
	if len(out.Events) == 0 {
		return textResult("The event feed is empty for that scope."), nil
	}
	result, err := jsonResult(out.Events)
	if err != nil {
		return callToolResult{}, err
	}
	if out.Dropped > 0 {
		// Said out loud, because a feed with gaps that does not admit to them is
		// worse than no feed: an agent reasoning about "no crash events" would
		// reach the wrong conclusion.
		result.Content = append(result.Content, contentBlock{Type: "text", Text: fmt.Sprintf(
			"Note: %d events were dropped by the dispatcher since start; this feed has gaps.",
			out.Dropped)})
	}
	return result, nil
}

func runNodeStats(ctx context.Context, s *Server, sess *Session, _ arguments) (callToolResult, error) {
	var out json.RawMessage
	if err := s.call(ctx, sess, http.MethodGet, pathStats, nil, &out); err != nil {
		return callToolResult{}, err
	}
	return jsonResult(out)
}

func runServiceStats(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	var out json.RawMessage
	path := query(pathStats, "project", args.text("project"), "service", args.text("service"))
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &out); err != nil {
		return callToolResult{}, err
	}
	return jsonResult(out)
}

func runListPipelines(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	var out struct {
		Runs []json.RawMessage `json:"runs"`
	}
	path := query(pathPipelines,
		"project", args.text("project"), "service", args.text("service"),
		"limit", fmt.Sprint(args.number("limit", 20)))
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &out); err != nil {
		return callToolResult{}, err
	}
	if len(out.Runs) == 0 {
		return textResult("No pipeline runs for that scope."), nil
	}
	return jsonResult(out.Runs)
}

func runListStorage(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	// Assembled from the services that declare volumes rather than read from a
	// storage table, because there is no such table: storage is declared in a
	// spec and used by the services that mount it (§8).
	services, err := s.services(ctx, sess)
	if err != nil {
		return callToolResult{}, err
	}
	project := args.text("project")

	type entry struct {
		Project  string   `json:"project"`
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		Mounts   []string `json:"mounted_by"`
		ReadOnly bool     `json:"read_only,omitempty"`
	}
	byKey := map[string]*entry{}
	for _, svc := range services {
		if project != "" && svc.Project != project {
			continue
		}
		for _, v := range svc.Volumes {
			key := svc.Project + "/" + v.Name
			existing, ok := byKey[key]
			if !ok {
				kind := v.Resource.Type
				if kind == "" {
					kind = "local"
				}
				existing = &entry{
					Project: svc.Project, Name: v.Name, Type: kind, ReadOnly: v.ReadOnly,
				}
				byKey[key] = existing
			}
			existing.Mounts = append(existing.Mounts,
				svc.Service+":"+v.MountPath)
		}
	}
	if len(byKey) == 0 {
		return textResult("No services declare volumes for that scope."), nil
	}

	out := make([]entry, 0, len(byKey))
	for _, e := range byKey {
		sort.Strings(e.Mounts)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Name < out[j].Name
	})
	return jsonResult(out)
}

func runGetAudit(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	var out struct {
		Entries []json.RawMessage `json:"entries"`
	}
	path := query(pathAudit,
		"actor", args.text("actor"), "action", args.text("action"),
		"limit", fmt.Sprint(args.number("limit", 50)))
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &out); err != nil {
		return callToolResult{}, err
	}
	if len(out.Entries) == 0 {
		return textResult("No audit entries match."), nil
	}
	return jsonResult(out.Entries)
}

// ---- mutate implementations ----

func runScale(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	if !args.has("count") {
		return callToolResult{}, fmt.Errorf("missing required argument: count")
	}
	count := args.number("count", -1)
	if count < 0 {
		return callToolResult{}, fmt.Errorf("count must be zero or more, got %v", args["count"])
	}
	return s.scaleTo(ctx, sess, args.text("project"), args.text("service"), count)
}

func runStop(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	return s.scaleTo(ctx, sess, args.text("project"), args.text("service"), 0)
}

// scaleTo is the one path to a replica count, for the same reason the CLI and
// the autoscaler share one (§9.2): two ways to set a number is two ways for it
// to be wrong.
func (s *Server) scaleTo(
	ctx context.Context, sess *Session, project, service string, count int,
) (callToolResult, error) {
	path := fmt.Sprintf("%s/%s/%s/scale", pathServices, escape(project), escape(service))
	if err := s.call(ctx, sess, http.MethodPost, path,
		map[string]int{"count": count}, nil); err != nil {
		return callToolResult{}, err
	}
	return textResult(fmt.Sprintf(
		"Set %s/%s to %d replica(s). The reconciler converges within a few seconds; "+
			"use list_allocs to see the result.", project, service, count)), nil
}

func runRestart(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	project, service := args.text("project"), args.text("service")
	path := fmt.Sprintf("%s/%s/%s/restart", pathServices, escape(project), escape(service))
	if err := s.call(ctx, sess, http.MethodPost, path, nil, nil); err != nil {
		return callToolResult{}, err
	}
	return textResult(fmt.Sprintf(
		"Restart requested for %s/%s. Replicas roll a few at a time according to the "+
			"service's update policy.", project, service)), nil
}

func runDeploy(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service", "image"); err != nil {
		return callToolResult{}, err
	}
	project, service, image := args.text("project"), args.text("service"), args.text("image")

	// Read, change one field, write back. The whole desired state has to go
	// through apply — there is no route that sets an image — and sending back
	// what was read means a deploy never silently drops a field this tool does
	// not know about.
	svc, err := s.service(ctx, sess, project, service)
	if err != nil {
		return callToolResult{}, err
	}
	previous := svc.Image
	if previous == image {
		return textResult(fmt.Sprintf("%s/%s already declares %s; nothing to do.",
			project, service, image)), nil
	}
	svc.Image = image

	var applied struct {
		Applied []string `json:"applied"`
	}
	if err := s.call(ctx, sess, http.MethodPut, pathServices,
		map[string]any{"services": []reconciler.Desired{svc}}, &applied); err != nil {
		return callToolResult{}, err
	}
	return textResult(fmt.Sprintf(
		"Deployed %s to %s/%s (was %s). Replicas roll according to the service's update policy.",
		image, project, service, orNone(previous))), nil
}

func runPipeline(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project", "service"); err != nil {
		return callToolResult{}, err
	}
	project, service := args.text("project"), args.text("service")
	// Defaults to true: asking for a build and not deploying it is the unusual
	// request, and the schema says so.
	deploy := true
	if args.has("deploy") {
		deploy = args.boolean("deploy")
	}

	var run map[string]any
	path := fmt.Sprintf("%s/%s/%s/build", pathPipelines, escape(project), escape(service))
	if err := s.call(ctx, sess, http.MethodPost, path,
		map[string]bool{"deploy": deploy}, &run); err != nil {
		return callToolResult{}, err
	}
	result, err := jsonResult(run)
	if err != nil {
		return callToolResult{}, err
	}
	result.Content = append(result.Content, contentBlock{Type: "text", Text: "Queued, not finished. " +
		"Builds are serialised; poll list_pipelines for the outcome."})
	return result, nil
}

func runTestNotification(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project"); err != nil {
		return callToolResult{}, err
	}
	var out struct {
		Results []struct {
			Channel string `json:"channel"`
			OK      bool   `json:"ok"`
			Error   string `json:"error,omitempty"`
		} `json:"results"`
	}
	path := query(fmt.Sprintf("%s/%s/notifications/test", pathProjects, escape(args.text("project"))),
		"channel", args.text("channel"))
	if err := s.call(ctx, sess, http.MethodPost, path, nil, &out); err != nil {
		return callToolResult{}, err
	}

	var b strings.Builder
	failed := false
	for _, r := range out.Results {
		if r.OK {
			fmt.Fprintf(&b, "%s: delivered\n", r.Channel)
			continue
		}
		failed = true
		fmt.Fprintf(&b, "%s: FAILED — %s\n", r.Channel, r.Error)
	}
	result := textResult(strings.TrimRight(b.String(), "\n"))
	// A channel that did not deliver is a tool failure, not a successful report
	// of a failure: an agent that reads "delivered: false" in a success result
	// is being asked to notice something the protocol has a field for.
	result.IsError = failed
	return result, nil
}

// ---- destructive implementations ----

func runDeleteProject(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("project"); err != nil {
		return callToolResult{}, err
	}
	project := args.text("project")

	services, err := s.services(ctx, sess)
	if err != nil {
		return callToolResult{}, err
	}
	var targets []string
	for _, svc := range services {
		if svc.Project == project {
			targets = append(targets, svc.Service)
		}
	}
	if len(targets) == 0 {
		return callToolResult{}, fmt.Errorf("project %q declares no services", project)
	}
	sort.Strings(targets)

	// Deleted one at a time, and the failures are reported rather than
	// aggregated away: a half-deleted project is a state someone has to finish
	// cleaning up, and they need to know which half.
	var deleted, failures []string
	for _, service := range targets {
		path := fmt.Sprintf("%s/%s/%s", pathServices, escape(project), escape(service))
		if err := s.call(ctx, sess, http.MethodDelete, path, nil, nil); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", service, err))
			continue
		}
		deleted = append(deleted, service)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Deleted %d of %d service(s) in project %q: %s\n",
		len(deleted), len(targets), project, strings.Join(deleted, ", "))
	if len(failures) > 0 {
		fmt.Fprintf(&b, "\nFailed:\n  %s\n", strings.Join(failures, "\n  "))
	}
	fmt.Fprint(&b, "\nSecrets under this project were not touched; delete them separately if "+
		"they are no longer needed.")

	result := textResult(b.String())
	result.IsError = len(failures) > 0
	return result, nil
}

// ---- shared helpers ----

// allocRecord is the alloc fields a tool reports.
type allocRecord struct {
	ID       string `json:"id"`
	Project  string `json:"project"`
	Service  string `json:"service"`
	Index    int    `json:"index"`
	Image    string `json:"image"`
	State    string `json:"state"`
	Restarts int    `json:"restarts"`
	Healthy  bool   `json:"healthy"`
	Message  string `json:"health_message,omitempty"`
}

// services fetches the declared set.
func (s *Server) services(ctx context.Context, sess *Session) ([]reconciler.Desired, error) {
	var out struct {
		Services []reconciler.Desired `json:"services"`
	}
	if err := s.call(ctx, sess, http.MethodGet, pathServices, nil, &out); err != nil {
		return nil, err
	}
	return out.Services, nil
}

// service finds one, or says which ones exist in that project — a model that
// misremembers a name gets the correction rather than a bare "not found".
func (s *Server) service(
	ctx context.Context, sess *Session, project, service string,
) (reconciler.Desired, error) {
	services, err := s.services(ctx, sess)
	if err != nil {
		return reconciler.Desired{}, err
	}
	var siblings []string
	for _, svc := range services {
		if svc.Project == project && svc.Service == service {
			return svc, nil
		}
		if svc.Project == project {
			siblings = append(siblings, svc.Service)
		}
	}
	if len(siblings) == 0 {
		return reconciler.Desired{}, fmt.Errorf("no service %s/%s, and project %q declares nothing",
			project, service, project)
	}
	sort.Strings(siblings)
	return reconciler.Desired{}, fmt.Errorf("no service %s/%s; project %q declares: %s",
		project, service, project, strings.Join(siblings, ", "))
}

// jsonResult renders a value as the text block a model reads.
//
// Indented JSON rather than a table: it is unambiguous about nesting and about
// null-versus-zero, and every model reads it well. The cap is applied here so no
// tool can forget it.
func jsonResult(v any) (callToolResult, error) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return callToolResult{}, fmt.Errorf("render result: %w", err)
	}
	return textResult(trimTo(string(body), maxResultBytes)), nil
}

func orNone(s string) string {
	if s == "" {
		return "no image"
	}
	return s
}

// ---- spec tools ----

// runPlanSpec parses a spec and reports what applying it would change.
func runPlanSpec(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("spec"); err != nil {
		return callToolResult{}, err
	}
	desired, _, err := s.parseSpec(args.text("spec"))
	if err != nil {
		return callToolResult{}, err
	}
	current, err := s.services(ctx, sess)
	if err != nil {
		return callToolResult{}, err
	}

	diff := reconciler.Diff(current, desired)
	if len(diff) == 0 {
		return textResult("No changes. The declared state already matches this spec."), nil
	}
	return textResult(fmt.Sprintf("%s\n\n%d change(s). Nothing has been applied; "+
		"call apply_spec with the same spec to make them.",
		strings.Join(diff, "\n"), len(diff))), nil
}

// runApplySpec applies a spec.
func runApplySpec(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	if err := args.require("spec"); err != nil {
		return callToolResult{}, err
	}
	desired, pipelines, err := s.parseSpec(args.text("spec"))
	if err != nil {
		return callToolResult{}, err
	}

	var out struct {
		Applied []string `json:"applied"`
	}
	body := map[string]any{"services": desired}
	if len(pipelines) > 0 {
		body["pipelines"] = pipelines
	}
	if err := s.call(ctx, sess, http.MethodPut, pathServices, body, &out); err != nil {
		return callToolResult{}, err
	}
	return textResult(fmt.Sprintf(
		"Applied %d service(s): %s. Services not named by this spec were left alone. "+
			"The reconciler converges; use list_allocs or get_events to watch it.",
		len(out.Applied), strings.Join(out.Applied, ", "))), nil
}

// parseSpec turns HCL source into desired state through the configured seam.
func (s *Server) parseSpec(source string) ([]reconciler.Desired, []gitops.Config, error) {
	if s.parse == nil {
		return nil, nil, fmt.Errorf(
			"this MCP server was built without a spec parser; plan_spec and apply_spec are unavailable")
	}
	if strings.TrimSpace(source) == "" {
		return nil, nil, fmt.Errorf("the spec is empty")
	}
	desired, pipelines, err := s.parse([]byte(source))
	if err != nil {
		// Returned as the tool's error text, diagnostics and all: HCL's
		// diagnostics name the line and the reason, which is exactly what a model
		// needs to fix the spec it just wrote.
		return nil, nil, fmt.Errorf("the spec did not parse:\n%w", err)
	}
	if len(desired) == 0 {
		return nil, nil, fmt.Errorf("the spec declares no services")
	}
	return desired, pipelines, nil
}

// ---- backup implementations ----

func runListBackups(ctx context.Context, s *Server, sess *Session, _ arguments) (callToolResult, error) {
	var out struct {
		Backups     []json.RawMessage `json:"backups"`
		Replication json.RawMessage   `json:"replication"`
	}
	if err := s.call(ctx, sess, http.MethodGet, pathBackups, nil, &out); err != nil {
		return callToolResult{}, err
	}

	result, err := jsonResult(map[string]any{
		"replication": out.Replication, "archives": out.Backups,
	})
	if err != nil {
		return callToolResult{}, err
	}
	if len(out.Backups) == 0 {
		// Stated rather than left as an empty list. "No archives" is the single
		// most important fact this tool can report, and a model reading `[]`
		// may not weigh it as one.
		result.Content = append(result.Content, contentBlock{Type: "text", Text: "There are " +
			"no archives: nothing on this node has been backed up, and a disk failure " +
			"would lose all of it."})
	}
	return result, nil
}

func runCreateBackup(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	reason := args.text("reason")
	if reason == "" {
		reason = "requested by an agent"
	}
	var manifest map[string]any
	if err := s.call(ctx, sess, http.MethodPost, pathBackups,
		map[string]string{"reason": reason}, &manifest); err != nil {
		return callToolResult{}, err
	}
	return jsonResult(manifest)
}

func runRestoreBackup(ctx context.Context, s *Server, sess *Session, args arguments) (callToolResult, error) {
	body := map[string]any{"skip_replay": args.boolean("skip_replay")}
	if archive := args.text("archive"); archive != "" {
		body["archive"] = archive
	}

	var out struct {
		Message string `json:"message"`
	}
	if err := s.call(ctx, sess, http.MethodPost, pathBackups+"/restore", body, &out); err != nil {
		return callToolResult{}, err
	}
	return textResult(out.Message + "\n\nThis is staged, not done. Tell the operator that " +
		"kanead has to be restarted, and that it is their call."), nil
}
