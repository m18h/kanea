package gitops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/store"
)

// The pipeline coordinator.
//
// Runner, Syncer, Builder, Queue and Webhooks each do one thing and know
// nothing about the Store's project records. This is the piece that reads a
// project's pipeline configuration and turns "build web" or "something was
// pushed" into a Request the runner understands. It is what the API and the
// daemon's poll loop both talk to.

// Errors a caller can act on.
var (
	// ErrNoSource means the project has no git block, so there is nothing to
	// sync or build from.
	ErrNoSource = errors.New("gitops: project has no git source configured")
	// ErrNoBuild means the service has no build block, so it deploys a
	// pre-built image and there is nothing to build.
	ErrNoBuild = errors.New("gitops: service has no build block")
	// ErrForeignProject means a synced spec declared services in a project
	// other than the one whose repository it came from.
	ErrForeignProject = errors.New("gitops: spec declares another project")
)

// Config is a project's stored configuration.
//
// It lives under store.KindProject, keyed by project name, and is written by
// the same apply that writes the services: the git block, the build blocks and
// the notifications block come from the same file, and splitting them across
// round-trips would let a service exist with a build block whose source Kanea
// does not know.
//
// It carries notifications as well as pipelines because it is *the* project
// record, not a pipelines record. The type living in this package is history:
// pipelines needed it first. If a third concern lands on it, move the type
// somewhere neutral rather than growing a third package's field here.
type Config struct {
	Project string `json:"project"`
	// Source is the git remote. A zero Source means the project deploys by
	// pushing specs at the API, which is a legitimate way to run.
	Source Source `json:"source,omitzero"`
	// WebhookSecretRef authenticates push notifications. Deliberately separate
	// from Source.AuthRef (§10.1): one lets Kanea read the repository, the
	// other lets the repository tell Kanea something.
	WebhookSecretRef string `json:"webhook_secret_ref,omitempty"`
	// PollInterval overrides the default sync cadence.
	PollInterval time.Duration `json:"poll_interval,omitempty"`
	// RequireApproval holds a synced change instead of applying it.
	RequireApproval bool `json:"require_approval,omitempty"`
	// Builds is the per-service build spec, keyed by service name.
	Builds map[string]BuildSpec `json:"builds,omitempty"`

	// Notifications is the project's `notifications` block (§11). Held as the
	// parsed spec type rather than resolved channels: a channel holds a
	// credential and an HTTP client, neither of which belongs in the Store.
	Notifications *jobspec.Notifications `json:"notifications,omitempty"`

	// LastCommit is the revision the last successful sync applied. It is what
	// makes a poll loop cheap: an unchanged remote does no work at all.
	LastCommit string `json:"last_commit,omitempty"`
	// LastSyncAt is when that happened, for the dashboard.
	LastSyncAt time.Time `json:"last_sync_at,omitzero"`
}

// HasSource reports whether the project can be synced.
func (c Config) HasSource() bool { return c.Source.URL != "" }

// SyncResult is what one sync did.
type SyncResult struct {
	Commit  string
	Message string
	// Applied lists the services whose desired state changed.
	Applied []string
	// Built lists the services a build was queued for.
	Built []string
	// Held lists services a sync would have changed but did not, because the
	// project requires approval (§10.1).
	Held []string
	// Unchanged reports that the remote is at the commit already applied.
	Unchanged bool
}

// Applier applies a synced job spec to the desired state.
//
// A seam, not an import: the conversion from a spec to what the reconciler runs
// knows both vocabularies and lives with the CLI that already does it for
// `kanea deploy`. Duplicating it here would give a synced spec and a pushed
// spec two subtly different meanings, which is exactly the failure GitOps is
// supposed to remove.
type Applier interface {
	Apply(ctx context.Context, spec *jobspec.Spec) ([]string, error)
}

// Service coordinates syncs and builds for every project.
type Service struct {
	store    store.Store
	runs     *Runs
	runner   *Runner
	queue    *Queue
	syncer   *Syncer
	webhooks *Webhooks
	applier  Applier
	// specOptions carries what a spec needs to validate that is not in the
	// file: the base domain an `expose` block is checked against, chiefly.
	// Without it a synced spec would validate differently from the same file
	// deployed with `kanea deploy`.
	specOptions jobspec.Options
	insecure    bool
	log         *slog.Logger
	now         func() time.Time

	// wake carries project names a delivery says to sync now. Buffered and
	// non-blocking: a webhook handler must answer the provider in milliseconds,
	// and a sync takes seconds. A dropped wake costs one poll interval of
	// latency, never a missed deploy, because the next poll reads the same
	// remote and finds the same commit.
	wake chan string
}

// ServiceConfig configures the coordinator.
type ServiceConfig struct {
	Store    store.Store
	Runs     *Runs
	Runner   *Runner
	Queue    *Queue
	Syncer   *Syncer
	Webhooks *Webhooks
	Applier  Applier
	// SpecOptions is what a synced spec is parsed with.
	SpecOptions jobspec.Options
	// Insecure allows a plain-HTTP registry, for a node-local one.
	Insecure bool
	Logger   *slog.Logger
	Now      func() time.Time
}

// NewService builds the coordinator.
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("gitops: a store is required")
	case cfg.Runs == nil:
		return nil, errors.New("gitops: a run store is required")
	case cfg.Runner == nil:
		return nil, errors.New("gitops: a runner is required")
	case cfg.Queue == nil:
		return nil, errors.New("gitops: a queue is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{
		store: cfg.Store, runs: cfg.Runs, runner: cfg.Runner, queue: cfg.Queue,
		syncer: cfg.Syncer, webhooks: cfg.Webhooks, applier: cfg.Applier,
		specOptions: cfg.SpecOptions, insecure: cfg.Insecure,
		log: cfg.Logger, now: cfg.Now,
		wake: make(chan string, 16),
	}, nil
}

// List returns pipeline runs, newest first.
func (s *Service) List(ctx context.Context, project, service string, limit int) ([]Run, error) {
	return s.runs.List(ctx, project, service, limit)
}

// Get returns one run.
func (s *Service) Get(ctx context.Context, project, service, id string) (Run, error) {
	return s.runs.Get(ctx, project, service, id)
}

// LogPath is where a run's log was written.
func (s *Service) LogPath(run Run) string { return s.runner.LogPath(run) }

// Wake is the channel the daemon's sync loop watches.
func (s *Service) Wake() <-chan string { return s.wake }

// ProjectConfig reads a project's pipeline configuration.
func (s *Service) ProjectConfig(ctx context.Context, project string) (Config, error) {
	cfg, _, err := store.GetValue[Config](ctx, s.store, store.KindProject, project)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Config{}, fmt.Errorf("%w: project %s", ErrNotFound, project)
		}
		return Config{}, err
	}
	// Older records, and records written by an apply that carried no git block,
	// have no project name in them. Fill it in so callers can rely on it.
	if cfg.Project == "" {
		cfg.Project = project
	}
	return cfg, nil
}

// Projects lists every project with pipeline configuration, for the poll loop.
func (s *Service) Projects(ctx context.Context) ([]Config, error) {
	var out []Config
	var after string
	for {
		values, page, err := store.ListValues[Config](ctx, s.store,
			store.KindProject, store.ListOptions{After: after, Limit: 200})
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		out = append(out, values...)
		if !page.More {
			break
		}
		after = page.NextAfter
	}
	return out, nil
}

// Trigger queues a manual build (§10.2, `kanea build web`).
func (s *Service) Trigger(
	ctx context.Context, project, service string, deploy bool, by string,
) (Run, error) {
	cfg, err := s.ProjectConfig(ctx, project)
	if err != nil {
		return Run{}, err
	}
	req, err := s.request(cfg, service)
	if err != nil {
		return Run{}, err
	}
	req.Trigger = TriggerManual
	req.TriggeredBy = by
	req.Deploy = deploy
	return s.queue.Submit(ctx, req)
}

// request assembles the runner's Request from stored configuration.
func (s *Service) request(cfg Config, service string) (Request, error) {
	if !cfg.HasSource() {
		return Request{}, fmt.Errorf("%w: %s", ErrNoSource, cfg.Project)
	}
	spec, ok := cfg.Builds[service]
	if !ok {
		return Request{}, fmt.Errorf("%w: %s/%s", ErrNoBuild, cfg.Project, service)
	}
	return Request{
		Project: cfg.Project, Service: service,
		Source: cfg.Source, Build: spec, Insecure: s.insecure,
	}, nil
}

// Sync fetches a project's source and applies what it finds (§10.1).
//
// The whole thing is one pass: fetch, parse, validate, apply, then queue a
// build for every service that has a build block. Builds are queued rather than
// run, so a sync of ten buildable services returns in the time of the fetch
// and the builds proceed one at a time behind the queue.
func (s *Service) Sync(ctx context.Context, project, by string) (SyncResult, error) {
	cfg, err := s.ProjectConfig(ctx, project)
	if err != nil {
		return SyncResult{}, err
	}
	if !cfg.HasSource() {
		return SyncResult{}, fmt.Errorf("%w: %s", ErrNoSource, project)
	}
	if s.syncer == nil || s.applier == nil {
		return SyncResult{}, errors.New("gitops: syncing is not configured on this daemon")
	}

	checkout, err := s.syncer.Fetch(ctx, cfg.Source)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{Commit: checkout.Commit, Message: checkout.Message}

	spec, err := parseCheckout(project, checkout, s.specOptions)
	if err != nil {
		return result, err
	}

	// Approval holds the apply, not the fetch: an operator reviewing a change
	// needs to see what it is, and the commit is recorded either way.
	buildable := buildableServices(spec)
	if cfg.RequireApproval {
		// Every service the commit describes, not only the buildable ones: an
		// approval gate holds the whole apply, so a change to a service that
		// only pulls an image is held too.
		for _, svc := range spec.Services {
			result.Held = append(result.Held, svc.Name)
		}
		sort.Strings(result.Held)
		s.log.Info("sync held for approval",
			"project", project, "commit", ShortID(checkout.Commit), "services", len(result.Held))
		return result, nil
	}

	// Nothing to do for a commit already applied. Checked after the parse so a
	// spec that stopped parsing is still reported, and before the apply so a
	// poll loop on an idle repository writes nothing at all.
	if cfg.LastCommit == checkout.Commit {
		result.Unchanged = true
		return result, nil
	}

	applied, err := s.applier.Apply(ctx, spec)
	if err != nil {
		return result, fmt.Errorf("apply %s@%s: %w", project, ShortID(checkout.Commit), err)
	}
	result.Applied = applied

	// The build blocks in the spec are authoritative from here: the apply just
	// wrote them, so re-reading the stored config would race with itself.
	cfg.Builds = buildSpecs(spec)
	for _, p := range spec.Projects {
		if p.Name == project {
			cfg.Notifications = p.Notifications
		}
	}
	cfg.LastCommit = checkout.Commit
	cfg.LastSyncAt = s.now()
	if _, err := store.PutValue(ctx, s.store, store.KindProject, project, cfg); err != nil {
		return result, fmt.Errorf("record sync state: %w", err)
	}

	for _, name := range buildable {
		req, err := s.request(cfg, name)
		if err != nil {
			continue
		}
		req.Trigger = TriggerPush
		req.TriggeredBy = by
		req.Deploy = true
		if _, err := s.queue.Submit(ctx, req); err != nil {
			// One service failing to queue must not abandon the rest: the
			// sync itself succeeded and the operator needs to see which
			// builds it produced.
			s.log.Error("cannot queue a build for a synced service",
				"project", project, "service", name, "error", err)
			continue
		}
		result.Built = append(result.Built, name)
	}

	s.log.Info("synced project", "project", project, "commit", ShortID(checkout.Commit),
		"applied", len(result.Applied), "queued", len(result.Built))
	return result, nil
}

// Deliver authenticates a push webhook and asks for a sync.
//
// It does not sync inline. The provider is waiting on this response with a ten
// second timeout, and a clone plus a parse plus an apply is not reliably inside
// it, so the delivery is verified, recorded, and handed to the sync loop.
func (s *Service) Deliver(
	ctx context.Context, project string, header http.Header, body []byte,
) (Delivery, error) {
	if s.webhooks == nil {
		return Delivery{}, errors.New("gitops: webhooks are not configured on this daemon")
	}
	cfg, err := s.ProjectConfig(ctx, project)
	if err != nil {
		return Delivery{}, err
	}
	delivery, err := s.webhooks.Verify(ctx, project, cfg.WebhookSecretRef, header, body)
	if err != nil {
		return Delivery{}, err
	}

	if !delivery.Deployable() {
		return delivery, nil
	}
	// A push to a branch nobody watches is a legitimate delivery that means
	// nothing here. Answering it with success and doing no work is correct;
	// syncing would deploy a feature branch over production.
	if watched := cfg.Source.Branch; watched != "" && delivery.Branch() != watched {
		s.log.Debug("ignoring a push to an unwatched branch",
			"project", project, "branch", delivery.Branch(), "watched", watched)
		return delivery, nil
	}

	select {
	case s.wake <- project:
	default:
		s.log.Warn("sync backlog full, falling back to the poll interval", "project", project)
	}
	return delivery, nil
}

// parseCheckout parses the specs a checkout produced and enforces the project
// boundary.
//
// A repository speaks for its own project and no other. Without this check, a
// project whose git source anyone can write becomes a way to redefine every
// other project on the node: the same cross-project escalation R5 blocks for
// secrets, arriving through a different door.
func parseCheckout(project string, checkout Checkout, opts jobspec.Options) (*jobspec.Spec, error) {
	if len(checkout.Specs) == 0 {
		return nil, fmt.Errorf("%w (commit %s)", ErrNoSpecs, ShortID(checkout.Commit))
	}
	spec, diags := jobspec.ParseContents(opts, checkout.Specs)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse specs at %s: %s", ShortID(checkout.Commit), diags.Error())
	}

	var foreign []string
	for _, p := range spec.Projects {
		if p.Name != project {
			foreign = append(foreign, p.Name)
		}
	}
	for _, svc := range spec.Services {
		if svc.Project != project && !contains(foreign, svc.Project) {
			foreign = append(foreign, svc.Project)
		}
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return nil, fmt.Errorf("%w: the source for project %s declares %s",
			ErrForeignProject, project, strings.Join(foreign, ", "))
	}
	return spec, nil
}

// buildableServices names the services with a build block, in a stable order.
func buildableServices(spec *jobspec.Spec) []string {
	var out []string
	for _, svc := range spec.Services {
		if svc.Build != nil {
			out = append(out, svc.Name)
		}
	}
	sort.Strings(out)
	return out
}

// buildSpecs converts the spec's build blocks into what the runner needs.
func buildSpecs(spec *jobspec.Spec) map[string]BuildSpec {
	out := map[string]BuildSpec{}
	for _, svc := range spec.Services {
		if svc.Build == nil {
			continue
		}
		out[svc.Name] = BuildSpec{
			Context:         svc.Build.Context,
			Dockerfile:      svc.Build.Dockerfile,
			Target:          svc.Build.Target,
			Tag:             svc.Build.Tag,
			CacheRepo:       svc.Build.CacheRepo,
			RegistryAuthRef: svc.Build.RegistryAuthRef,
		}
	}
	return out
}

// ConfigFromSpec derives a project's pipeline configuration from a spec, for
// the apply path.
//
// Returns false when the spec says nothing about the project's pipelines, so an
// apply of an image-only spec does not overwrite a git block with a zero value.
func ConfigFromSpec(spec *jobspec.Spec, project string) (Config, bool) {
	cfg := Config{Project: project, Builds: map[string]BuildSpec{}}
	found := false

	for _, p := range spec.Projects {
		if p.Name != project || p.Git == nil {
			continue
		}
		found = true
		cfg.Source = Source{
			URL: p.Git.URL, Branch: p.Git.Branch,
			Path: p.Git.Path, AuthRef: p.Git.AuthRef,
		}
		cfg.WebhookSecretRef = p.Git.WebhookSecretRef
		cfg.RequireApproval = p.Git.RequireApproval
		// Already validated as a duration by the parser, so a parse failure
		// here would be a bug rather than user input; the zero value falls
		// back to the default interval.
		if p.Git.PollInterval != "" {
			if d, err := time.ParseDuration(p.Git.PollInterval); err == nil {
				cfg.PollInterval = d
			}
		}
	}

	for name, bspec := range buildSpecs(spec) {
		cfg.Builds[name] = bspec
		found = true
	}
	for _, p := range spec.Projects {
		if p.Name == project && p.Notifications != nil {
			cfg.Notifications = p.Notifications
			found = true
		}
	}
	return cfg, found
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
