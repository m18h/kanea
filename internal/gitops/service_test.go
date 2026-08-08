package gitops_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/store"
)

// applier records the specs a sync applied.
type applier struct {
	mu    sync.Mutex
	specs []*jobspec.Spec
	err   error
}

func (a *applier) Apply(_ context.Context, spec *jobspec.Spec) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	a.specs = append(a.specs, spec)

	var applied []string
	for _, svc := range spec.Services {
		applied = append(applied, svc.Project+"/"+svc.Name)
	}
	return applied, nil
}

func (a *applier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.specs)
}

// serviceHarness is the coordinator over a real store, a real syncer and a fake
// buildctl.
type serviceHarness struct {
	svc     *gitops.Service
	queue   *gitops.Queue
	store   store.Store
	applier *applier
	clock   *clock
}

func newServiceHarness(t *testing.T, secrets gitops.Resolver) *serviceHarness {
	t.Helper()

	runs, c, st := newRuns(t)
	binary, _, _ := fakeBuildctl(t, writeMetadata)
	builder, err := gitops.NewBuilder(gitops.BuilderConfig{
		Binary: binary, WorkDir: t.TempDir(), Socket: "unix:///tmp/test.sock",
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	runner, err := gitops.NewRunner(gitops.RunnerConfig{
		Runs: runs, Syncer: gitops.NewSyncer(gitops.SyncerConfig{Secrets: secrets}),
		Builder: builder, Deployer: newDeployer(), Secrets: secrets,
		LogDir: t.TempDir(), WorkDir: t.TempDir(), Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	queue, err := gitops.NewQueue(gitops.QueueConfig{Runner: runner, Now: c.now})
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}

	h := &serviceHarness{store: st, applier: &applier{}, clock: c, queue: queue}
	h.svc, err = gitops.NewService(gitops.ServiceConfig{
		Store: st, Runs: runs, Runner: runner, Queue: queue,
		Syncer:   gitops.NewSyncer(gitops.SyncerConfig{Secrets: secrets}),
		Webhooks: gitops.NewWebhooks(gitops.WebhooksConfig{Secrets: secrets, Now: c.now}),
		Applier:  h.applier, Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return h
}

// configure writes a project's pipeline configuration.
func (h *serviceHarness) configure(t *testing.T, cfg gitops.Config) {
	t.Helper()
	if _, err := store.PutValue(context.Background(), h.store,
		store.KindProject, cfg.Project, cfg); err != nil {
		t.Fatalf("put config: %v", err)
	}
}

// syncRepo is a repository whose specs declare the shop project.
func syncRepo(t *testing.T) string {
	t.Helper()
	return repo(t, map[string]string{
		".kanea/web.hcl": `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  build {
    context = "./web"
    target  = "registry.example.com/shop/web"
    tag     = "${GIT_SHA_SHORT}"
  }
  task "app" { image = "registry.example.com/shop/web:latest" }
}`,
		"web/Dockerfile": "FROM scratch\n",
	})
}

func TestSyncAppliesAndQueuesABuild(t *testing.T) {
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: syncRepo(t)},
	})

	result, err := h.svc.Sync(context.Background(), "shop", "tester")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(result.Applied) != 1 || result.Applied[0] != "shop/web" {
		t.Fatalf("applied = %v, want [shop/web]", result.Applied)
	}
	if len(result.Built) != 1 || result.Built[0] != "web" {
		t.Fatalf("built = %v, want [web]", result.Built)
	}
	if result.Commit == "" {
		t.Fatal("no commit recorded")
	}

	// The build blocks the spec declared are stored, so a later `kanea build`
	// needs nothing from the repository to know what to build.
	cfg, err := h.svc.ProjectConfig(context.Background(), "shop")
	if err != nil {
		t.Fatalf("ProjectConfig: %v", err)
	}
	if cfg.Builds["web"].Target != "registry.example.com/shop/web" {
		t.Fatalf("stored builds = %+v", cfg.Builds)
	}
	if cfg.LastCommit != result.Commit {
		t.Fatalf("last commit = %q, want %q", cfg.LastCommit, result.Commit)
	}
}

func TestSyncOfAnUnchangedCommitDoesNothing(t *testing.T) {
	// A poll loop runs this every couple of minutes against repositories that
	// mostly have not moved. If an unchanged remote still applied and queued a
	// build, a project with a build block would rebuild and redeploy itself
	// forever with nobody having changed anything.
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: syncRepo(t)},
	})

	ctx := context.Background()
	if _, err := h.svc.Sync(ctx, "shop", "first"); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	result, err := h.svc.Sync(ctx, "shop", "second")
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if !result.Unchanged {
		t.Fatal("second sync of the same commit should report unchanged")
	}
	if len(result.Applied) != 0 || len(result.Built) != 0 {
		t.Fatalf("second sync did work: %+v", result)
	}
	if h.applier.count() != 1 {
		t.Fatalf("applied %d times, want 1", h.applier.count())
	}
}

func TestSyncRejectsAForeignProject(t *testing.T) {
	// The security boundary of GitOps. A repository speaks for its own project
	// and no other — without this, whoever can push to one project's source can
	// redefine every service on the node, which is the cross-project escalation
	// R5 blocks for secrets arriving through a different door.
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop",
		Source: gitops.Source{URL: repo(t, map[string]string{
			".kanea/x.hcl": `
spec_version = 1
project "billing" {}
service "api" {
  project = "billing"
  task "app" { image = "evil:latest" }
}`,
		})},
	})

	_, err := h.svc.Sync(context.Background(), "shop", "tester")
	if !errors.Is(err, gitops.ErrForeignProject) {
		t.Fatalf("err = %v, want ErrForeignProject", err)
	}
	if h.applier.count() != 0 {
		t.Fatal("a foreign spec was applied")
	}
	if !strings.Contains(err.Error(), "billing") {
		t.Fatalf("err = %v; it should name the project it refused", err)
	}
}

func TestSyncHoldsWhenApprovalIsRequired(t *testing.T) {
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop", RequireApproval: true,
		Source: gitops.Source{URL: syncRepo(t)},
	})

	result, err := h.svc.Sync(context.Background(), "shop", "tester")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(result.Held) == 0 {
		t.Fatal("nothing held")
	}
	if len(result.Applied) != 0 || len(result.Built) != 0 {
		t.Fatalf("an approval-gated project applied anyway: %+v", result)
	}
	if h.applier.count() != 0 {
		t.Fatal("the applier was called for a held sync")
	}
	// The commit is still reported: an operator deciding whether to approve
	// needs to know what they would be approving.
	if result.Commit == "" {
		t.Fatal("a held sync should still report the commit")
	}
}

func TestTriggerNeedsABuildBlock(t *testing.T) {
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: syncRepo(t)},
	})

	_, err := h.svc.Trigger(context.Background(), "shop", "worker", true, "tester")
	if !errors.Is(err, gitops.ErrNoBuild) {
		t.Fatalf("err = %v, want ErrNoBuild", err)
	}
}

func TestTriggerNeedsASource(t *testing.T) {
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop",
		Builds:  map[string]gitops.BuildSpec{"web": {Context: "./web"}},
	})

	_, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if !errors.Is(err, gitops.ErrNoSource) {
		t.Fatalf("err = %v, want ErrNoSource", err)
	}
}

func TestTriggerQueuesARun(t *testing.T) {
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: syncRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {
			Context: "./web", Target: "registry.example.com/shop/web",
		}},
	})

	run, err := h.svc.Trigger(context.Background(), "shop", "web", true, "alice")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if run.State != gitops.RunQueued {
		t.Fatalf("state = %q, want queued", run.State)
	}
	if run.Trigger != gitops.TriggerManual || run.TriggeredBy != "alice" {
		t.Fatalf("run = %+v; want a manual trigger attributed to alice", run)
	}
	if h.queue.Depth() != 1 {
		t.Fatalf("queue depth = %d, want 1", h.queue.Depth())
	}
}

func TestDeliverWakesTheSyncLoop(t *testing.T) {
	secrets := &resolver{values: map[string][]byte{webhookSecretRef: []byte("s3cret")}}
	h := newServiceHarness(t, secrets)
	h.configure(t, gitops.Config{
		Project: "shop", WebhookSecretRef: webhookSecretRef,
		Source: gitops.Source{URL: syncRepo(t), Branch: "main"},
	})

	header, body := githubPush("s3cret", "d-1", pushBody)

	delivery, err := h.svc.Deliver(context.Background(), "shop", header, body)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !delivery.Deployable() {
		t.Fatal("a push to main should be deployable")
	}
	select {
	case project := <-h.svc.Wake():
		if project != "shop" {
			t.Fatalf("woke for %q, want shop", project)
		}
	default:
		t.Fatal("no wake was queued")
	}
}

func TestDeliverIgnoresAnUnwatchedBranch(t *testing.T) {
	// A push to a feature branch is a legitimate delivery that means nothing
	// here. Syncing it would deploy that branch over production.
	secrets := &resolver{values: map[string][]byte{webhookSecretRef: []byte("s3cret")}}
	h := newServiceHarness(t, secrets)
	h.configure(t, gitops.Config{
		Project: "shop", WebhookSecretRef: webhookSecretRef,
		Source: gitops.Source{URL: syncRepo(t), Branch: "main"},
	})

	header, body := githubPush("s3cret",
		"d-2", `{"ref":"refs/heads/feature","after":"abc123def456","deleted":false}`)

	if _, err := h.svc.Deliver(context.Background(), "shop", header, body); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	select {
	case project := <-h.svc.Wake():
		t.Fatalf("woke for %q on an unwatched branch", project)
	default:
	}
}

func TestDeliverRefusesAnUnsignedPush(t *testing.T) {
	secrets := &resolver{values: map[string][]byte{webhookSecretRef: []byte("s3cret")}}
	h := newServiceHarness(t, secrets)
	h.configure(t, gitops.Config{
		Project: "shop", WebhookSecretRef: webhookSecretRef,
		Source: gitops.Source{URL: syncRepo(t), Branch: "main"},
	})

	header := http.Header{}
	header.Set("X-GitHub-Event", "push")
	header.Set("X-GitHub-Delivery", "d-3")

	_, err := h.svc.Deliver(context.Background(), "shop", header, []byte(pushBody))
	if !errors.Is(err, gitops.ErrUnsignedWebhook) {
		t.Fatalf("err = %v, want ErrUnsignedWebhook", err)
	}
	select {
	case <-h.svc.Wake():
		t.Fatal("an unsigned delivery woke the sync loop")
	default:
	}
}

func TestConfigFromSpecKeepsGitAndBuilds(t *testing.T) {
	spec, diags := jobspec.ParseContents(jobspec.Options{}, map[string][]byte{
		"k.hcl": []byte(`
spec_version = 1
project "shop" {
  git {
    url                = "https://example.com/shop.git"
    branch             = "main"
    auth_ref           = "secret:shop/deploy-key"
    webhook_secret_ref = "secret:shop/webhook"
    poll_interval      = "5m"
    require_approval   = true
  }
}
service "web" {
  project = "shop"
  build {
    context           = "./web"
    target            = "registry.example.com/shop/web"
    registry_auth_ref = "secret:shop/registry"
  }
  task "app" { image = "registry.example.com/shop/web:latest" }
}`),
	})
	if diags.HasErrors() {
		t.Fatalf("parse: %s", diags.Error())
	}

	cfg, ok := gitops.ConfigFromSpec(spec, "shop")
	if !ok {
		t.Fatal("no pipeline config derived from a spec with a git block")
	}
	if cfg.Source.URL != "https://example.com/shop.git" || cfg.Source.Branch != "main" {
		t.Fatalf("source = %+v", cfg.Source)
	}
	if cfg.WebhookSecretRef != "secret:shop/webhook" {
		t.Fatalf("webhook secret = %q", cfg.WebhookSecretRef)
	}
	if cfg.PollInterval.Minutes() != 5 || !cfg.RequireApproval {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.Builds["web"].RegistryAuthRef != "secret:shop/registry" {
		t.Fatalf("builds = %+v", cfg.Builds)
	}

	// An image-only spec must not produce a config: an apply of one would
	// otherwise overwrite a git block with a zero value and silently stop a
	// project syncing.
	plain, diags := jobspec.ParseContents(jobspec.Options{}, map[string][]byte{
		"k.hcl": []byte(`
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "registry.example.com/shop/web:1" }
}`),
	})
	if diags.HasErrors() {
		t.Fatalf("parse: %s", diags.Error())
	}
	if _, ok := gitops.ConfigFromSpec(plain, "shop"); ok {
		t.Fatal("an image-only spec produced a pipeline config")
	}
}
