package gitops_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/gitops"
)

// deployer records what a successful build asked to deploy.
type deployer struct {
	mu   sync.Mutex
	refs map[string]string
	err  error
}

func newDeployer() *deployer { return &deployer{refs: map[string]string{}} }

func (d *deployer) Deploy(_ context.Context, project, service, ref string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.refs[project+"/"+service] = ref
	return nil
}

func (d *deployer) ref(key string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refs[key]
}

// runnerHarness is a runner over a real run store, a real syncer and a fake
// buildctl — so a test drives the whole sequence the daemon drives.
type runnerHarness struct {
	runner   *gitops.Runner
	runs     *gitops.Runs
	deployer *deployer
	logDir   string
	argsFile string
	clock    *clock
}

func newRunner(t *testing.T, script string, secrets gitops.Resolver) *runnerHarness {
	t.Helper()

	runs, c, _ := newRuns(t)
	binary, argsFile, _ := fakeBuildctl(t, script)
	builder, err := gitops.NewBuilder(gitops.BuilderConfig{
		Binary: binary, WorkDir: t.TempDir(), Socket: "unix:///tmp/test.sock",
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}

	h := &runnerHarness{
		runs: runs, deployer: newDeployer(), logDir: t.TempDir(),
		argsFile: argsFile, clock: c,
	}
	h.runner, err = gitops.NewRunner(gitops.RunnerConfig{
		Runs: runs, Syncer: gitops.NewSyncer(gitops.SyncerConfig{Secrets: secrets}),
		Builder: builder, Deployer: h.deployer, Secrets: secrets,
		LogDir: h.logDir, WorkDir: t.TempDir(), Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return h
}

// buildRepo is a repository with a service to build.
func buildRepo(t *testing.T) string {
	return repo(t, map[string]string{
		".kanea/web.hcl": `project "shop" {}`,
		"web/Dockerfile": "FROM scratch\n",
		"README.md":      "docs",
	})
}

func TestRunBuildsAndDeploysADigest(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)
	source := gitops.Source{URL: buildRepo(t), Branch: ""}

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: source,
		Build: gitops.BuildSpec{
			Context: "./web", Target: "registry.example.com/shop/web", Tag: "${GIT_SHA_SHORT}",
		},
		Trigger: gitops.TriggerPush, Deploy: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}
	if run.Commit == "" || run.Digest != "sha256:cafebabe" {
		t.Fatalf("run = %+v; want the commit and digest recorded", run)
	}

	// By digest, never by tag: §14 A08 wants the thing that runs to be the
	// thing that was built, and a tag is a moving pointer.
	deployed := h.deployer.ref("shop/web")
	if !strings.HasSuffix(deployed, "@sha256:cafebabe") {
		t.Fatalf("deployed %q, want a digest reference", deployed)
	}

	// Every step is recorded, in order.
	var names []string
	for _, step := range run.Steps {
		names = append(names, step.Name)
		if step.State != gitops.RunSucceeded {
			t.Errorf("step %s = %s", step.Name, step.State)
		}
	}
	want := []string{gitops.StepCheckout, gitops.StepBuild, gitops.StepDeploy}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("steps = %v, want %v", names, want)
	}
}

func TestTheTagExpandsTheCommit(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{
			Context: "./web", Target: "registry.example.com/shop/web", Tag: "${GIT_SHA_SHORT}",
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The built-in §6.1 documents. A tag that still reads "${GIT_SHA_SHORT}"
	// would push a literal — and every build would overwrite the last.
	short := run.Commit[:7]
	if !strings.HasSuffix(run.Image, ":"+short) {
		t.Fatalf("image = %q, want the tag expanded to %s", run.Image, short)
	}
	if got := argValue(args(t, h.argsFile), "--output"); !strings.Contains(got, short) {
		t.Errorf("--output = %q", got)
	}
}

func TestExpandTag(t *testing.T) {
	checkout := gitops.Checkout{Commit: "abcdef1234567890", Ref: "feature/login"}
	tests := []struct{ name, in, want string }{
		{"short sha", "${GIT_SHA_SHORT}", "abcdef1"},
		{"full sha", "${GIT_SHA}", "abcdef1234567890"},
		{"branch is sanitised", "${GIT_BRANCH}", "feature-login"},
		{"combination", "v2-${GIT_BRANCH}-${GIT_SHA_SHORT}", "v2-feature-login-abcdef1"},
		{"literal is untouched", "stable", "stable"},
		// Forgetting to write a tag is not a reason to push over `latest`.
		{"empty becomes the commit", "", "abcdef1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitops.ExpandTag(tc.in, checkout); got != tc.want {
				t.Fatalf("ExpandTag(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// A branch name is not a valid tag if it has a slash in it, and most
	// branches do. Rejecting would fail every feature-branch build.
	if got := gitops.ExpandTag("", gitops.Checkout{}); got != "latest" {
		t.Errorf("a build with no commit and no tag = %q, want latest", got)
	}
}

func TestGitIsNotInTheBuildContext(t *testing.T) {
	// §10.2's hygiene rule: a `COPY .` with `.git` present puts the whole
	// history — including any credential ever committed and later removed —
	// inside the published image.
	//
	// Asserted from inside the fake builder, at the moment the context is
	// handed over. Checking afterwards would prove nothing: the checkout is
	// removed when the run ends, so a stat would fail either way.
	script := `
prev=""
ctxdir=""
for a in "$@"; do
  case "$a" in
    context=*) ctxdir="${a#context=}" ;;
  esac
  if [ "$prev" = "--metadata-file" ]; then
    printf '{"containerimage.digest":"sha256:cafebabe"}' > "$a"
  fi
  prev="$a"
done
if [ -e "$ctxdir/.git" ]; then
  echo "FAIL: .git is in the build context" >&2
  exit 9
fi
exit 0
`
	h := newRunner(t, script, nil)

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web",
		// The context is the repository root, which is exactly where `.git`
		// would be.
		Source: gitops.Source{URL: repo(t, map[string]string{
			"Dockerfile":     "FROM scratch\n",
			".kanea/web.hcl": `project "shop" {}`,
		})},
		Build: gitops.BuildSpec{Target: "registry.example.com/shop/web"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v; the builder refused the context", run)
	}
}

func TestAFailedBuildIsRecordedNotReturnedAsAnError(t *testing.T) {
	h := newRunner(t, "echo 'ERROR: failed to solve' >&2\nexit 1\n", nil)

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build:  gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
		Deploy: true,
	})
	// A failed build is a result, not an error to swallow: the error return is
	// for a record that could not be written, which is the only kind a caller
	// can do nothing about.
	if err != nil {
		t.Fatalf("Run returned an error for a failed build: %v", err)
	}
	if run.State != gitops.RunFailed {
		t.Fatalf("state = %q, want failed", run.State)
	}
	if run.Error == "" {
		t.Error("a failed run carries no reason")
	}
	// And nothing was deployed.
	if h.deployer.ref("shop/web") != "" {
		t.Fatal("a failed build was deployed")
	}
	// The step that failed is named, so the dashboard can point at it.
	last := run.Steps[len(run.Steps)-1]
	if last.Name != gitops.StepBuild || last.State != gitops.RunFailed {
		t.Fatalf("steps = %+v; the build step is not marked failed", run.Steps)
	}
}

func TestAFailedCheckoutStopsBeforeBuilding(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web",
		Source: gitops.Source{URL: filepath.Join(t.TempDir(), "no-such-repo")},
		Build:  gitops.BuildSpec{Target: "registry.example.com/shop/web"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != gitops.RunFailed {
		t.Fatalf("state = %q, want failed", run.State)
	}
	if _, err := os.Stat(h.argsFile); err == nil {
		t.Error("the build ran despite the checkout failing")
	}
}

func TestABuildContextOutsideTheCheckoutIsRefused(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)

	// `context = "../../etc"` is a job spec reading the node's filesystem, and
	// it is refused rather than trusted to be absurd.
	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{Context: "../../etc", Target: "registry.example.com/shop/web"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != gitops.RunFailed {
		t.Fatalf("state = %q, want failed", run.State)
	}
	if !strings.Contains(run.Error, "outside the checkout") {
		t.Errorf("error = %q; it does not say why", run.Error)
	}
}

func TestABuildWithoutDeployChangesNothing(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build:   gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
		Trigger: gitops.TriggerManual,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.State != gitops.RunSucceeded || run.Digest == "" {
		t.Fatalf("run = %+v", run)
	}
	// `kanea build` without --deploy: the image exists, nothing moved.
	if h.deployer.ref("shop/web") != "" {
		t.Fatal("a build with Deploy=false changed desired state")
	}
	for _, step := range run.Steps {
		if step.Name == gitops.StepDeploy {
			t.Fatal("a deploy step was recorded for a build that did not deploy")
		}
	}
}

func TestAFailedDeployFailsTheRun(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)
	h.deployer.err = errors.New("store is busy")

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build:  gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
		Deploy: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The image was built and pushed, but it is not running. Reporting success
	// would tell an operator the deploy happened.
	if run.State != gitops.RunFailed {
		t.Fatalf("state = %q, want failed", run.State)
	}
	if run.Digest == "" {
		t.Error("the digest was lost; the image exists and the record should say so")
	}
}

func TestTheBuildLogIsWritten(t *testing.T) {
	h := newRunner(t, "echo '#1 [1/2] FROM scratch'\n"+writeMetadata, nil)

	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	body, err := os.ReadFile(h.runner.LogPath(run)) // #nosec G304 — a path the runner composed
	if err != nil {
		t.Fatalf("read build log: %v", err)
	}
	log := string(body)
	// Kanea's own annotations and the builder's output share one file, because
	// an operator reading a failed build wants both.
	for _, want := range []string{"cloning", "building", "FROM scratch", "pushed"} {
		if !strings.Contains(log, want) {
			t.Errorf("build log is missing %q:\n%s", want, log)
		}
	}
}

func TestALocalBuildNeedsNoGitSource(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)

	// What `kanea build` does from a developer's working copy: there is no
	// repository, the files are already here.
	run, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web",
		Build:   gitops.BuildSpec{Target: "registry.example.com/shop/web", Tag: "dev"},
		Trigger: gitops.TriggerManual,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// It fails, because an empty checkout has no recipe — but it fails as a
	// build, having got that far, rather than as a checkout error.
	if run.State != gitops.RunFailed {
		t.Fatalf("state = %q", run.State)
	}
	if !strings.Contains(run.Error, "Containerfile") {
		t.Errorf("error = %q, want the missing recipe named", run.Error)
	}
	if run.Steps[0].Name != gitops.StepCheckout || run.Steps[0].State != gitops.RunSucceeded {
		t.Errorf("the checkout step did not succeed for a source-less build: %+v", run.Steps)
	}
}

func TestRegistryCredentialsAreResolvedFromTheSecretsStore(t *testing.T) {
	secrets := &resolver{values: map[string][]byte{
		"secret:shop/registry": []byte(`{"auths":{"registry.example.com":{"auth":"x"}}}`),
	}}
	h := newRunner(t, writeMetadata, secrets)

	if _, err := h.runner.Run(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{
			Context: "./web", Target: "registry.example.com/shop/web",
			RegistryAuthRef: "secret:shop/registry",
		},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if secrets.asked == 0 {
		t.Fatal("the registry credential was never resolved")
	}
}

func TestNewRunnerRequiresItsCollaborators(t *testing.T) {
	runs, _, _ := newRuns(t)
	syncer := gitops.NewSyncer(gitops.SyncerConfig{})

	if _, err := gitops.NewRunner(gitops.RunnerConfig{Syncer: syncer}); err == nil {
		t.Error("a runner with no run store was accepted")
	}
	if _, err := gitops.NewRunner(gitops.RunnerConfig{Runs: runs}); err == nil {
		t.Error("a runner with no syncer was accepted")
	}
}

func newQueue(t *testing.T, h *runnerHarness) *gitops.Queue {
	t.Helper()
	q, err := gitops.NewQueue(gitops.QueueConfig{Runner: h.runner, Depth: 2, Now: h.clock.now})
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	return q
}

func TestQueueReturnsARunIDImmediately(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)
	q := newQueue(t, h)

	// A build takes minutes and an HTTP request must not: the caller needs an
	// id to follow logs by long before there is a result.
	run, err := q.Submit(context.Background(), gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if run.ID == "" || run.State != gitops.RunQueued {
		t.Fatalf("run = %+v, want a queued run with an id", run)
	}
	if q.Depth() != 1 {
		t.Fatalf("depth = %d, want 1", q.Depth())
	}
}

func TestQueueRunsSubmittedBuilds(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)
	q := newQueue(t, h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	run, err := q.Submit(ctx, gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	done := make(chan struct{})
	go func() { defer close(done); q.Run(ctx) }()

	waitFor(t, func() bool {
		got, err := h.runs.Get(context.Background(), "shop", "web", run.ID)
		return err == nil && got.State.Terminal()
	}, "the queued build to finish")

	got, err := h.runs.Get(context.Background(), "shop", "web", run.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != gitops.RunSucceeded || got.Digest == "" {
		t.Fatalf("run = %+v", got)
	}
	cancel()
	<-done
}

func TestAFullQueueIsRefusedAndRecorded(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)
	q := newQueue(t, h) // depth 2, and nothing is working it

	req := gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
	}
	for range 2 {
		if _, err := q.Submit(context.Background(), req); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}

	// Refused rather than blocked: a webhook handler that waits on a full
	// queue holds a connection the provider will time out.
	run, err := q.Submit(context.Background(), req)
	if !errors.Is(err, gitops.ErrQueueFull) {
		t.Fatalf("err = %v, want ErrQueueFull", err)
	}
	// And the record says so, rather than sitting at "queued" for a build
	// nothing will ever pick up.
	if run.State != gitops.RunCancelled {
		t.Fatalf("state = %q, want cancelled", run.State)
	}
}

func TestShutdownCancelsWhatIsStillQueued(t *testing.T) {
	h := newRunner(t, writeMetadata, nil)
	q := newQueue(t, h)
	ctx, cancel := context.WithCancel(context.Background())

	req := gitops.Request{
		Project: "shop", Service: "web", Source: gitops.Source{URL: buildRepo(t)},
		Build: gitops.BuildSpec{Context: "./web", Target: "registry.example.com/shop/web"},
	}
	run, err := q.Submit(ctx, req)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// The daemon stops before the worker ever starts. A queued run nothing will
	// pick up would otherwise sit at "queued" forever, and after a restart an
	// operator would see a build that never happened with no sign it never will.
	cancel()
	q.Run(ctx)

	got, err := h.runs.Get(context.Background(), "shop", "web", run.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != gitops.RunCancelled {
		t.Fatalf("state = %q, want cancelled", got.State)
	}
	if got.Error == "" {
		t.Error("a cancelled run gives no reason")
	}
}

// waitFor polls a condition with a deadline.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
