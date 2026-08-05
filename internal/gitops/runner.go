package gitops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// The pipeline runner: one build, start to finish (PRD §10.2).
//
// It owns the *sequence* — check out, build, deploy — and nothing else. The
// checkout is the syncer's, the build is the builder's, and the deploy is the
// reconciler's by way of a seam, because an image reference written into
// desired state is a state mutation and this package does not own state.
//
// Every step is recorded on the run as it happens rather than at the end. A
// build that hangs for ten minutes should show "building, 10m" in the
// dashboard, not "queued" — and a daemon killed mid-build should leave a
// record that says where it got to.

// Deployer applies a built image to a service's desired state.
//
// A seam rather than a Store handle: pinning a digest is a change to what
// runs, and the reconciler owns that. It also means a build can be run with
// deployment turned off — which is what `kanea build` without `--deploy` is.
type Deployer interface {
	// Deploy pins an image reference on a service. The reference carries a
	// digest, never a tag: §14 A08 wants the thing that runs to be the thing
	// that was built, and a tag is a moving pointer.
	Deploy(ctx context.Context, project, service, imageRef string) error
}

// BuildSpec is a service's `build` block, as the job spec declares it (§6.1).
type BuildSpec struct {
	// Context is the directory within the repository to build from.
	Context string
	// Dockerfile overrides recipe detection.
	Dockerfile string
	// Target is the image repository to push to.
	Target string
	// Tag may contain the built-in variables — see ExpandTag.
	Tag string
	// CacheRepo enables registry-backed layer caching.
	CacheRepo string
	// RegistryAuthRef is a `secret:` reference to a docker config.json.
	RegistryAuthRef string
}

// Request is one pipeline run to execute.
type Request struct {
	Project string
	Service string
	Source  Source
	Build   BuildSpec

	Trigger     Trigger
	TriggeredBy string
	// Deploy pins the produced digest on the service when the build succeeds.
	Deploy bool
	// Insecure allows a plain-HTTP registry.
	Insecure bool
}

// RunnerConfig configures the pipeline runner.
type RunnerConfig struct {
	Runs    *Runs
	Syncer  *Syncer
	Builder *Builder
	// Deployer is optional: without one, a successful build records its digest
	// and changes nothing.
	Deployer Deployer
	// Secrets resolves the registry credential.
	Secrets Resolver
	// LogDir is where build logs are written, one file per run.
	LogDir string
	// WorkDir is where checkouts are materialised.
	WorkDir string
	Logger  *slog.Logger
	Now     func() time.Time
}

// Runner executes pipeline runs.
type Runner struct {
	runs     *Runs
	syncer   *Syncer
	builder  *Builder
	deployer Deployer
	secrets  Resolver
	logDir   string
	workDir  string
	log      *slog.Logger
	now      func() time.Time
}

// NewRunner builds the pipeline runner.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	switch {
	case cfg.Runs == nil:
		return nil, errors.New("gitops: a run store is required")
	case cfg.Syncer == nil:
		return nil, errors.New("gitops: a syncer is required")
	case cfg.Builder == nil:
		return nil, errors.New("gitops: a builder is required")
	case cfg.LogDir == "":
		return nil, errors.New("gitops: a build log directory is required")
	case cfg.WorkDir == "":
		return nil, errors.New("gitops: a checkout directory is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	for _, dir := range []string{cfg.LogDir, cfg.WorkDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("gitops: %s: %w", dir, err)
		}
	}
	return &Runner{
		runs: cfg.Runs, syncer: cfg.Syncer, builder: cfg.Builder,
		deployer: cfg.Deployer, secrets: cfg.Secrets,
		logDir: cfg.LogDir, workDir: cfg.WorkDir, log: cfg.Logger, now: cfg.Now,
	}, nil
}

// LogPath is where a run's build log lives.
//
// Files, not the Store: a verbose build is megabytes of output nobody queries,
// and §17's reasoning about workload logs applies unchanged.
func (r *Runner) LogPath(run Run) string {
	return filepath.Join(r.logDir, run.Project+"-"+run.Service+"-"+ShortID(run.ID)+".log")
}

// Run executes one pipeline run to completion.
//
// It returns the final run record whether the build succeeded or not: a failed
// build is a result, not an error to swallow. The error return is for the cases
// where the *record itself* could not be written, which is the only kind of
// failure a caller can do nothing about.
func (r *Runner) Run(ctx context.Context, req Request) (Run, error) {
	run, err := r.Queue(ctx, req)
	if err != nil {
		return Run{}, err
	}
	return r.Execute(ctx, run, req)
}

// Queue records a run as queued without starting it.
//
// Separate from Execute so a caller can be told *which* run it just asked for
// before the build begins: a build takes minutes, and `kanea build` needs an id
// to follow logs by long before there is a result to report.
func (r *Runner) Queue(ctx context.Context, req Request) (Run, error) {
	return r.runs.Create(ctx, Run{
		Project: req.Project, Service: req.Service,
		Trigger: req.Trigger, TriggeredBy: req.TriggeredBy,
		Ref: req.Source.Branch,
	})
}

// Execute carries out a queued run.
func (r *Runner) Execute(ctx context.Context, run Run, req Request) (Run, error) {
	// 0600: kanead is the only reader. The CLI and the dashboard both reach
	// build logs through the API, so there is no group that needs this file.
	logs, err := os.OpenFile(r.LogPath(run), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 — a path this runner composed
	if err != nil {
		return r.fail(ctx, run, fmt.Errorf("open build log: %w", err))
	}
	defer func() {
		if cerr := logs.Close(); cerr != nil {
			r.log.Warn("close build log", "run", run.ID, "error", cerr)
		}
	}()

	run.Start(r.now())
	if err := r.runs.Update(ctx, run); err != nil {
		return run, err
	}

	checkout, dir, err := r.checkout(ctx, &run, req, logs)
	if err != nil {
		return r.fail(ctx, run, err)
	}
	defer func() {
		// The checkout is source code, and on a shared node that is worth
		// removing promptly rather than at the next sweep.
		if rerr := os.RemoveAll(dir); rerr != nil {
			r.log.Warn("cannot remove build checkout", "path", dir, "error", rerr)
		}
	}()

	run.Commit = checkout.Commit
	if checkout.Ref != "" {
		run.Ref = checkout.Ref
	}

	result, err := r.build(ctx, &run, req, dir, checkout, logs)
	if err != nil {
		return r.fail(ctx, run, err)
	}
	run.Image = result.Reference
	run.Digest = result.Digest

	if req.Deploy {
		if err := r.deploy(ctx, &run, req, result); err != nil {
			return r.fail(ctx, run, err)
		}
	}

	run.Finish(r.now(), nil)
	if err := r.runs.Update(ctx, run); err != nil {
		return run, err
	}
	r.log.Info("build succeeded",
		"service", run.ServiceKey(), "run", ShortID(run.ID),
		"commit", shortCommit(run.Commit), "digest", run.Digest,
		"duration", run.Duration(r.now()).Round(time.Millisecond))
	return run, nil
}

// checkout materialises the source into a working tree.
func (r *Runner) checkout(ctx context.Context, run *Run, req Request, logs io.Writer) (Checkout, string, error) {
	run.BeginStep(StepCheckout, r.now())
	if err := r.runs.Update(ctx, *run); err != nil {
		return Checkout{}, "", err
	}

	dir, err := os.MkdirTemp(r.workDir, "checkout-")
	if err != nil {
		return Checkout{}, "", fmt.Errorf("checkout scratch: %w", err)
	}

	// A local build with no git source: the caller already has the files, and
	// `build.context` is a path on this node. That is what `kanea build` does
	// from a developer's working copy.
	if req.Source.URL == "" {
		run.EndStep(StepCheckout, r.now(), nil)
		return Checkout{}, dir, r.runs.Update(ctx, *run)
	}

	note(logs, "==> cloning %s\n", req.Source.URL)
	checkout, err := r.syncer.Materialize(ctx, req.Source, dir)
	run.EndStep(StepCheckout, r.now(), err)
	if uerr := r.runs.Update(ctx, *run); uerr != nil {
		return Checkout{}, dir, uerr
	}
	if err != nil {
		return Checkout{}, dir, err
	}
	note(logs, "==> at %s (%s)\n", shortCommit(checkout.Commit), checkout.Message)
	return checkout, dir, nil
}

// build runs the image build.
func (r *Runner) build(
	ctx context.Context, run *Run, req Request, dir string, checkout Checkout, logs io.Writer,
) (BuildResult, error) {
	run.BeginStep(StepBuild, r.now())
	if err := r.runs.Update(ctx, *run); err != nil {
		return BuildResult{}, err
	}

	auth, err := r.registryAuth(ctx, req.Build.RegistryAuthRef)
	if err != nil {
		run.EndStep(StepBuild, r.now(), err)
		return BuildResult{}, err
	}

	contextDir := dir
	if req.Build.Context != "" {
		contextDir = filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(req.Build.Context, "./")))
	}
	// A context outside the checkout would be a job spec reading the node's
	// filesystem: `context = "../../etc"` is the shape, and it is refused here
	// rather than trusted to be absurd.
	if err := withinDir(dir, contextDir); err != nil {
		run.EndStep(StepBuild, r.now(), err)
		return BuildResult{}, err
	}

	tag := ExpandTag(req.Build.Tag, checkout)
	note(logs, "==> building %s:%s from %s\n", req.Build.Target, tag, req.Build.Context)

	result, err := r.builder.Build(ctx, BuildRequest{
		ContextDir: contextDir, Recipe: req.Build.Dockerfile,
		Target: req.Build.Target, Tag: tag, CacheRepo: req.Build.CacheRepo,
		RegistryAuth: auth, Insecure: req.Insecure,
	}, logs)

	run.EndStep(StepBuild, r.now(), err)
	if uerr := r.runs.Update(ctx, *run); uerr != nil {
		return BuildResult{}, uerr
	}
	if err != nil {
		return BuildResult{}, err
	}
	note(logs, "==> pushed %s\n", result.Digest)
	return result, nil
}

// deploy pins the produced digest on the service.
func (r *Runner) deploy(ctx context.Context, run *Run, req Request, result BuildResult) error {
	if r.deployer == nil {
		return errors.New("gitops: this build asked to deploy but no deployer is configured")
	}

	run.BeginStep(StepDeploy, r.now())
	if err := r.runs.Update(ctx, *run); err != nil {
		return err
	}

	// By digest, never by tag. A tag is a moving pointer, and §14 A08 wants
	// the thing that runs to be the thing that was built.
	ref := req.Build.Target + "@" + result.Digest
	err := r.deployer.Deploy(ctx, req.Project, req.Service, ref)
	run.EndStep(StepDeploy, r.now(), err)
	if uerr := r.runs.Update(ctx, *run); uerr != nil {
		return uerr
	}
	return err
}

// registryAuth resolves the push credentials.
func (r *Runner) registryAuth(ctx context.Context, ref string) ([]byte, error) {
	if ref == "" {
		return nil, nil
	}
	if r.secrets == nil {
		return nil, fmt.Errorf("gitops: %s is referenced but no secrets store is configured", ref)
	}
	value, err := r.secrets.Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("gitops: resolve %s: %w", ref, err)
	}
	return value, nil
}

// fail records a run's failure and returns it.
//
// The record is written before the error is returned, so a run that failed is
// visible in the dashboard whether or not the caller does anything with the
// error.
func (r *Runner) fail(ctx context.Context, run Run, cause error) (Run, error) {
	run.Finish(r.now(), cause)
	if err := r.runs.Update(ctx, run); err != nil {
		return run, err
	}
	r.log.Warn("build failed",
		"service", run.ServiceKey(), "run", ShortID(run.ID), "error", cause)
	return run, nil
}

// note writes Kanea's own annotations into a build log.
//
// A failed write is not actionable and must not fail a build: this is
// commentary around output the builder writes to the same file directly, and
// losing a line of it is nothing next to losing the build. It is counted so
// the condition is visible rather than silent.
func note(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		logWriteFailures.Add(1)
	}
}

// logWriteFailures counts annotations that could not be written.
var logWriteFailures atomic.Int64

// LogWriteFailures reports how many build-log annotations were lost.
func LogWriteFailures() int64 { return logWriteFailures.Load() }

// ExpandTag substitutes the built-in variables §6.1 documents.
//
// An empty tag becomes the short commit, because that is what a deploy wants
// and forgetting to write it is not a reason to push over `latest`.
func ExpandTag(tag string, checkout Checkout) string {
	short := shortCommit(checkout.Commit)
	if tag == "" {
		if short == "" {
			return "latest"
		}
		return short
	}
	replacements := map[string]string{
		"${GIT_SHA_SHORT}": short,
		"${GIT_SHA}":       checkout.Commit,
		"${GIT_BRANCH}":    sanitizeTag(checkout.Ref),
	}
	for name, value := range replacements {
		tag = strings.ReplaceAll(tag, name, value)
	}
	if tag == "" {
		return "latest"
	}
	return tag
}

// sanitizeTag makes a branch name usable as an image tag.
//
// A tag may not contain a slash, and `feature/login` is an ordinary branch
// name. Replacing rather than rejecting: the alternative is a build that fails
// for every branch with a slash in it, which is most of them.
func sanitizeTag(ref string) string {
	replacer := strings.NewReplacer("/", "-", " ", "-", "~", "-", "^", "-", ":", "-")
	return strings.Trim(replacer.Replace(ref), "-.")
}

// shortCommit is the conventional seven-character abbreviation.
func shortCommit(sha string) string {
	if len(sha) < 7 {
		return sha
	}
	return sha[:7]
}

// withinDir reports whether target is inside root.
func withinDir(root, target string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("gitops: build context %q is outside the checkout", target)
	}
	return nil
}
