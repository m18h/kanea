package gitops

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The BuildKit runner (PRD §10.2).
//
// BuildKit is the only build driver, chosen in M0 spike ④ because it is the
// only validated configuration needing **no elevated privilege anywhere**:
// `buildkitd` runs as an unprivileged non-root host user under rootlesskit,
// and this drives it over its unix socket with `buildctl`. Nothing in the build
// path is a privileged container, so §14's workload hardening defaults are
// untouched — that property is what decided the driver.
//
// Everything here that looks fiddly comes from the spike's findings:
//
//   - `--opt filename=` is passed **explicitly**, because BuildKit's frontend
//     defaults to the literal name `Dockerfile` and Kanea accepts
//     `Containerfile` too, with Containerfile winning when both exist;
//   - registry credentials are materialised as a `config.json` outside the
//     build context, because a credential in the context is a credential in
//     the image;
//   - the digest comes from `--metadata-file`, since parsing it out of the
//     progress output would be parsing a UI.

// DefaultBuildkitSocket is where the provisioned daemon listens: in its own
// home under the data directory, *not* under `/run` — rootlesskit copy-ups
// `/run` into a namespace-private tmpfs, so a socket there is invisible to
// every client outside the namespace (M0 spike ④). Root-reachable only, by
// the unit's 0750 home.
//
// Must equal provision.BuildkitSocket over the default layout, pinned by
// test: the previous value here predated the installer, named a path under
// `/run` that nothing creates, and left doctor warning about a healthy
// daemon while kanead dialed a socket that could never answer.
const DefaultBuildkitSocket = "unix:///var/lib/kanea/buildkit/run/buildkitd.sock"

// Build timeouts.
const (
	// DefaultBuildTimeout bounds one build. Long, because a cold build of a
	// large image legitimately takes minutes — the spike measured 22.8 s cold
	// and 546 ms warm for a small one — and short enough that a wedged build
	// does not hold the queue forever.
	DefaultBuildTimeout = 30 * time.Minute
	// probeTimeout bounds the startup check.
	probeTimeout = 10 * time.Second
)

// Recipe file names, in precedence order (§10.2, the Podman convention).
var recipeNames = []string{"Containerfile", "Dockerfile"}

// BuildRequest is one build.
type BuildRequest struct {
	// ContextDir is the directory to build from. It must already exist; the
	// runner does not fetch it.
	ContextDir string
	// Recipe overrides detection and may name either file.
	Recipe string
	// Target is the image reference to push, without a tag.
	Target string
	// Tag is the tag to push it under.
	Tag string
	// CacheRepo enables registry-backed layer caching when set.
	CacheRepo string
	// RegistryAuth is a docker `config.json`, resolved from the secrets store.
	// Empty means an anonymous push, which only works against a registry that
	// allows one.
	RegistryAuth []byte
	// Insecure allows a plain-HTTP registry. For a node-local registry; the
	// flag exists because the spike needed it and real deployments should not.
	Insecure bool
}

// Reference is the full image reference this request pushes.
func (r BuildRequest) Reference() string {
	if r.Tag == "" {
		return r.Target
	}
	return r.Target + ":" + r.Tag
}

// BuildResult is what a build produced.
type BuildResult struct {
	// Digest pins the image (§14 A08). The deploy uses this rather than the
	// tag, because a tag is a moving pointer.
	Digest string
	// Reference is the image reference that was pushed.
	Reference string
	Duration  time.Duration
}

// BuilderConfig configures the runner.
type BuilderConfig struct {
	// Socket is the buildkitd address. Empty means the default.
	Socket string
	// Binary is the buildctl executable. Empty means "buildctl" on PATH.
	Binary string
	// WorkDir is where per-build scratch — the metadata file, the registry
	// credentials — is written. Each build gets a subdirectory, removed after.
	WorkDir string
	// Timeout bounds one build.
	Timeout time.Duration
	Logger  *slog.Logger
	Now     func() time.Time
}

// Builder runs builds against the rootless buildkitd.
//
// One build at a time. §10.2 makes isolation collective rather than per build —
// the daemon carries one systemd cap and `--oci-max-parallelism` — so a second
// concurrent build would not get its own budget, it would share the first's and
// make both slower and less predictable.
type Builder struct {
	socket  string
	binary  string
	workDir string
	timeout time.Duration
	log     *slog.Logger
	now     func() time.Time

	// mu serialises builds. The queue is in the pipeline runner above this.
	mu sync.Mutex
}

// Errors a build distinguishes.
var (
	// ErrNoRecipe means neither Containerfile nor Dockerfile is in the context.
	ErrNoRecipe = errors.New("gitops: no Containerfile or Dockerfile in the build context")
	// ErrBuilderUnavailable means buildkitd is not reachable.
	ErrBuilderUnavailable = errors.New("gitops: buildkitd is not reachable")
	// ErrBuildFailed means the build itself failed. The log has the reason.
	ErrBuildFailed = errors.New("gitops: build failed")
)

// NewBuilder builds the runner.
func NewBuilder(cfg BuilderConfig) (*Builder, error) {
	if cfg.WorkDir == "" {
		return nil, errors.New("gitops: a build work directory is required")
	}
	if cfg.Socket == "" {
		cfg.Socket = DefaultBuildkitSocket
	}
	if cfg.Binary == "" {
		cfg.Binary = "buildctl"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultBuildTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return nil, fmt.Errorf("gitops: build work dir: %w", err)
	}
	return &Builder{
		socket: cfg.Socket, binary: cfg.Binary, workDir: cfg.WorkDir,
		timeout: cfg.Timeout, log: cfg.Logger, now: cfg.Now,
	}, nil
}

// Probe reports whether buildkitd is reachable.
//
// Called at startup so a node with no builder says so once, in front of the
// operator, rather than failing the first push that arrives an hour later.
func (b *Builder) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, b.binary, "--addr", b.socket, "debug", "workers") // #nosec G204 — operator-configured binary and socket
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w at %s: %w (%s)",
			ErrBuilderUnavailable, b.socket, err, firstLine(string(out)))
	}
	return nil
}

// Build runs one build and streams its output to logs.
//
// The writer receives buildctl's progress verbatim. It is the build log the
// dashboard streams and the CLI prints, and it goes to a file rather than the
// Store for the reason §17 gives about workload logs: it is unbounded output
// that nobody queries.
func (b *Builder) Build(ctx context.Context, req BuildRequest, logs io.Writer) (BuildResult, error) {
	if req.ContextDir == "" {
		return BuildResult{}, errors.New("gitops: a build needs a context directory")
	}
	if req.Target == "" {
		return BuildResult{}, errors.New("gitops: a build needs a target image")
	}

	recipe, err := DetectRecipe(req.ContextDir, req.Recipe)
	if err != nil {
		return BuildResult{}, err
	}

	// One at a time: §10.2's isolation is collective, so a second concurrent
	// build shares the first's budget rather than getting its own.
	b.mu.Lock()
	defer b.mu.Unlock()

	scratch, err := os.MkdirTemp(b.workDir, "build-")
	if err != nil {
		return BuildResult{}, fmt.Errorf("gitops: build scratch: %w", err)
	}
	defer func() {
		// The scratch holds registry credentials. Removing it is not tidiness.
		if err := os.RemoveAll(scratch); err != nil {
			b.log.Error("cannot remove build scratch; it holds registry credentials",
				"path", scratch, "error", err)
		}
	}()

	env, err := b.registryAuth(scratch, req.RegistryAuth)
	if err != nil {
		return BuildResult{}, err
	}

	metadata := filepath.Join(scratch, "metadata.json")
	args := buildArgs(req, recipe, metadata)

	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	started := b.now()
	cmd := exec.CommandContext(ctx, b.binary, append([]string{"--addr", b.socket}, args...)...) // #nosec G204 — operator-configured binary; every argument is built here, never interpolated from a spec string
	cmd.Env = env
	// Progress goes to stderr and the frontend's own output to stdout; a build
	// log that dropped either would be missing exactly the part someone is
	// reading it for.
	cmd.Stdout = logs
	cmd.Stderr = logs

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return BuildResult{}, fmt.Errorf("%w: timed out after %s", ErrBuildFailed, b.timeout)
		}
		return BuildResult{}, fmt.Errorf("%w: %w", ErrBuildFailed, err)
	}

	digest, err := readDigest(metadata)
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Digest:    digest,
		Reference: req.Reference(),
		Duration:  b.now().Sub(started),
	}, nil
}

// registryAuth materialises the push credentials outside the build context.
//
// Outside, and this is the point: a `config.json` inside the context is a
// credential in the image, since a `COPY .` takes it along. §10.2's build
// hygiene rule exists because that mistake is easy and permanent.
func (b *Builder) registryAuth(scratch string, config []byte) ([]string, error) {
	env := os.Environ()
	if len(config) == 0 {
		return env, nil
	}

	dir := filepath.Join(scratch, "docker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("gitops: registry auth dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), config, 0o600); err != nil {
		return nil, fmt.Errorf("gitops: write registry auth: %w", err)
	}
	return append(env, "DOCKER_CONFIG="+dir), nil
}

// buildArgs is the invocation M0 spike ④ validated.
func buildArgs(req BuildRequest, recipe, metadataFile string) []string {
	output := fmt.Sprintf("type=image,name=%s,push=true", req.Reference())
	if req.Insecure {
		output += ",registry.insecure=true"
	}

	args := []string{
		"build",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + req.ContextDir,
		"--local", "dockerfile=" + req.ContextDir,
		// Explicit, always: the frontend defaults to the literal "Dockerfile",
		// so a Containerfile build silently fails to find its recipe without
		// this (M0 spike ④).
		"--opt", "filename=" + recipe,
		"--output", output,
		"--metadata-file", metadataFile,
		// Plain progress, because this is written to a log file and read as
		// text; the default renders a terminal UI with cursor movement in it.
		"--progress", "plain",
	}

	if req.CacheRepo != "" {
		exportCache := "type=registry,ref=" + req.CacheRepo + ",mode=max"
		importCache := "type=registry,ref=" + req.CacheRepo
		if req.Insecure {
			exportCache += ",registry.insecure=true"
			importCache += ",registry.insecure=true"
		}
		args = append(args, "--export-cache", exportCache, "--import-cache", importCache)
	}
	return args
}

// DetectRecipe picks the build recipe (§10.2).
//
// Containerfile wins when both are present — the Podman/buildah convention the
// PRD adopts — and an explicit override may name either. The result is passed
// to `--opt filename=` because BuildKit would otherwise assume `Dockerfile`.
func DetectRecipe(contextDir, override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(filepath.Join(contextDir, override)); err != nil {
			return "", fmt.Errorf("gitops: build.dockerfile names %q, which is not in the context: %w",
				override, err)
		}
		return override, nil
	}
	for _, name := range recipeNames {
		if _, err := os.Stat(filepath.Join(contextDir, name)); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoRecipe, contextDir)
}

// buildMetadata is the slice of buildctl's metadata file Kanea reads.
type buildMetadata struct {
	Digest string `json:"containerimage.digest"`
}

// readDigest pulls the image digest out of the metadata file.
//
// From the file rather than from the progress output: the output is a UI, and
// a digest scraped from it would break the first time BuildKit changed a line.
func readDigest(path string) (string, error) {
	body, err := os.ReadFile(path) // #nosec G304 — a path this process just created
	if err != nil {
		return "", fmt.Errorf("gitops: read build metadata: %w", err)
	}
	var metadata buildMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", fmt.Errorf("gitops: parse build metadata: %w", err)
	}
	if metadata.Digest == "" {
		// The build reported success without producing a digest, which means
		// nothing was pushed. Deploying the tag anyway would deploy whatever
		// that tag pointed at before.
		return "", errors.New("gitops: the build produced no image digest")
	}
	return metadata.Digest, nil
}

// firstLine is the first line of a command's output, for an error message.
func firstLine(out string) string {
	scanner := bufio.NewScanner(strings.NewReader(out))
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}
