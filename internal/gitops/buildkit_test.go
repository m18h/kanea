package gitops_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
)

// fakeBuildctl writes a stand-in for buildctl that records its argv and
// environment, and produces whatever metadata the test asks for.
//
// A fake binary rather than an interface seam: what is under test is the exact
// invocation M0 spike ④ validated (`--opt filename=`, the output string, the
// metadata file) and an interface would let that drift while the tests stayed
// green. This runs the real exec path, so the argv asserted below is the argv
// buildkitd would receive.
func fakeBuildctl(t *testing.T, script string) (binary, argsFile, envFile string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "buildctl")
	argsFile = filepath.Join(dir, "args")
	envFile = filepath.Join(dir, "env")

	body := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + argsFile + "\n" +
		"env > " + envFile + "\n" +
		script + "\n"
	if err := os.WriteFile(binary, []byte(body), 0o700); err != nil { // #nosec G306; an executable a test runs
		t.Fatalf("write fake buildctl: %v", err)
	}
	return binary, argsFile, envFile
}

// writeMetadata is the script fragment a successful fake build runs: find the
// --metadata-file argument and write a digest into it.
const writeMetadata = `
prev=""
for a in "$@"; do
  if [ "$prev" = "--metadata-file" ]; then
    printf '{"containerimage.digest":"sha256:cafebabe"}' > "$a"
  fi
  prev="$a"
done
echo "#1 [internal] load build definition"
exit 0
`

// buildContext writes a build context with the given files.
func buildContext(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func newBuilder(t *testing.T, binary string) *gitops.Builder {
	t.Helper()
	b, err := gitops.NewBuilder(gitops.BuilderConfig{
		Binary: binary, WorkDir: t.TempDir(), Socket: "unix:///tmp/test.sock",
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

// args reads the recorded argv.
func args(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304; a path this test created
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
}

// argValue returns the value following a flag.
func argValue(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func TestBuildPassesTheInvocationTheSpikeValidated(t *testing.T) {
	binary, argsFile, _ := fakeBuildctl(t, writeMetadata)
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	result, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "abc123",
	}, io.Discard)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.Digest != "sha256:cafebabe" {
		t.Errorf("digest = %q", result.Digest)
	}
	if result.Reference != "registry.example.com/shop/web:abc123" {
		t.Errorf("reference = %q", result.Reference)
	}

	argv := args(t, argsFile)
	// The findings from M0 spike ④, each of which is a silent failure if it
	// regresses.
	if argValue(argv, "--frontend") != "dockerfile.v0" {
		t.Errorf("frontend = %q", argValue(argv, "--frontend"))
	}
	if argValue(argv, "--opt") != "filename=Dockerfile" {
		t.Errorf("--opt = %q; the frontend needs the recipe named explicitly",
			argValue(argv, "--opt"))
	}
	if got := argValue(argv, "--output"); !strings.Contains(got, "push=true") ||
		!strings.Contains(got, "name=registry.example.com/shop/web:abc123") {
		t.Errorf("--output = %q", got)
	}
	if argValue(argv, "--metadata-file") == "" {
		t.Error("no --metadata-file; the digest would have to be scraped from a UI")
	}
	if argValue(argv, "--progress") != "plain" {
		t.Errorf("--progress = %q; the default renders a terminal UI into a log file",
			argValue(argv, "--progress"))
	}
	if argValue(argv, "--addr") == "" {
		t.Error("no --addr; the daemon socket is not the default one")
	}
}

func TestContainerfileWinsOverDockerfile(t *testing.T) {
	binary, argsFile, _ := fakeBuildctl(t, writeMetadata)
	ctx := buildContext(t, map[string]string{
		"Containerfile": "FROM scratch\n",
		"Dockerfile":    "FROM scratch\n",
	})

	if _, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
	}, io.Discard); err != nil {
		t.Fatalf("Build: %v", err)
	}
	// The Podman convention §10.2 adopts. Getting this backwards builds the
	// wrong recipe without saying so.
	if got := argValue(args(t, argsFile), "--opt"); got != "filename=Containerfile" {
		t.Fatalf("--opt = %q, want Containerfile to win", got)
	}
}

func TestRecipeDetection(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		override string
		want     string
		wantErr  bool
	}{
		{
			name:  "dockerfile alone",
			files: map[string]string{"Dockerfile": ""},
			want:  "Dockerfile",
		},
		{
			name:  "containerfile alone",
			files: map[string]string{"Containerfile": ""},
			want:  "Containerfile",
		},
		{
			name:  "containerfile wins",
			files: map[string]string{"Containerfile": "", "Dockerfile": ""},
			want:  "Containerfile",
		},
		{
			name:     "override may name either",
			files:    map[string]string{"Dockerfile": "", "Containerfile": "", "build.docker": ""},
			override: "build.docker",
			want:     "build.docker",
		},
		{
			name:    "neither present",
			files:   map[string]string{"main.go": ""},
			wantErr: true,
		},
		{
			name:     "override names a file that is not there",
			files:    map[string]string{"Dockerfile": ""},
			override: "Containerfile",
			wantErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := buildContext(t, tc.files)
			got, err := gitops.DetectRecipe(dir, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("DetectRecipe = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DetectRecipe: %v", err)
			}
			if got != tc.want {
				t.Fatalf("DetectRecipe = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestASymlinkedRecipeIsRefused(t *testing.T) {
	// The stat here runs as root on the host, before BuildKit's in-context
	// link rebasing ever applies: following a recipe symlink makes any host
	// path a file-existence oracle, and on a reader without rebasing, a read
	// primitive. Lstat, and refuse.
	dir := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	if err := os.Symlink("/etc/shadow", filepath.Join(dir, "Containerfile")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Auto-detect skips the link rather than selecting it: the real
	// Dockerfile still wins.
	got, err := gitops.DetectRecipe(dir, "")
	if err != nil || got != "Dockerfile" {
		t.Fatalf("DetectRecipe = %q, %v; want the real Dockerfile", got, err)
	}

	// An override naming the link is refused by name.
	if _, err := gitops.DetectRecipe(dir, "Containerfile"); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("DetectRecipe(override) = %v; want the symlink refusal", err)
	}
}

func TestBuildWithoutARecipeFailsBeforeInvokingBuildkit(t *testing.T) {
	binary, argsFile, _ := fakeBuildctl(t, writeMetadata)
	ctx := buildContext(t, map[string]string{"main.go": "package main"})

	_, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web",
	}, io.Discard)
	if !errors.Is(err, gitops.ErrNoRecipe) {
		t.Fatalf("err = %v, want ErrNoRecipe", err)
	}
	// Caught here rather than by buildkitd, so the message names the context
	// instead of quoting a frontend error.
	if _, statErr := os.Stat(argsFile); statErr == nil {
		t.Error("buildctl was invoked for a context with no recipe")
	}
}

func TestRegistryCredentialsGoOutsideTheContext(t *testing.T) {
	binary, _, envFile := fakeBuildctl(t, writeMetadata)
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	if _, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
		RegistryAuth: []byte(`{"auths":{"registry.example.com":{"auth":"c2VjcmV0"}}}`),
	}, io.Discard); err != nil {
		t.Fatalf("Build: %v", err)
	}

	env, err := os.ReadFile(envFile) // #nosec G304; a path this test created
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	dockerConfig := ""
	for line := range strings.SplitSeq(string(env), "\n") {
		if after, ok := strings.CutPrefix(line, "DOCKER_CONFIG="); ok {
			dockerConfig = after
		}
	}
	if dockerConfig == "" {
		t.Fatal("no DOCKER_CONFIG; the push would be anonymous")
	}
	// A config.json inside the context is a credential in the image, because
	// `COPY .` takes it along. §10.2's build hygiene rule exists for this.
	if strings.HasPrefix(dockerConfig, ctx) {
		t.Fatalf("registry credentials were written inside the build context: %s", dockerConfig)
	}
	if _, err := os.Stat(filepath.Join(ctx, "config.json")); err == nil {
		t.Fatal("a config.json was left in the build context")
	}
}

func TestBuildScratchIsRemoved(t *testing.T) {
	binary, _, _ := fakeBuildctl(t, writeMetadata)
	workDir := t.TempDir()
	builder, err := gitops.NewBuilder(gitops.BuilderConfig{
		Binary: binary, WorkDir: workDir, Socket: "unix:///tmp/test.sock",
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	if _, err := builder.Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
		RegistryAuth: []byte(`{"auths":{}}`),
	}, io.Discard); err != nil {
		t.Fatalf("Build: %v", err)
	}

	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatalf("read work dir: %v", err)
	}
	// The scratch held registry credentials. Removing it is not tidiness.
	if len(entries) != 0 {
		t.Fatalf("build scratch survived: %v", entries)
	}
}

func TestCacheRepoAddsBothDirections(t *testing.T) {
	binary, argsFile, _ := fakeBuildctl(t, writeMetadata)
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	if _, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
		CacheRepo: "registry.example.com/shop/web-cache",
	}, io.Discard); err != nil {
		t.Fatalf("Build: %v", err)
	}

	argv := args(t, argsFile)
	// Export without import is a cache nobody reads; import without export is
	// one nobody fills. The spike measured 22.8 s cold against 546 ms warm,
	// which is the whole value of getting both.
	if !strings.Contains(argValue(argv, "--export-cache"), "web-cache") {
		t.Error("no --export-cache")
	}
	if !strings.Contains(argValue(argv, "--import-cache"), "web-cache") {
		t.Error("no --import-cache")
	}
}

func TestBuildFailureIsReported(t *testing.T) {
	binary, _, _ := fakeBuildctl(t, "echo 'ERROR: failed to solve' >&2\nexit 1\n")
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	var logs strings.Builder
	_, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
	}, &logs)
	if !errors.Is(err, gitops.ErrBuildFailed) {
		t.Fatalf("err = %v, want ErrBuildFailed", err)
	}
	// The reason lives in the log the operator reads, not in the error string.
	if !strings.Contains(logs.String(), "failed to solve") {
		t.Errorf("the build output was not streamed: %q", logs.String())
	}
}

func TestASuccessfulBuildWithNoDigestIsAFailure(t *testing.T) {
	// buildctl exits zero having written an empty metadata file. Nothing was
	// pushed, so deploying the tag would deploy whatever it pointed at before.
	binary, _, _ := fakeBuildctl(t, `
prev=""
for a in "$@"; do
  if [ "$prev" = "--metadata-file" ]; then printf '{}' > "$a"; fi
  prev="$a"
done
exit 0
`)
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	_, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
	}, io.Discard)
	if err == nil {
		t.Fatal("a build that pushed nothing was reported as a success")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("err = %v; it does not say what is missing", err)
	}
}

func TestBuildOutputIsStreamed(t *testing.T) {
	binary, _, _ := fakeBuildctl(t, "echo '#1 [1/2] FROM scratch'\n"+writeMetadata)
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	var logs strings.Builder
	if _, err := newBuilder(t, binary).Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx, Target: "registry.example.com/shop/web", Tag: "v1",
	}, &logs); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(logs.String(), "FROM scratch") {
		t.Fatalf("build output was not streamed: %q", logs.String())
	}
}

func TestProbeReportsAnUnreachableDaemon(t *testing.T) {
	binary, _, _ := fakeBuildctl(t, "echo 'failed to connect' >&2\nexit 1\n")

	err := newBuilder(t, binary).Probe(context.Background())
	if !errors.Is(err, gitops.ErrBuilderUnavailable) {
		t.Fatalf("err = %v, want ErrBuilderUnavailable", err)
	}
	// Named at startup, in front of the operator, rather than failing the
	// first push that arrives an hour later.
	if !strings.Contains(err.Error(), "unix:///tmp/test.sock") {
		t.Errorf("err = %v; it does not name the socket", err)
	}
}

func TestProbeSucceedsAgainstAWorkingDaemon(t *testing.T) {
	binary, _, _ := fakeBuildctl(t, "echo 'linux/arm64'\nexit 0\n")
	if err := newBuilder(t, binary).Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestNewBuilderNeedsAWorkDir(t *testing.T) {
	if _, err := gitops.NewBuilder(gitops.BuilderConfig{}); err == nil {
		t.Fatal("a builder with nowhere to put scratch was accepted")
	}
}

func TestBuildValidatesItsRequest(t *testing.T) {
	binary, _, _ := fakeBuildctl(t, writeMetadata)
	builder := newBuilder(t, binary)
	ctx := buildContext(t, map[string]string{"Dockerfile": "FROM scratch\n"})

	if _, err := builder.Build(context.Background(), gitops.BuildRequest{
		Target: "registry.example.com/shop/web",
	}, io.Discard); err == nil {
		t.Error("a build with no context was accepted")
	}
	if _, err := builder.Build(context.Background(), gitops.BuildRequest{
		ContextDir: ctx,
	}, io.Discard); err == nil {
		t.Error("a build with no target image was accepted")
	}
}
