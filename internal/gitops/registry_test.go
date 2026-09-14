package gitops_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/registry"
	"github.com/m18h/kanea/internal/store"
)

// The internal-registry seam (§5.2.14): an omitted build.target is defaulted
// on the node, in Service.request, and nowhere else. These tests pin the
// three sides of that: the composition and its refusals, the output-only
// plain-HTTP allowance, and the credential merge.

// testRegistry is the seam most tests need: an address to compose with and a
// recognisable credential.
func testRegistry() gitops.InternalRegistry {
	return gitops.InternalRegistry{
		Addr: "127.0.0.1:5100",
		PushAuth: func() []byte {
			return []byte(`{"auths":{"127.0.0.1:5100":{"auth":"a2FuZWE6aHVudGVyMg=="}}}`)
		},
	}
}

// registryHarness is serviceHarness's sibling with the registry seam wired
// and the runner's argv and deploys observable.
type registryHarness struct {
	svc      *gitops.Service
	queue    *gitops.Queue
	store    store.Store
	deployer *deployer
	argsFile string
	envFile  string
}

func newRegistryHarness(t *testing.T, script string, secrets gitops.Resolver, reg gitops.InternalRegistry) *registryHarness {
	t.Helper()

	runs, c, st := newRuns(t)
	binary, argsFile, envFile := fakeBuildctl(t, script)
	builder, err := gitops.NewBuilder(gitops.BuilderConfig{
		Binary: binary, WorkDir: t.TempDir(), Socket: "unix:///tmp/test.sock",
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}

	h := &registryHarness{store: st, deployer: newDeployer(), argsFile: argsFile, envFile: envFile}
	runner, err := gitops.NewRunner(gitops.RunnerConfig{
		Runs: runs, Syncer: gitops.NewSyncer(gitops.SyncerConfig{Secrets: secrets}),
		Builder: builder, Deployer: h.deployer, Secrets: secrets, Registry: reg,
		LogDir: t.TempDir(), WorkDir: t.TempDir(), Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	h.queue, err = gitops.NewQueue(gitops.QueueConfig{Runner: runner, Now: c.now})
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	h.svc, err = gitops.NewService(gitops.ServiceConfig{
		Store: st, Runs: runs, Runner: runner, Queue: h.queue,
		Syncer:   gitops.NewSyncer(gitops.SyncerConfig{Secrets: secrets}),
		Applier:  &applier{},
		Registry: reg, Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return h
}

func (h *registryHarness) configure(t *testing.T, cfg gitops.Config) {
	t.Helper()
	if _, err := store.PutValue(context.Background(), h.store,
		store.KindProject, cfg.Project, cfg); err != nil {
		t.Fatalf("put config: %v", err)
	}
}

// execute drives the queue until the triggered run finishes.
func (h *registryHarness) execute(t *testing.T, run gitops.Run) gitops.Run {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.queue.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, err := h.svc.Get(context.Background(), run.Project, run.Service, run.ID)
		if err != nil {
			t.Fatalf("Get run: %v", err)
		}
		if got.State != gitops.RunQueued && got.State != gitops.RunRunning {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the run never finished")
	return gitops.Run{}
}

func TestTriggerRefusesAnOmittedTargetWithNoRegistry(t *testing.T) {
	h := newServiceHarness(t, nil)
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {Context: "./web"}},
	})

	_, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if !errors.Is(err, gitops.ErrNoTarget) {
		t.Fatalf("err = %v, want ErrNoTarget: an omitted target on a registry-less node "+
			"must fail in front of the operator, not mid-build", err)
	}
}

func TestTriggerRefusesACacheRepoOnTheInternalRegistry(t *testing.T) {
	h := newRegistryHarness(t, writeMetadata, nil, testRegistry())
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {
			Context: "./web", Target: "registry.example.com/shop/web",
			CacheRepo: "127.0.0.1:5100/shop/web-cache",
		}},
	})

	_, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if !errors.Is(err, gitops.ErrInternalCacheRepo) {
		t.Fatalf("err = %v, want ErrInternalCacheRepo", err)
	}
}

func TestTriggerDefaultsAnOmittedTargetToTheInternalRegistry(t *testing.T) {
	h := newRegistryHarness(t, writeMetadata, nil, testRegistry())
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {Context: "./web"}},
	})

	queued, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	run := h.execute(t, queued)
	if run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}

	// The composed target reached buildctl with the plain-HTTP allowance on
	// the output.
	argv := args(t, h.argsFile)
	output := argValue(argv, "--output")
	if !strings.HasPrefix(output, "type=image,name=127.0.0.1:5100/shop/web:") ||
		!strings.HasSuffix(output, ",push=true,registry.insecure=true") {
		t.Errorf("--output = %q; want the composed internal target, insecure", output)
	}
	// And the deploy pinned the digest onto the same composed reference.
	if ref := h.deployer.ref("shop/web"); ref != "127.0.0.1:5100/shop/web@sha256:cafebabe" {
		t.Errorf("deployed ref = %q", ref)
	}

	// The stored record still says what the spec said: nothing (recurring
	// rule 6; a node address baked in here would make one spec mean different
	// things on two machines).
	cfg, _, err := store.GetValue[gitops.Config](context.Background(), h.store,
		store.KindProject, "shop")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.Builds["web"].Target != "" {
		t.Errorf("stored target = %q; the record must stay empty", cfg.Builds["web"].Target)
	}
}

func TestAnExplicitTargetIsUntouched(t *testing.T) {
	h := newRegistryHarness(t, writeMetadata, nil, testRegistry())
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {
			Context: "./web", Target: "registry.example.com/shop/web", Tag: "pinned",
		}},
	})

	queued, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	run := h.execute(t, queued)
	if run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}
	output := argValue(args(t, h.argsFile), "--output")
	if output != "type=image,name=registry.example.com/shop/web:pinned,push=true" {
		t.Errorf("--output = %q; an explicit target gets no allowance and no rewrite", output)
	}
}

func TestInternalTargetDoesNotDowngradeTheCachePush(t *testing.T) {
	h := newRegistryHarness(t, writeMetadata, nil, testRegistry())
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {
			Context: "./web", CacheRepo: "registry.example.com/shop/web-cache",
		}},
	})

	queued, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if run := h.execute(t, queued); run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}

	argv := args(t, h.argsFile)
	if output := argValue(argv, "--output"); !strings.Contains(output, "registry.insecure=true") {
		t.Errorf("--output = %q; the internal push needs the allowance", output)
	}
	for _, flag := range []string{"--export-cache", "--import-cache"} {
		if value := argValue(argv, flag); strings.Contains(value, "registry.insecure") {
			t.Errorf("%s = %q; a defaulted target must never downgrade an external cache push", flag, value)
		}
	}
}

// copyDockerConfig is the script fragment that preserves the materialised
// credential before the runner deletes its scratch directory.
func copyDockerConfig(dest string) string {
	return `cp "$DOCKER_CONFIG/config.json" ` + dest + "\n" + writeMetadata
}

func TestInternalTargetMergesThePushCredential(t *testing.T) {
	saved := t.TempDir() + "/config.json"
	secrets := &resolver{values: map[string][]byte{
		"secret:shop/registry": []byte(`{"auths":{"ghcr.io":{"username":"u","password":"p"}},"credHelpers":{"gcr.io":"gcloud"}}`),
	}}
	h := newRegistryHarness(t, copyDockerConfig(saved), secrets, testRegistry())
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {
			Context: "./web", RegistryAuthRef: "secret:shop/registry",
		}},
	})

	queued, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if run := h.execute(t, queued); run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}

	body, err := os.ReadFile(saved) // #nosec G304; a path this test created
	if err != nil {
		t.Fatalf("the build saw no config.json: %v", err)
	}
	var cfg struct {
		Auths       map[string]json.RawMessage `json:"auths"`
		CredHelpers map[string]string          `json:"credHelpers"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("materialised config: %v", err)
	}
	// Merged, not replaced: the spec's credential still authenticates its own
	// registry, the internal one authenticates the push, and top-level keys
	// beyond auths survive.
	for _, host := range []string{"ghcr.io", "127.0.0.1:5100"} {
		if _, ok := cfg.Auths[host]; !ok {
			t.Errorf("materialised config is missing %s", host)
		}
	}
	if cfg.CredHelpers["gcr.io"] != "gcloud" {
		t.Errorf("credHelpers did not survive the merge: %+v", cfg.CredHelpers)
	}
}

func TestInternalTargetWithNoPushCredentialFails(t *testing.T) {
	h := newRegistryHarness(t, writeMetadata, nil,
		gitops.InternalRegistry{Addr: "127.0.0.1:5100"})
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {Context: "./web"}},
	})

	queued, err := h.svc.Trigger(context.Background(), "shop", "web", true, "tester")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	run := h.execute(t, queued)
	if run.State != gitops.RunFailed || !strings.Contains(run.Error, "push credential") {
		t.Fatalf("run = %+v; a credential-less internal target must fail closed by name", run)
	}
}

// TestInternalRegistryEndToEnd drives the real sequence: an omitted target,
// a fake buildctl that performs the actual HTTP push - session POST, blob
// PUT, manifest PUT, with the Basic credential out of the materialised
// config.json - against a live internal registry, and a deploy of the digest
// the registry verified. The curl-less protocol coverage lives in
// internal/registry, so nothing load-bearing hides behind the skip.
func TestInternalRegistryEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not on PATH")
	}

	reg, err := registry.New(registry.Config{
		Addr: "127.0.0.1:0", Dir: t.TempDir(),
		Allowed: func(_ context.Context, project, service string) bool {
			return project == "shop" && service == "web"
		},
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- reg.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	config := []byte(`{"built":"by the e2e test"}`)
	configDgst := sha256Digest(config)
	manifest := []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
			`"config":{"digest":%q,"size":%d},"layers":[]}`, configDgst, len(config)))
	manifestDgst := sha256Digest(manifest)

	// The push a real buildkitd performs, spelled in curl: every step -fsS,
	// so any refused request fails the "build".
	base := "http://" + reg.Addr() + "/v2/shop/web"
	script := `set -e
AUTH=$(sed -n 's/.*"auth"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DOCKER_CONFIG/config.json" | head -1)
LOC=$(curl -fsS -X POST -H "Authorization: Basic $AUTH" -o /dev/null -D - "` + base + `/blobs/uploads/" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
printf '%s' '` + string(config) + `' | curl -fsS -X PUT -H "Authorization: Basic $AUTH" --data-binary @- "http://` + reg.Addr() + `${LOC}?digest=` + configDgst + `" -o /dev/null
printf '%s' '` + string(manifest) + `' | curl -fsS -X PUT -H "Authorization: Basic $AUTH" -H "Content-Type: application/vnd.oci.image.manifest.v1+json" --data-binary @- "` + base + `/manifests/` + manifestDgst + `" -o /dev/null
prev=""
for a in "$@"; do
  if [ "$prev" = "--metadata-file" ]; then
    printf '{"containerimage.digest":"` + manifestDgst + `"}' > "$a"
  fi
  prev="$a"
done
`

	h := newRegistryHarness(t, script, nil,
		gitops.InternalRegistry{Addr: reg.Addr(), PushAuth: reg.PushDockerConfig})
	h.configure(t, gitops.Config{
		Project: "shop", Source: gitops.Source{URL: buildRepo(t)},
		Builds: map[string]gitops.BuildSpec{"web": {Context: "./web"}},
	})

	queued, err := h.svc.Trigger(context.Background(), "shop", "web", true, "e2e")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	run := h.execute(t, queued)
	if run.State != gitops.RunSucceeded {
		t.Fatalf("run = %+v", run)
	}

	// The deploy pinned the digest the registry verified, on the composed
	// internal reference.
	wantRef := reg.Addr() + "/shop/web@" + manifestDgst
	if ref := h.deployer.ref("shop/web"); ref != wantRef {
		t.Errorf("deployed ref = %q, want %q", ref, wantRef)
	}

	// And the image is anonymously pullable, bytes intact.
	resp, err := http.Get("http://" + reg.Addr() + "/v2/shop/web/manifests/" + manifestDgst) // #nosec G107; a loopback address this test bound
	if err != nil {
		t.Fatalf("pull manifest: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // a test response
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != string(manifest) {
		t.Fatalf("pulled manifest = %d %q (%v)", resp.StatusCode, body, err)
	}
}

func sha256Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
