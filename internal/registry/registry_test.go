package registry_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/registry"
)

// harness is a served registry and the pieces a test asserts with.
type harness struct {
	reg  *registry.Registry
	addr string
	// auth is the Authorization header value writes need.
	auth   string
	client *http.Client
}

// allowShopWeb is the pipeline bound most tests run under.
func allowShopWeb(_ context.Context, project, service string) bool {
	return project == "shop" && service == "web"
}

func newHarness(t *testing.T, allowed func(context.Context, string, string) bool) *harness {
	t.Helper()
	reg, err := registry.New(registry.Config{
		// Port 0: the test needs a listener, not the default port, which
		// another process (or a parallel test) may hold.
		Addr:    "127.0.0.1:0",
		Dir:     t.TempDir(),
		Allowed: allowed,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reg.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(reg.PushDockerConfig(), &cfg); err != nil {
		t.Fatalf("parse push config: %v", err)
	}
	return &harness{
		reg: reg, addr: reg.Addr(),
		auth:   "Basic " + cfg.Auths[reg.Addr()].Auth,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// do performs one request, with the push credential when asked.
func (h *harness) do(t *testing.T, method, path string, body []byte, authed bool, header map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+h.addr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if authed {
		req.Header.Set("Authorization", h.auth)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() }) //nolint:errcheck // a test response
	return resp
}

// pushBlob drives the session flow containerd's pusher drives: one POST for
// the session, one monolithic PUT with the content and ?digest=.
func (h *harness) pushBlob(t *testing.T, repo string, content []byte) string {
	t.Helper()
	dgst := digestOf(content)
	post := h.do(t, http.MethodPost, "/v2/"+repo+"/blobs/uploads/", nil, true, nil)
	if post.StatusCode != http.StatusAccepted {
		t.Fatalf("POST upload = %d", post.StatusCode)
	}
	location := post.Header.Get("Location")
	if location == "" || strings.Contains(location, "?") {
		t.Fatalf("Location = %q; want a relative path with no query", location)
	}
	put := h.do(t, http.MethodPut, location+"?digest="+dgst, content, true, nil)
	if put.StatusCode != http.StatusCreated {
		t.Fatalf("PUT upload = %d", put.StatusCode)
	}
	if got := put.Header.Get("Docker-Content-Digest"); got != dgst {
		t.Fatalf("Docker-Content-Digest = %q, want %q", got, dgst)
	}
	return dgst
}

// pushImage pushes a config blob and a manifest referencing it, tagged.
func (h *harness) pushImage(t *testing.T, repo, tag string, seed byte) (manifest []byte, dgst string) {
	t.Helper()
	config := []byte(fmt.Sprintf(`{"seed":%d}`, seed))
	configDgst := h.pushBlob(t, repo, config)
	manifest = []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
			`"config":{"digest":%q,"size":%d},"layers":[]}`, configDgst, len(config)))
	resp := h.do(t, http.MethodPut, "/v2/"+repo+"/manifests/"+tag, manifest, true,
		map[string]string{"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT manifest = %d", resp.StatusCode)
	}
	return manifest, digestOf(manifest)
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || len(body.Errors) == 0 {
		t.Fatalf("no distribution error body (%v)", err)
	}
	return body.Errors[0].Code
}

func TestNewRefusesANonLoopbackBind(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:0",      // wildcard
		"10.10.1.6:0",    // private
		"192.0.2.7:5100", // public
		"localhost:5100", // a name, not an address
		"[::]:5100",      // v6 wildcard
	} {
		if _, err := registry.New(registry.Config{Addr: addr, Dir: t.TempDir()}); err == nil {
			t.Errorf("New accepted %q; the registry serves anonymous reads and must bind loopback only", addr)
		}
	}
	// The v6 loopback is as loopback as the v4 one.
	reg, err := registry.New(registry.Config{Addr: "[::1]:0", Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("New refused [::1]: %v", err)
	}
	_ = reg
}

func TestPushDockerConfigCarriesThePerBootCredential(t *testing.T) {
	h := newHarness(t, allowShopWeb)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h.auth, "Basic "))
	if err != nil {
		t.Fatalf("auth is not base64: %v", err)
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user != "kanea" {
		t.Fatalf("credential = %q; want kanea:<secret>", raw)
	}
	if len(pass) != 64 {
		t.Fatalf("secret length = %d, want 64 hex characters", len(pass))
	}
}

func TestPingAnswersTheVersionCheck(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	resp := h.do(t, http.MethodGet, "/v2/", nil, false, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/ = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
		t.Errorf("version header = %q", got)
	}
}

func TestWritesRequireThePerBootCredential(t *testing.T) {
	h := newHarness(t, allowShopWeb)

	resp := h.do(t, http.MethodPost, "/v2/shop/web/blobs/uploads/", nil, false, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("WWW-Authenticate = %q; containerd's authorizer needs a Basic challenge", got)
	}

	// A wrong password is the same refusal.
	req, err := http.NewRequest(http.MethodPost, "http://"+h.addr+"/v2/shop/web/blobs/uploads/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.SetBasicAuth("kanea", "not-the-secret")
	wrong, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer wrong.Body.Close() //nolint:errcheck // a test response
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-password POST = %d, want 401", wrong.StatusCode)
	}

	auth, _, _, _, _ := h.reg.Refusals()
	if auth != 2 {
		t.Errorf("auth refusals = %d, want 2", auth)
	}
}

func TestReadsAreAnonymous(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	_, dgst := h.pushImage(t, "shop/web", "v1", 1)

	resp := h.do(t, http.MethodGet, "/v2/shop/web/manifests/"+dgst, nil, false, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous manifest GET = %d, want 200", resp.StatusCode)
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	reg, err := registry.New(registry.Config{Addr: "127.0.0.1:0", Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reg.Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v on a clean cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop on cancel")
	}
}
