package api_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/secrets"
	"github.com/kanea-dev/kanea/internal/store"
)

type harness struct {
	client *api.Client
	store  store.Store
	logDir string
	socket string
	notify chan struct{}
}

// newHarness starts a server over a unix socket. The variadic hooks let a test
// adjust the config it is actually about without every other test knowing those
// fields exist.
func newHarness(t *testing.T, with ...func(*api.ServerConfig)) *harness {
	t.Helper()

	dir := t.TempDir()
	// macOS caps unix socket paths at ~104 bytes and t.TempDir() is long, so
	// the socket goes in the shortest temp path available.
	socket := filepath.Join(shortTempDir(t), "k.sock")

	st, err := store.Open(store.Options{Path: filepath.Join(dir, "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}

	h := &harness{store: st, logDir: logDir, socket: socket, notify: make(chan struct{}, 1)}
	cfg := api.ServerConfig{
		Store: st, Socket: socket, Version: "test", LogDir: logDir, Notify: h.notify,
	}
	for _, apply := range with {
		apply(&cfg)
	}
	server, err := api.NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := server.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})

	h.client = api.NewClient(socket)
	waitHealthy(t, h.client)
	return h
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func waitHealthy(t *testing.T, c *api.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := c.Health(context.Background()); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("server never became healthy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// testService builds a service in the "shop" project, which is what every test
// here uses; cross-project cases seed the store directly.
func testService(service string, count int) reconciler.Desired {
	return reconciler.Desired{
		Project: "shop", Service: service, Count: count, Image: "nginx:1.27-alpine",
		Resources: runtime.Resources{CPUMillis: 100, MemoryBytes: 256 << 20},
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t)
	got, err := h.client.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if got.Status != "ok" || got.Version != "test" {
		t.Errorf("health = %+v", got)
	}
}

func TestApplyAndListServices(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	resp, err := h.client.Apply(ctx, []reconciler.Desired{
		testService("web", 2),
		testService("api", 1),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(resp.Applied) != 2 || resp.Index == 0 {
		t.Errorf("apply response = %+v", resp)
	}

	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("services = %d, want 2", len(services))
	}
	// Sorted, so CLI output is stable between calls.
	if services[0].Service != "api" || services[1].Service != "web" {
		t.Errorf("services are not sorted: %s, %s", services[0].Service, services[1].Service)
	}
}

func TestApplyWakesTheReconciler(t *testing.T) {
	// A deploy must converge immediately, not after the next tick.
	h := newHarness(t)
	if _, err := h.client.Apply(context.Background(), []reconciler.Desired{testService("web", 1)}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	select {
	case <-h.notify:
	case <-time.After(2 * time.Second):
		t.Error("apply did not wake the reconciler")
	}
}

func TestApplyIsPartial(t *testing.T) {
	// Applying one file must not delete services declared elsewhere.
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, []reconciler.Desired{testService("web", 1)}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{testService("api", 1)}); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 2 {
		t.Errorf("services = %d, want both to survive", len(services))
	}
}

func TestApplyRejectsBadRequests(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, nil); err == nil {
		t.Error("empty apply should be rejected")
	}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{{Service: "web"}}); err == nil {
		t.Error("service without a project should be rejected")
	}
}

func TestDeleteService(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, []reconciler.Desired{testService("web", 1)}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := h.client.DeleteService(ctx, "shop", "web"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("services = %d, want 0", len(services))
	}

	// Deleting something that is not there is a 404, not a silent success:
	// a typo in a service name should be visible.
	if _, err := h.client.DeleteService(ctx, "shop", "ghost"); err == nil {
		t.Error("deleting an unknown service should fail")
	}
}

func TestListAllocsFilters(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	records := []reconciler.AllocRecord{
		{ID: "shop-web-0", Project: "shop", Service: "web", Index: 0, State: reconciler.AllocRunning},
		{ID: "shop-api-0", Project: "shop", Service: "api", Index: 0, State: reconciler.AllocRunning},
		{ID: "blog-cms-0", Project: "blog", Service: "cms", Index: 0, State: reconciler.AllocRunning},
	}
	for _, rec := range records {
		if _, err := store.PutValue(ctx, h.store, store.KindAlloc, rec.Key(), rec); err != nil {
			t.Fatalf("seed alloc: %v", err)
		}
	}

	tests := []struct {
		name             string
		project, service string
		want             int
	}{
		{"all", "", "", 3},
		{"by project", "shop", "", 2},
		{"by service", "", "web", 1},
		{"by both", "shop", "api", 1},
		{"no match", "shop", "ghost", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allocs, err := h.client.Allocs(ctx, tc.project, tc.service)
			if err != nil {
				t.Fatalf("allocs: %v", err)
			}
			if len(allocs) != tc.want {
				t.Errorf("allocs = %d, want %d", len(allocs), tc.want)
			}
		})
	}
}

func TestLogsStreamsOneAlloc(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	rec := reconciler.AllocRecord{ID: "shop-web-0", Project: "shop", Service: "web", State: reconciler.AllocRunning}
	if _, err := store.PutValue(ctx, h.store, store.KindAlloc, rec.Key(), rec); err != nil {
		t.Fatal(err)
	}
	writeLog(t, h.logDir, "shop-web-0", "line one\nline two\n")

	var buf bytes.Buffer
	if err := h.client.Logs(ctx, api.LogOptions{Service: "web"}, &buf); err != nil {
		t.Fatalf("logs: %v", err)
	}
	if got := buf.String(); got != "line one\nline two\n" {
		t.Errorf("logs = %q", got)
	}
}

func TestLogsPrefixesWhenFollowingSeveralAllocs(t *testing.T) {
	// With one alloc the stream is clean; with several, each line must say
	// which alloc it came from.
	h := newHarness(t)
	ctx := context.Background()

	for i, text := range []string{"from zero\n", "from one\n"} {
		rec := reconciler.AllocRecord{
			ID: "shop-web-" + string(rune('0'+i)), Project: "shop", Service: "web", Index: i,
			State: reconciler.AllocRunning,
		}
		if _, err := store.PutValue(ctx, h.store, store.KindAlloc, rec.Key(), rec); err != nil {
			t.Fatal(err)
		}
		writeLog(t, h.logDir, rec.ID, text)
	}

	var buf bytes.Buffer
	if err := h.client.Logs(ctx, api.LogOptions{Service: "web"}, &buf); err != nil {
		t.Fatalf("logs: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "shop-web-0 | from zero") || !strings.Contains(out, "shop-web-1 | from one") {
		t.Errorf("logs = %q, want alloc-prefixed lines", out)
	}
}

func TestLogsTail(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	rec := reconciler.AllocRecord{ID: "shop-web-0", Project: "shop", Service: "web", State: reconciler.AllocRunning}
	if _, err := store.PutValue(ctx, h.store, store.KindAlloc, rec.Key(), rec); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for i := range 100 {
		sb.WriteString("line ")
		sb.WriteString(string(rune('0' + i%10)))
		sb.WriteString("\n")
	}
	writeLog(t, h.logDir, "shop-web-0", sb.String())

	var buf bytes.Buffer
	if err := h.client.Logs(ctx, api.LogOptions{Service: "web", Tail: 5}, &buf); err != nil {
		t.Fatalf("logs: %v", err)
	}
	lines := strings.Count(buf.String(), "\n")
	if lines != 5 {
		t.Errorf("tail returned %d lines, want 5", lines)
	}
}

func TestLogsFollowStreamsNewOutput(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rec := reconciler.AllocRecord{ID: "shop-web-0", Project: "shop", Service: "web", State: reconciler.AllocRunning}
	if _, err := store.PutValue(ctx, h.store, store.KindAlloc, rec.Key(), rec); err != nil {
		t.Fatal(err)
	}
	path := writeLog(t, h.logDir, "shop-web-0", "first\n")

	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- h.client.Logs(ctx, api.LogOptions{Service: "web", Follow: true}, out) }()

	waitFor(t, func() bool { return strings.Contains(out.String(), "first") }, "initial line")

	// Append while following: the new line must arrive without reconnecting.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("second\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	waitFor(t, func() bool { return strings.Contains(out.String(), "second") }, "appended line")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("follow returned %v, want nil after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("follow did not return after cancellation")
	}
}

func TestLogsForUnknownServiceIs404(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	if err := h.client.Logs(context.Background(), api.LogOptions{Service: "ghost"}, &buf); err == nil {
		t.Error("expected an error for a service with no allocs")
	}
}

func TestClientReportsAHelpfulErrorWhenDaemonIsDown(t *testing.T) {
	// The most common first-run mistake: running a CLI command with no daemon.
	client := api.NewClient(filepath.Join(t.TempDir(), "absent.sock"))
	_, err := client.Health(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "is it running") {
		t.Errorf("error = %q, want it to suggest starting kanead", err)
	}
}

func TestSocketPermissionsAreRestrictive(t *testing.T) {
	// The socket is the authentication boundary in M1 (PRD §14, A05).
	h := newHarness(t)
	info, err := os.Stat(h.socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o, want 600", perm)
	}
}

func TestListenReplacesAStaleSocket(t *testing.T) {
	// A crashed kanead leaves its socket file behind; the next start must not
	// refuse to bind because of it.
	h := newHarness(t)
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state2.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	second, err := api.NewServer(api.ServerConfig{Store: st, Socket: h.socket, LogDir: h.logDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Listen(); err != nil {
		t.Fatalf("listen over a stale socket: %v", err)
	}
}

// ---- helpers ----

func writeLog(t *testing.T, dir, allocID, content string) string {
	t.Helper()
	path := filepath.Join(dir, allocID+".log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return path
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// syncBuffer is a bytes.Buffer safe for the follow test's concurrent writer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// httpClient dials the harness's unix socket over HTTP, which is what the
// websocket client needs: the socket is the transport, "kanead" is a placeholder
// host that never leaves the process.
func (h *harness) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", h.socket)
			},
		},
	}
}

// putService writes one desired service straight to the Store, bypassing the
// API so a feed test is about the feed and not about apply.
func (h *harness) putService(t *testing.T, project, service string, count int) {
	t.Helper()
	d := reconciler.Desired{
		Project: project, Service: service, Count: count,
		Image:     "docker.io/library/nginx:1.27-alpine",
		Resources: runtime.Resources{CPUMillis: 100, MemoryBytes: 256 << 20},
	}
	if _, err := store.PutValue(context.Background(), h.store,
		store.KindService, project+"/"+service, d); err != nil {
		t.Fatalf("put service: %v", err)
	}
}

// withSecrets gives the harness a real secrets store.
func withSecrets(cfg *api.ServerConfig) {
	dir, err := os.MkdirTemp("", "ksec")
	if err != nil {
		panic(err)
	}
	st, err := store.Open(store.Options{Path: filepath.Join(dir, "secrets.db")})
	if err != nil {
		panic(err)
	}
	s, err := secrets.Open(secrets.Config{
		Store:   st,
		KeyPath: filepath.Join(dir, secrets.KeyFileName),
	})
	if err != nil {
		panic(err)
	}
	cfg.Secrets = s
	cfg.ServeDashboard = true
}

// raw makes a request over the harness's socket and returns the status and body.
func (h *harness) raw(t *testing.T, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "http://kanead"+path, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := h.httpClient().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}
