package edge

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// startEdge runs a server on ephemeral ports and returns its base URLs.
func startEdge(t *testing.T, snapshotPath string) (public, status string) {
	t.Helper()

	srv, err := New(Config{
		HTTPAddr:     "127.0.0.1:0",
		StatusAddr:   "127.0.0.1:0",
		SnapshotPath: snapshotPath,
		PollInterval: 5 * time.Millisecond,
		DrainTimeout: time.Second,
		Version:      "test",
		Logger:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the edge did not shut down")
		}
	})

	return "http://" + srv.Addr(), "http://" + srv.statusLn.Addr().String()
}

// get fetches a URL with an explicit Host header.
func get(t *testing.T, url, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// The edge starts before kanead has published anything and serves 404s rather
// than refusing to come up. "The control plane is down" must not become "the
// site is down".
func TestServerStartsWithoutASnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	public, status := startEdge(t, path)

	if code, _ := get(t, public+"/", "anything.example.com"); code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 with no routes", code)
	}
	if code, _ := get(t, status+"/healthz", ""); code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", code)
	}
}

// The whole point of the snapshot: kanead publishes, the edge picks it up
// without either process knowing about the other.
func TestServerPicksUpAPublishedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	public, statusURL := startEdge(t, path)

	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "served")
	}))
	if err := Publish(path, Snapshot{Index: 5, Routes: []Route{route}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	waitFor(t, func() bool {
		code, _ := get(t, public+"/", "web.shop.example.com")
		return code == http.StatusOK
	}, "the edge never picked up the published route")

	_, body := get(t, public+"/", "web.shop.example.com")
	if body != "served" {
		t.Errorf("body = %q", body)
	}

	// And the diagnostics listener reflects it.
	code, raw := get(t, statusURL+"/routes", "")
	if code != http.StatusOK {
		t.Fatalf("/routes = %d", code)
	}
	var payload struct {
		Index  uint64 `json:"index"`
		Routes []struct {
			Host    string `json:"host"`
			Service string `json:"service"`
		} `json:"routes"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("decode /routes: %v", err)
	}
	if payload.Index != 5 {
		t.Errorf("index = %d, want 5", payload.Index)
	}
	if len(payload.Routes) != 1 || payload.Routes[0].Service != "shop/web" {
		t.Errorf("routes = %+v", payload.Routes)
	}
}

// The diagnostics listener answers questions the internet has no business
// asking, so it binds to loopback and is not reachable on the public one.
func TestStatusEndpointsAreNotOnThePublicListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	public, _ := startEdge(t, path)

	for _, p := range []string{"/healthz", "/routes"} {
		if code, _ := get(t, public+p, "anything.example.com"); code != http.StatusNotFound {
			t.Errorf("public %s = %d, want 404", p, code)
		}
	}
}

func TestNewRequiresASnapshotPath(t *testing.T) {
	if _, err := New(Config{HTTPAddr: "127.0.0.1:0"}); err == nil {
		t.Error("accepted a config with no snapshot path")
	}
}

// waitFor polls until cond holds or the test gives up.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}
