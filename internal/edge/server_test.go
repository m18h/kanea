package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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

// startTLSEdge runs a server with both listeners and returns their base URLs.
func startTLSEdge(t *testing.T, snapshotPath, bundlePath string) (plain, secure string) {
	t.Helper()

	srv, err := New(Config{
		HTTPAddr:     "127.0.0.1:0",
		HTTPSAddr:    "127.0.0.1:0",
		StatusAddr:   "",
		SnapshotPath: snapshotPath,
		BundlePath:   bundlePath,
		PollInterval: 5 * time.Millisecond,
		DrainTimeout: time.Second,
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

	return "http://" + srv.Addr(), "https://" + srv.httpsLn.Addr().String()
}

// The exit criterion for TLS: a client that trusts the certificate reaches the
// service over HTTPS, and the upstream is told the request arrived over TLS.
func TestServerTerminatesTLS(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.json")
	bundlePath := filepath.Join(dir, "certs.json")

	// Buffered and non-blocking: the poll below makes repeated requests, and a
	// handler that blocks on a full channel deadlocks the server.
	seen := make(chan http.Header, 16)
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Clone():
		default:
		}
		_, _ = io.WriteString(w, "over tls")
	}))
	if err := Publish(routesPath, Snapshot{Index: 1, Routes: []Route{route}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	cert := selfSigned(t, time.Now().Add(time.Hour), "web.shop.example.com")
	if err := PublishBundle(bundlePath, Bundle{Index: 1, Certificates: []Certificate{cert}}, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	_, secure := startTLSEdge(t, routesPath, bundlePath)
	client := trustingClient(t, cert, secure)

	// The dial goes to loopback, but the SNI and the Host header both carry the
	// real name: one selects the certificate, the other selects the route.
	waitFor(t, func() bool {
		code, _ := tryGet(client, secure+"/", "web.shop.example.com")
		return code == http.StatusOK
	}, "the edge never served the published certificate")

	code, body := getWith(t, client, secure+"/", "web.shop.example.com")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body != "over tls" {
		t.Errorf("body = %q", body)
	}

	// One proxy serves both listeners, so the scheme has to come from the
	// request rather than from configuration.
	var header http.Header
	select {
	case header = <-seen:
	case <-time.After(time.Second):
		t.Fatal("the upstream saw no request")
	}
	if got := header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", got)
	}
	if got := header.Get("X-Forwarded-Port"); got != "443" {
		t.Errorf("X-Forwarded-Port = %q, want 443", got)
	}
}

// A host with no certificate must keep serving plaintext. Redirecting it turns
// "not issued yet" into "unreachable" and takes down the HTTP-01 validation
// that would have fixed it.
func TestServerRedirectsOnlyCoveredHosts(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.json")
	bundlePath := filepath.Join(dir, "certs.json")

	_, covered := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	_, bare := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "plaintext")
	}))
	bare.Service = "bare"
	bare.Domains = []string{"bare.example.com"}

	if err := Publish(routesPath, Snapshot{Routes: []Route{covered, bare}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	cert := selfSigned(t, time.Now().Add(time.Hour), "web.shop.example.com")
	if err := PublishBundle(bundlePath, Bundle{Certificates: []Certificate{cert}}, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	plain, _ := startTLSEdge(t, routesPath, bundlePath)
	noRedirect := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	waitFor(t, func() bool {
		code, _ := getWith(t, noRedirect, plain+"/", "web.shop.example.com")
		return code == http.StatusPermanentRedirect
	}, "the covered host was never redirected")

	code, _ := getWith(t, noRedirect, plain+"/", "web.shop.example.com")
	if code != http.StatusPermanentRedirect {
		t.Errorf("covered host = %d, want 308", code)
	}

	code, body := getWith(t, noRedirect, plain+"/", "bare.example.com")
	if code != http.StatusOK || body != "plaintext" {
		t.Errorf("uncovered host = %d %q, want a plaintext 200", code, body)
	}
}

// The validation that produces a certificate must work on a node that has none,
// so challenges are answered before the redirect is considered.
func TestServerServesACMEChallenges(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.json")
	bundlePath := filepath.Join(dir, "certs.json")

	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a challenge request was proxied to the upstream")
		w.WriteHeader(http.StatusOK)
	}))
	if err := Publish(routesPath, Snapshot{Routes: []Route{route}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// A certificate is present for this host, so the redirect would fire if
	// challenges were not handled first.
	cert := selfSigned(t, time.Now().Add(time.Hour), "web.shop.example.com")
	if err := PublishBundle(bundlePath, Bundle{
		Certificates:   []Certificate{cert},
		HTTPChallenges: []HTTPChallenge{{Token: "tok-123", KeyAuth: "tok-123.thumbprint"}},
	}, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	plain, _ := startTLSEdge(t, routesPath, bundlePath)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	waitFor(t, func() bool {
		code, body := getWith(t, client, plain+acmeChallengePrefix+"tok-123", "web.shop.example.com")
		return code == http.StatusOK && body == "tok-123.thumbprint"
	}, "the challenge was never answered")

	// An unknown token 404s rather than being proxied — the internet scans
	// this path constantly.
	if code, _ := getWith(t, client, plain+acmeChallengePrefix+"nope", "web.shop.example.com"); code != http.StatusNotFound {
		t.Errorf("unknown token = %d, want 404", code)
	}
}

// trustingClient dials the edge's TLS listener with the test certificate as its
// only root, so a handshake failure is a real failure rather than the expected
// rejection of a self-signed chain.
func trustingClient(t *testing.T, cert Certificate, secureURL string) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cert.CertPEM)) {
		t.Fatal("cannot parse the test certificate")
	}
	addr := strings.TrimPrefix(secureURL, "https://")

	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// The listener is on an ephemeral port on loopback; the certificate
			// names the real host, so the dial and the SNI are separated.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: cert.Domains[0], MinVersion: tls.VersionTLS12},
		},
	}
}

// getWith fetches a URL with an explicit Host using a given client.
func getWith(t *testing.T, client *http.Client, url, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	resp, err := client.Do(req)
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

// tryGet is getWith without the fatal, for polling until a condition holds.
func tryGet(client *http.Client, url, host string) (int, string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return 0, ""
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, ""
	}
	return resp.StatusCode, string(body)
}
