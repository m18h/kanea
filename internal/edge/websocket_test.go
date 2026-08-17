package edge

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/bcrypt"
)

// WebSocket passthrough (PRD §5.2.6, v1.41). There is deliberately no
// websocket code in the proxy (httputil.ReverseProxy carries the Upgrade
// natively) so what these tests pin is that the machinery *around* it never
// breaks the session: the middleware chain runs before the upgrade, the body
// deadline and the server's idle timeout leave a hijacked connection alone,
// and the metrics count the session without timing it.

// wsEcho is a backend that upgrades and echoes one message at a time.
func wsEcho(t *testing.T) (*httptest.Server, Route) {
	t.Helper()
	return upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// The edge is the origin-agnostic party here; Origin policy is the
			// application's own concern and this backend has none.
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusInternalError, "test over")
		for {
			kind, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), kind, data); err != nil {
				return
			}
		}
	}))
}

// wsDial connects through addr while addressing the route's domain: the
// Host-routing equivalent of pointing DNS at the edge.
func wsDial(ctx context.Context, t *testing.T, addr, domain string) *websocket.Conn {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	c, _, err := websocket.Dial(ctx, "ws://"+domain+"/", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatalf("websocket dial via %s: %v", addr, err)
	}
	return c
}

// echoOnce proves the session is alive in both directions.
func echoOnce(ctx context.Context, t *testing.T, c *websocket.Conn, msg string) {
	t.Helper()
	if err := c.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != msg {
		t.Fatalf("echo = %q, want %q", data, msg)
	}
}

// The whole path, end to end: kanead publishes a snapshot, the edge picks it
// up, and a WebSocket upgrade rides the same route table an HTTP request does.
func TestWebSocketEchoesThroughTheEdge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	public, _ := startEdge(t, path)

	_, route := wsEcho(t)
	if err := Publish(path, Snapshot{Index: 1, Routes: []Route{route}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	waitFor(t, func() bool {
		code, _ := get(t, public+"/", "other.probe.example.com")
		_ = code
		// The 404 for an unknown host proves the snapshot loaded; the real
		// probe below is the upgrade itself.
		code2, _ := get(t, public+"/health-probe", "web.shop.example.com")
		return code2 != http.StatusNotFound
	}, "the edge never picked up the route")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := wsDial(ctx, t, strings.TrimPrefix(public, "http://"), "web.shop.example.com")
	defer c.Close(websocket.StatusNormalClosure, "done")

	echoOnce(ctx, t, c, "hello through the edge")
	echoOnce(ctx, t, c, "and back again")
}

// IdleTimeout applies between requests on a kept-alive connection; a hijacked
// connection has left the server's accounting entirely. If this ever regresses
// (a wrapper that stops forwarding Hijack, a deadline applied to the raw conn)
// every WebSocket dies at the idle timeout while idle, which is most of a
// WebSocket's life.
func TestWebSocketSurvivesTheServersIdleTimeout(t *testing.T) {
	_, route := wsEcho(t)
	p := newTestProxy(t, route)

	srv := httptest.NewUnstartedServer(p)
	srv.Config.IdleTimeout = 100 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := wsDial(ctx, t, strings.TrimPrefix(srv.URL, "http://"), "web.shop.example.com")
	defer c.Close(websocket.StatusNormalClosure, "done")

	// Idle for several multiples of the server's IdleTimeout, then speak.
	time.Sleep(500 * time.Millisecond)
	echoOnce(ctx, t, c, "still here")
}

// Auth runs before the upgrade: an unauthenticated client gets 401 (or 503
// when the material is missing), never a 101 whose session then has to be
// torn down.
func TestWebSocketUpgradeMeetsAuthFirst(t *testing.T) {
	_, route := wsEcho(t)
	route.AuthRequired = true

	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	upgradeHeaders := http.Header{
		"Connection":            []string{"Upgrade"},
		"Upgrade":               []string{"websocket"},
		"Sec-Websocket-Version": []string{"13"},
		"Sec-Websocket-Key":     []string{"dGhlIHNhbXBsZSBub25jZQ=="},
	}

	// Marked route, no material: fail closed.
	p := newTestProxy(t, route)
	resp := request(p, http.MethodGet, "web.shop.example.com", "/", upgradeHeaders)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("upgrade with no auth material = %d, want 503", resp.StatusCode)
	}

	// Material present, wrong credentials: 401 with a challenge.
	p.SetAuth([]AuthEntry{{
		Project: "shop", Service: "web", Mode: AuthBasic,
		Users: []string{"ama:" + string(hash)},
	}})
	headers := upgradeHeaders.Clone()
	headers.Set("Authorization", "Basic YW1hOndyb25n") // ama:wrong
	resp = request(p, http.MethodGet, "web.shop.example.com", "/", headers)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("upgrade with wrong credentials = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("a 401 without WWW-Authenticate is not actionable")
	}
}

// The rate limit spends a token on the upgrade request like any other; the
// refusal is a 429 with Retry-After, not a connection that hangs.
func TestWebSocketUpgradeMeetsTheRateLimit(t *testing.T) {
	_, route := wsEcho(t)
	route.RateLimit = &RateLimit{Requests: 1, Window: "1m", Per: "ip"}
	p := newTestProxy(t, route)

	upgradeHeaders := http.Header{
		"Connection":            []string{"Upgrade"},
		"Upgrade":               []string{"websocket"},
		"Sec-Websocket-Version": []string{"13"},
		"Sec-Websocket-Key":     []string{"dGhlIHNhbXBsZSBub25jZQ=="},
	}

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", upgradeHeaders)
	_ = resp.Body.Close()
	// httptest's recorder cannot be hijacked, so the first upgrade fails at the
	// hijack: after it spent its token, which is all this test needs.

	resp = request(p, http.MethodGet, "web.shop.example.com", "/", upgradeHeaders)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second upgrade = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a 429 without Retry-After leaves the client guessing")
	}
}

// A WebSocket is counted but never timed (§9.1.1): the observation's duration
// is the session's lifetime, and one long session would poison the p95 the
// autoscaler reads. The 101 lands in requests_total under protocol=websocket;
// the latency histograms never see it, which also keeps _count equal to the
// +Inf bucket, without which the exposition is malformed.
func TestAWebSocketIsCountedButNeverTimed(t *testing.T) {
	_, route := wsEcho(t)
	p := newTestProxy(t, route)

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := wsDial(ctx, t, strings.TrimPrefix(srv.URL, "http://"), "web.shop.example.com")
	echoOnce(ctx, t, c, "count me")
	c.Close(websocket.StatusNormalClosure, "done")

	// The observation is recorded when ServeHTTP returns, after the session
	// ends; the close above races it by a hair.
	waitFor(t, func() bool {
		return strings.Contains(render(t, p.Metrics()),
			`kanea_edge_service_requests_total{service="shop/web",code="101",method="GET",protocol="websocket"} 1`)
	}, "the websocket session was never observed")

	body := render(t, p.Metrics())
	if got := sample(t, body,
		`kanea_edge_service_request_duration_ms_count{service="shop/web",code="101",method="GET",protocol="websocket"}`); got != "0" {
		t.Errorf("labelled histogram _count = %s, want 0: a session length entered the latency histogram", got)
	}
	if got := sample(t, body, `kanea_edge_request_duration_ms_count{service="shop/web"}`); got != "0" {
		t.Errorf("aggregate histogram _count = %s, want 0", got)
	}
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/web"}`); got != "1" {
		t.Errorf("requests_total = %s, want 1; counted is not optional", got)
	}
	if got := sample(t, body,
		`kanea_edge_request_duration_ms_bucket{service="shop/web",le="+Inf"}`); got != "0" {
		t.Errorf("+Inf bucket = %s, want 0 (must equal _count)", got)
	}
}

// An upgrade attempted over HTTP/2 cannot be hijacked (http2's ResponseWriter
// is not a Hijacker) and the failure must be a clean 502, not a panic. The
// backend here answers 101 to a request that never asked to upgrade, which is
// exactly what the h2 path delivers: inbound h2 strips connection-specific
// headers, so the upstream's 101 is always unsolicited from the proxy's view.
func TestAnH2InboundUpgradeAttemptFailsCleanly(t *testing.T) {
	// A raw backend that answers every request with 101, holding the socket.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				_, _ = io.WriteString(c,
					"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				// Hold the connection until the proxy gives up on it.
				buf := make([]byte, 1)
				_, _ = br.Read(buf)
			}(conn)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	p := newTestProxy(t, Route{
		Project: "shop", Service: "web",
		Domains:  []string{"web.shop.example.com"},
		Upstream: tcpAddr.IP.String(), Port: tcpAddr.Port,
	})

	srv := httptest.NewUnstartedServer(p)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "web.shop.example.com"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("h2 request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.ProtoMajor != 2 {
		t.Fatalf("negotiated %s, want HTTP/2: the test is not exercising the h2 path", resp.Proto)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("h2 protocol-switch attempt = %d, want a clean 502", resp.StatusCode)
	}
}

// A published http listener shares serveRoute with host routing, so a
// WebSocket works on a node port exactly as it does on the domain.
func TestPublishedHTTPListenerCarriesWebSockets(t *testing.T) {
	wsSrv, _ := wsEcho(t)
	set, _ := newTestSet(t)

	u := splitUpstream(t, strings.TrimPrefix(wsSrv.URL, "http://"))
	cfg := testListener(9601, ListenerHTTP)
	cfg.Upstream, cfg.UpstreamPort = u.host, u.port
	set.Apply([]Listener{cfg})

	set.mu.Lock()
	addr := set.entries[entryKey{port: 9601}].ln.Addr().String()
	set.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A published port is reached by address; the Host header is whatever the
	// address is, and the route is fixed at bind time.
	c, _, err := websocket.Dial(ctx, "ws://"+addr+"/", nil)
	if err != nil {
		t.Fatalf("websocket dial on published port: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")
	echoOnce(ctx, t, c, "over the node port")
}

// Go's ReverseProxy flushes immediately for text/event-stream and for any
// response of unknown length, regardless of the configured FlushInterval.
// gRPC streaming (v1.41) relies on the unknown-length half of that rule, so
// this pins it: if a Go release ever changes it, streaming breaks here first.
func TestSSEFlushesImmediatelyDespiteTheConfiguredInterval(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))

	p := NewProxy(ProxyConfig{
		Logger: slog.New(slog.DiscardHandler),
		// An hour: if the first event arrives, it arrived because of the
		// immediate-flush rule, not because the interval elapsed.
		FlushInterval: time.Hour,
	})
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetTable(table)

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "web.shop.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	line := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, line); err != nil {
		t.Fatalf("reading the first event: %v", err)
	}
	if got := string(line); got != "data: first\n\n" {
		t.Errorf("first event = %q", got)
	}
}
