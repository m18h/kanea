package edge

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// upstream starts a backend and returns a Route pointing at it.
func upstream(t *testing.T, h http.Handler) (*httptest.Server, Route) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split upstream address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("upstream port: %v", err)
	}
	return srv, Route{
		Project: "shop", Service: "web",
		Domains:  []string{"web.shop.example.com"},
		Upstream: host, Port: port,
	}
}

// newTestProxy wires a proxy to the given routes.
func newTestProxy(t *testing.T, routes ...Route) *Proxy {
	t.Helper()
	p := NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)})
	table, err := NewTable(Snapshot{Routes: routes})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(table)
	return p
}

// request drives one request through the proxy handler.
func request(p *Proxy, method, host, path string, header http.Header) *http.Response {
	r := httptest.NewRequest(method, path, nil)
	r.Host = host
	for name, values := range header {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w.Result()
}

func TestProxyRoutesByHost(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from web")
	}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from web" {
		t.Errorf("body = %q", body)
	}
}

// An unknown Host is a 404 and nothing else: no default backend, no redirect.
// It is also the DNS-rebinding defense for whatever else lives on this address.
func TestProxyRefusesAnUnknownHost(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("an unrouted host reached the upstream")
		w.WriteHeader(http.StatusOK)
	}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "attacker.example.com", "/", nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestProxyRejectsForwardProxyUse(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a CONNECT reached the upstream")
	}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodConnect, "web.shop.example.com", "/", nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// The whole reason the edge owns these headers: a client that can set them can
// claim to be any address, and IP restriction, rate limiting and every access
// log downstream are keyed on exactly that.
func TestProxyStripsClientForwardingHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	p := newTestProxy(t, route)

	spoofed := http.Header{}
	for _, name := range forwardedHeaders {
		spoofed.Set(name, "10.9.9.9")
	}
	resp := request(p, http.MethodGet, "web.shop.example.com", "/", spoofed)
	defer func() { _ = resp.Body.Close() }()

	header := <-seen
	if got := header.Get("X-Forwarded-For"); got == "10.9.9.9" {
		t.Error("the client's X-Forwarded-For survived; the identity is forgeable")
	}
	// httptest.NewRequest uses 192.0.2.1:1234 as the peer.
	if got := header.Get("X-Forwarded-For"); !strings.Contains(got, "192.0.2.1") {
		t.Errorf("X-Forwarded-For = %q, want the real peer address", got)
	}
	for _, name := range []string{"Forwarded", "X-Real-Ip", "X-Forwarded-Ssl", "X-Original-Forwarded-For"} {
		if got := header.Get(name); got == "10.9.9.9" {
			t.Errorf("%s = %q survived from the client", name, got)
		}
	}
	if got := header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http on a plaintext listener", got)
	}
	if got := header.Get("X-Forwarded-Host"); got != "web.shop.example.com" {
		t.Errorf("X-Forwarded-Host = %q", got)
	}
}

// An application that builds absolute URLs from Host must see the name the
// client asked for, not the private frontend address.
func TestProxyPreservesTheClientHost(t *testing.T) {
	seen := make(chan string, 1)
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		w.WriteHeader(http.StatusOK)
	}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	defer func() { _ = resp.Body.Close() }()

	if host := <-seen; host != "web.shop.example.com" {
		t.Errorf("upstream saw Host %q, want the client's", host)
	}
}

// A 502 tells the client the request failed and nothing else, not the internal
// address, not the service name, not why.
func TestProxyLeaksNothingWhenTheUpstreamIsDown(t *testing.T) {
	srv, route := upstream(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // the address is now dead but still routable
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, secret := range []string{route.Upstream, "shop", "web", strconv.Itoa(route.Port)} {
		if strings.Contains(string(body), secret) {
			t.Errorf("the 502 body %q leaks %q", body, secret)
		}
	}
}

func TestProxyRequiresAHost(t *testing.T) {
	p := newTestProxy(t)
	resp := request(p, http.MethodGet, "", "/", nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// A reload swaps a whole new table in; requests after it use the new routes.
func TestProxyTableSwap(t *testing.T) {
	_, first := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "first")
	}))
	_, second := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "second")
	}))
	second.Domains = first.Domains

	p := newTestProxy(t, first)
	table, err := NewTable(Snapshot{Routes: []Route{second}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(table)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "second" {
		t.Errorf("body = %q, want the new route's upstream", body)
	}
}

// K-11: client-sent Upgrade headers no longer exempt a request from the
// slow-body bound. A real WebSocket handshake has no body (ContentLength == 0
// exempts it); an "upgrade" carrying a gigabyte body that arrives a byte a
// minute is the abuse case, and the deadline must still fire.
func TestProxyDoesNotExemptAnUpgradeWithABody(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	p := NewProxy(ProxyConfig{
		Logger:      slog.New(slog.DiscardHandler),
		BodyTimeout: 50 * time.Millisecond,
	})
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(table)

	edgeSrv := httptest.NewServer(p)
	defer edgeSrv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(edgeSrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	head := "POST / HTTP/1.1\r\n" +
		"Host: web.shop.example.com\r\n" +
		"Connection: upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Content-Length: 1000000000\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	// One byte, then silence: the dribble the bound exists to stop.
	if _, err := io.WriteString(conn, "x"); err != nil {
		t.Fatalf("write first body byte: %v", err)
	}

	// Well past BodyTimeout: with the exemption in force this connection stays
	// open indefinitely; without it the server-side deadline fires and the
	// connection closes. The upstream's response may arrive first (it never
	// read the body), so read until an error rather than at the first byte.
	time.Sleep(150 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	for {
		var buf [256]byte
		if _, err := br.Read(buf[:]); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("the dribbled connection outlived the deadline: the upgrade headers exempted it")
			}
			return // EOF or reset: the server-side deadline fired
		}
	}
}

// The reason there is no server-wide ReadTimeout: it would fire on Go's
// background disconnect-detection read, cancel the request context, and kill a
// connection that upgraded to something long-lived.
func TestProxyPassesThroughAnUpgrade(t *testing.T) {
	backend := &upgradeBackend{t: t}
	_, route := upstream(t, backend)

	p := NewProxy(ProxyConfig{
		Logger: slog.New(slog.DiscardHandler),
		// Aggressively short, so a body deadline wrongly applied to an upgraded
		// connection would show up as a failure rather than as a slow test.
		BodyTimeout: 50 * time.Millisecond,
	})
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(table)

	edgeSrv := httptest.NewServer(p)
	defer edgeSrv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(edgeSrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	handshake := "GET /ws HTTP/1.1\r\n" +
		"Host: web.shop.example.com\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: kanea-test\r\n\r\n"
	if _, err := io.WriteString(conn, handshake); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Well past BodyTimeout: a deadline left on this connection would break it.
	time.Sleep(150 * time.Millisecond)
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write after upgrade: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read after upgrade: %v", err)
	}
	if strings.TrimSpace(line) != "pong" {
		t.Errorf("read %q, want pong", line)
	}
}

// upgradeBackend answers an upgrade request and then echoes "ping" as "pong"
// over the raw connection.
type upgradeBackend struct{ t *testing.T }

func (b *upgradeBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") == "" {
		http.Error(w, "not an upgrade", http.StatusBadRequest)
		return
	}
	conn, br, err := http.NewResponseController(w).Hijack()
	if err != nil {
		b.t.Errorf("hijack: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn,
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: kanea-test\r\n\r\n"); err != nil {
		return
	}
	line, err := br.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ping" {
		return
	}
	_, _ = io.WriteString(conn, "pong\n")
}

func TestIsUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		upgrade    string
		want       bool
	}{
		{"websocket", "Upgrade", "websocket", true},
		{"mixed case", "upgrade", "WebSocket", true},
		{"listed with keep-alive", "keep-alive, Upgrade", "websocket", true},
		{"no upgrade header", "Upgrade", "", false},
		{"plain request", "keep-alive", "", false},
		{"substring is not a token", "Upgraded", "websocket", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.connection != "" {
				r.Header.Set("Connection", tc.connection)
			}
			if tc.upgrade != "" {
				r.Header.Set("Upgrade", tc.upgrade)
			}
			if got := isUpgrade(r); got != tc.want {
				t.Errorf("isUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}
