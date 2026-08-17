package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// The h2c upstream path (PRD §5.2.6, §6.2 R28, v1.41). gRPC needs HTTP/2 end
// to end: inbound is Go's automatic ALPN on :443 (pinned below), and outbound
// is the second shared transport a grpc-marked route selects. These tests use
// x/net/http2 directly rather than grpc-go: what the edge must get right are
// wire properties (prior-knowledge h2c, trailers, streaming flush), and a
// dependency on the gRPC stack would test its client more than this proxy.

// h2cUpstream is a backend that speaks prior-knowledge cleartext HTTP/2 and
// reports the protocol it saw.
func h2cUpstream(t *testing.T, handler http.HandlerFunc) Route {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = protocols
	srv.Start()
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().(*net.TCPAddr)
	return Route{
		Project: "shop", Service: "api",
		Domains:  []string{"api.shop.example.com"},
		Upstream: addr.IP.String(), Port: addr.Port,
		Protocol: RouteProtocolGRPC,
	}
}

// h2Client is a TLS client that negotiates HTTP/2 with the edge while dialling
// a loopback address: the grpc-test twin of trustingClient, which pins
// HTTP/1.1 by building its own http.Transport.
func h2Client(t *testing.T, cert Certificate, secureURL string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cert.CertPEM)) {
		t.Fatal("cannot parse the test certificate")
	}
	addr := strings.TrimPrefix(secureURL, "https://")
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(conn, cfg)
				return tc, tc.HandshakeContext(ctx)
			},
			TLSClientConfig: &tls.Config{
				RootCAs: pool, ServerName: cert.Domains[0], MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// The end-to-end property R28 exists for: a TLS+h2 request through a real
// edge reaches the upstream as cleartext HTTP/2, the response streams (a
// mid-stream chunk is readable before the handler finishes), and the gRPC
// trailer survives the trip.
func TestGRPCRouteDialsTheUpstreamOverH2C(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.json")
	bundlePath := filepath.Join(dir, "certs.json")

	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	route := h2cUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream saw %s, want cleartext HTTP/2", r.Proto)
		}
		if r.TLS != nil {
			t.Error("upstream saw TLS; h2c must be plaintext")
		}
		if r.URL.Path == "/warm" {
			// The poll below only needs routing to be live; the streaming
			// choreography is for the real call.
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = io.WriteString(w, "chunk1")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		_, _ = io.WriteString(w, "chunk2")
		w.Header().Set("Grpc-Status", "0")
	})
	if err := Publish(routesPath, Snapshot{Index: 1, Routes: []Route{route}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	cert := selfSigned(t, time.Now().Add(time.Hour), "api.shop.example.com")
	if err := PublishBundle(bundlePath, Bundle{Index: 1, Certificates: []Certificate{cert}}, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	_, secure := startTLSEdge(t, routesPath, bundlePath)
	client := h2Client(t, cert, secure)

	waitFor(t, func() bool {
		code, _ := tryGet(client, secure+"/warm", "api.shop.example.com")
		return code != 0 && code != http.StatusNotFound
	}, "the edge never picked up the grpc route")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://api.shop.example.com/pkg.Service/Method", strings.NewReader("frame"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("grpc-shaped request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.ProtoMajor != 2 {
		t.Fatalf("client negotiated %s, want HTTP/2", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The first chunk must arrive while the handler is still blocked:
	// streaming, not buffering (Go's ReverseProxy flushes immediately for
	// unknown-length responses regardless of FlushInterval).
	first := make([]byte, len("chunk1"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("reading the first chunk: %v", err)
	}
	if string(first) != "chunk1" {
		t.Fatalf("first chunk = %q", first)
	}
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the rest: %v", err)
	}
	if string(rest) != "chunk2" {
		t.Errorf("rest = %q", rest)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Grpc-Status trailer = %q, want 0; gRPC cannot signal completion without it", got)
	}
}

// An unmarked route keeps the HTTP/1.1 transport: the marker selects the
// transport, and its absence must select the old one byte-for-byte.
func TestAnUnmarkedRouteStillDialsHTTP1(t *testing.T) {
	saw := make(chan string, 1)
	_, route := upstream(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case saw <- r.Proto:
		default:
		}
	}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	_ = resp.Body.Close()
	select {
	case proto := <-saw:
		if !strings.HasPrefix(proto, "HTTP/1.") {
			t.Errorf("upstream saw %s, want HTTP/1.x", proto)
		}
	case <-time.After(time.Second):
		t.Fatal("the upstream saw no request")
	}
}

// An HTTP/1.1 client on a grpc-marked route is still forwarded: over h2c;
// and gets a well-formed h1 response back. Real gRPC clients never do this;
// the property matters because :80 exists and a curl must not wedge.
func TestAGRPCRouteServesAPlainHTTP1Client(t *testing.T) {
	route := h2cUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream saw %s, want HTTP/2 regardless of the inbound version", r.Proto)
		}
		_, _ = io.WriteString(w, "h1 in, h2c out")
	})
	p := NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)})
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetTable(table)

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.shop.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("h1 GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "h1 in, h2c out" {
		t.Errorf("status %d body %q", resp.StatusCode, body)
	}
}

// A dead upstream answers a request that is gRPC on the wire with the
// trailers-only refusal (200 + Grpc-Status 14) because a raw 502 renders as
// "unexpected HTTP status" garbage in a gRPC client. A plain request on the
// same route keeps the anonymous 502.
func TestADeadGRPCUpstreamRefusesInGRPCTerms(t *testing.T) {
	// A route to a port nothing listens on.
	dead := Route{
		Project: "shop", Service: "api",
		Domains:  []string{"api.shop.example.com"},
		Upstream: "127.0.0.1", Port: 1,
		Protocol: RouteProtocolGRPC,
	}
	p := newTestProxy(t, dead)

	srv := httptest.NewUnstartedServer(p)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := srv.Client()

	// gRPC on the wire: h2 + the content type.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/pkg.Service/Method", strings.NewReader("frame"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.shop.example.com"
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("grpc request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("grpc refusal status = %d, want 200 (trailers-only)", resp.StatusCode)
	}
	if got := resp.Header.Get("Grpc-Status"); got != "14" {
		t.Errorf("Grpc-Status = %q, want 14 (UNAVAILABLE)", got)
	}
	if got := resp.Header.Get("Grpc-Message"); strings.Contains(got, "127.0.0.1") {
		t.Errorf("Grpc-Message leaks the upstream address: %q", got)
	}

	// The same dead route, spoken to as plain HTTPS: the anonymous 502.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.shop.example.com"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("plain request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("plain refusal status = %d, want 502", resp.StatusCode)
	}
}

// The grpc label needs the route marker AND the wire to agree (§9.1.1): a
// browser's h2 GET to a grpc route stays https, so no client can mint the
// fourth protocol value by picking headers.
func TestGRPCLabelRequiresTheMarkerAndTheWire(t *testing.T) {
	route := h2cUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	p := NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)})
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetTable(table)

	srv := httptest.NewUnstartedServer(p)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := srv.Client()

	// gRPC on the wire.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/pkg.Service/Method", strings.NewReader("frame"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.shop.example.com"
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// A browser-shaped h2 GET to the same route.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.shop.example.com"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	body := render(t, p.Metrics())
	if got := sample(t, body,
		`kanea_edge_service_requests_total{service="shop/api",code="200",method="POST",protocol="grpc"}`); got != "1" {
		t.Errorf("grpc series = %s, want 1", got)
	}
	if got := sample(t, body,
		`kanea_edge_service_requests_total{service="shop/api",code="200",method="GET",protocol="https"}`); got != "1" {
		t.Errorf("https series = %s, want 1: the browser GET must not be labelled grpc", got)
	}
}

// A gRPC client-stream is a request body held open for the life of the call;
// the slow-body deadline must not kill it (the isUpgrade exemption, applied
// to h2 streams).
func TestAGRPCStreamOutlivesTheBodyTimeout(t *testing.T) {
	route := h2cUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		// Echo the body back as it arrives: a stand-in for a bidi stream.
		w.Header().Set("Content-Type", "application/grpc")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.Copy(w, r.Body)
	})
	p := NewProxy(ProxyConfig{
		Logger: slog.New(slog.DiscardHandler),
		// Short enough that a stream held open past it proves the exemption.
		BodyTimeout: 150 * time.Millisecond,
	})
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetTable(table)

	srv := httptest.NewUnstartedServer(p)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/pkg.Service/Stream", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.shop.example.com"
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Hold the stream open for several body-timeout multiples, then write.
	time.Sleep(600 * time.Millisecond)
	if _, err := io.WriteString(pw, "late frame"); err != nil {
		t.Fatalf("writing after the timeout window: %v", err)
	}
	_ = pw.Close()

	echoed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("the stream died: %v", err)
	}
	if string(echoed) != "late frame" {
		t.Errorf("echoed = %q", echoed)
	}
}

// Inbound HTTP/2 on :443 is Go's automatic ALPN: nothing in the edge
// configures it, which means nothing stops a future tls.Config edit from
// turning it off silently. This is the tripwire.
func TestInboundTLSNegotiatesHTTP2(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.json")
	bundlePath := filepath.Join(dir, "certs.json")

	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	if err := Publish(routesPath, Snapshot{Index: 1, Routes: []Route{route}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	cert := selfSigned(t, time.Now().Add(time.Hour), "web.shop.example.com")
	if err := PublishBundle(bundlePath, Bundle{Index: 1, Certificates: []Certificate{cert}}, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	_, secure := startTLSEdge(t, routesPath, bundlePath)
	client := h2Client(t, cert, secure)

	waitFor(t, func() bool {
		code, _ := tryGet(client, secure+"/", "web.shop.example.com")
		return code == http.StatusOK
	}, "the edge never served the route over TLS")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://web.shop.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2 GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Errorf("negotiated %s, want HTTP/2; gRPC support just silently broke", resp.Proto)
	}
}
