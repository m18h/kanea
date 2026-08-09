package edge

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// A client that has finished sending must be able to keep reading. Postgres and
// most line protocols depend on seeing EOF while still writing back; without
// CloseWrite the peer waits for input that will never come and the session
// hangs with no error anywhere.
func TestRelayHalfClose(t *testing.T) {
	// The far side reads to EOF, then answers. It cannot answer before EOF —
	// that is the whole point of the test.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		body, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("saw: "), body...))
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	front, _ := relayFront(t, upstreamListener(t, upstream))
	client, err := net.Dial("tcp", front)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("SELECT 1")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "saw: SELECT 1" {
		t.Errorf("response = %q; the half-close did not reach the upstream", got)
	}
}

// ip_restriction is checked at accept time, before the upstream is dialled. It
// has to be: on a tcp listener the upstream sees the edge's address rather than
// the client's, so it cannot make this decision itself.
func TestRelayIPRestrictionRefusesBeforeDialling(t *testing.T) {
	var dialled bool
	cfg := testListener(0, ListenerTCP)
	cfg.IPRestriction = &IPRestriction{Allow: []string{"203.0.113.0/24"}}

	metrics := NewMetrics()
	relay, err := newRelay(cfg, newConnLimiter(10), slog.New(slog.DiscardHandler), metrics,
		func(string, string) (net.Conn, error) {
			dialled = true
			return nil, nil
		})
	if err != nil {
		t.Fatalf("newRelay: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go relay.serve(ln)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// 127.0.0.1 is not in 203.0.113.0/24, so the connection is closed and the
	// upstream is never contacted.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("read: %v", err)
	}
	if dialled {
		t.Error("a refused address still reached the upstream dialler")
	}
}

// Refused when full, never queued. A queued TCP connection looks connected to
// the client and is not, so it waits out its own timeout instead of failing
// over to something that works.
func TestRelayRefusesWhenFull(t *testing.T) {
	limiter := newConnLimiter(1)
	if !limiter.acquire() {
		t.Fatal("the first connection was refused")
	}
	if limiter.acquire() {
		t.Error("a full limiter handed out a second slot")
	}
	if got := limiter.inFlight(); got != 1 {
		t.Errorf("inFlight = %d, want 1", got)
	}
	limiter.release()
	if !limiter.acquire() {
		t.Error("a released slot was not reusable")
	}

	// A zero maximum is unlimited rather than closed: it is what an unset
	// --max-published-conns means, and refusing everything there would take the
	// feature down by default.
	unlimited := newConnLimiter(0)
	for range 100 {
		if !unlimited.acquire() {
			t.Fatal("a zero limit refused a connection")
		}
	}
}

// relayFront binds a relay in front of an upstream and returns its address
// along with the collector it counts into.
func relayFront(t *testing.T, upstream fakeUpstream) (string, *Metrics) {
	t.Helper()
	cfg := testListener(0, ListenerTCP)
	cfg.Upstream, cfg.UpstreamPort = upstream.host, upstream.port

	metrics := NewMetrics()
	relay, err := newRelay(cfg, newConnLimiter(10), slog.New(slog.DiscardHandler), metrics, nil)
	if err != nil {
		t.Fatalf("newRelay: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go relay.serve(ln)
	return ln.Addr().String(), metrics
}

func upstreamListener(t *testing.T, ln net.Listener) fakeUpstream {
	t.Helper()
	return splitUpstream(t, ln.Addr().String())
}

// Published ports had no counters at all before v1.35 — ErrTooManyConns
// carried a comment saying it existed "so the refusal is countable" while
// nothing counted it (PRD §9.1.1, §7.2.2).

func TestRelayCountsTheRefusalReason(t *testing.T) {
	cfg := testListener(0, ListenerTCP)
	cfg.IPRestriction = &IPRestriction{Allow: []string{"203.0.113.0/24"}}

	metrics := NewMetrics()
	relay, err := newRelay(cfg, newConnLimiter(10), slog.New(slog.DiscardHandler), metrics, nil)
	if err != nil {
		t.Fatalf("newRelay: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go relay.serve(ln)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("read: %v", err)
	}

	entrypoint := EntrypointForPort(cfg.Port)
	body := render(t, metrics)
	// The reason is the point. "Refused" alone cannot tell an operator whether
	// their allowlist is working or their connection ceiling is too low, and
	// those call for opposite responses.
	if got := sample(t, body, `kanea_edge_tcp_refused_total{service="`+cfg.Name()+
		`",entrypoint="`+entrypoint+`",reason="ip_restriction"}`); got != "1" {
		t.Errorf("ip_restriction refusals = %s, want 1", got)
	}
	// A refused connection was never relayed. Counting it as accepted would
	// make a listener at its ceiling look busy rather than full.
	if got := sample(t, body, `kanea_edge_tcp_connections_total{service="`+cfg.Name()+
		`",entrypoint="`+entrypoint+`"}`); got != "0" {
		t.Errorf("accepted = %s; a refused connection was counted as accepted", got)
	}
}

func TestRelayCountsBytesInBothDirections(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		body, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("saw: "), body...))
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	front, metrics := relayFront(t, upstreamListener(t, upstream))
	client, err := net.Dial("tcp", front)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	const payload = "SELECT 1"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw, ok := client.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("read: %v", err)
	}

	// The relay's deferred close runs after the last copy returns; give it the
	// moment it needs rather than racing it.
	deadline := time.Now().Add(2 * time.Second)
	label := `kanea_edge_tcp_bytes_in_total{service="` + testListener(0, ListenerTCP).Name() +
		`",entrypoint="` + EntrypointForPort(testListener(0, ListenerTCP).Port) + `"}`
	var in string
	for time.Now().Before(deadline) {
		if in = sample(t, render(t, metrics), label); in != "0" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if in != "8" {
		t.Errorf("bytes in = %s, want %d — the counts come from io.Copy's own return, "+
			"so a wrapper that broke the splice fast path would also break this", in, len(payload))
	}
}
