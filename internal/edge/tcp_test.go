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

	front := relayFront(t, upstreamListener(t, upstream))
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

	relay, err := newRelay(cfg, newConnLimiter(10), slog.New(slog.DiscardHandler),
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

// relayFront binds a relay in front of an upstream and returns its address.
func relayFront(t *testing.T, upstream fakeUpstream) string {
	t.Helper()
	cfg := testListener(0, ListenerTCP)
	cfg.Upstream, cfg.UpstreamPort = upstream.host, upstream.port

	relay, err := newRelay(cfg, newConnLimiter(10), slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatalf("newRelay: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go relay.serve(ln)
	return ln.Addr().String()
}

func upstreamListener(t *testing.T, ln net.Listener) fakeUpstream {
	t.Helper()
	return splitUpstream(t, ln.Addr().String())
}
