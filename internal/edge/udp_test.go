package edge

import (
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"
)

// udpBackend is a fake service: it answers every datagram with "saw: <body>".
// udpBytesOut totals what the relay has written back to its clients.
//
// The reply loop touches a session immediately before it writes, so a non-zero
// total is proof the touch has already happened — which is what makes it safe
// to move the clock out from under it.
func udpBytesOut(u *udpRelay) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	var total int64
	for _, s := range u.sessions {
		total += s.bytesOut.Load()
	}
	return total
}

func udpBackend(t *testing.T) (ip string, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("saw: "), buf[:n]...), addr)
		}
	}()
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

// udpFront builds a serving relay on an ephemeral port and returns it with its
// address.
func udpFront(t *testing.T, cfg Listener, metrics *Metrics) (*udpRelay, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	relay, err := newUDPRelay(cfg, pc, newConnLimiter(64), slog.New(slog.DiscardHandler), metrics, nil)
	if err != nil {
		t.Fatalf("newUDPRelay: %v", err)
	}
	go relay.serve()
	t.Cleanup(func() {
		_ = pc.Close()
		relay.closeLive()
	})
	return relay, pc.LocalAddr().String()
}

// setClock swaps the relay's clock under its lock, the way clock() reads it.
func setClock(relay *udpRelay, now func() time.Time) {
	relay.mu.Lock()
	relay.now = now
	relay.mu.Unlock()
}

func udpListenerFor(ip string, port int) Listener {
	return Listener{
		Project: "games", Service: "factorio",
		Port: 34197, Mode: ListenerUDP,
		UpstreamPort: port, Backends: []string{ip},
	}
}

// The whole feature, end to end: a datagram in, a session created, the
// backend's answer relayed back to the same client.
func TestUDPRelayRoundTrip(t *testing.T) {
	ip, port := udpBackend(t)
	relay, front := udpFront(t, udpListenerFor(ip, port), NewMetrics())

	client, err := net.Dial("udp", front)
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "saw: ping" {
		t.Errorf("reply = %q", got)
	}
	if got := relay.liveCount(); got != 1 {
		t.Errorf("sessions = %d, want 1", got)
	}
}

// ip_restriction is checked on the datagram that would create a session — the
// accept-time hook a datagram socket lacks, recovered at the only moment there
// is — and a refused client's datagrams never reach a backend.
func TestUDPRelayIPRestrictionRefusesBeforeDialling(t *testing.T) {
	cfg := udpListenerFor("127.0.0.1", 9)
	cfg.IPRestriction = &IPRestriction{Allow: []string{"203.0.113.0/24"}}

	dialled := false
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	metrics := NewMetrics()
	relay, err := newUDPRelay(cfg, pc, newConnLimiter(4), slog.New(slog.DiscardHandler), metrics,
		func(string, string) (net.Conn, error) {
			dialled = true
			return nil, net.ErrClosed
		})
	if err != nil {
		t.Fatalf("newUDPRelay: %v", err)
	}

	relay.handle([]byte("nope"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 5000})
	if dialled {
		t.Error("a refused datagram dialled the backend")
	}
	if relay.liveCount() != 0 {
		t.Error("a refused datagram left a session behind")
	}
	if got := metrics.udpCounters("games/factorio", EntrypointForPort(34197)); loadCounter(&got.mu, got.refused, ReasonIPRestriction) != 1 {
		t.Error("the refusal was not counted")
	}
}

// A datagram with no backends is dropped and counted — UDP has no way to tell
// the client, so the operator's counter is the only witness.
func TestUDPRelayCountsDropsWithNoBackends(t *testing.T) {
	cfg := udpListenerFor("127.0.0.1", 9)
	cfg.Backends = nil
	metrics := NewMetrics()
	relay, front := udpFront(t, cfg, metrics)

	client, err := net.Dial("udp", front)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	_, _ = client.Write([]byte("void"))

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := metrics.udpCounters("games/factorio", EntrypointForPort(34197))
		if loadCounter(&got.mu, got.refused, ReasonNoBackends) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the drop was never counted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if relay.liveCount() != 0 {
		t.Error("a backendless datagram opened a session")
	}
}

// The per-listener session cap refuses, never queues, and the refusal is
// counted under its own reason.
func TestUDPRelayRefusesAtItsSessionCap(t *testing.T) {
	ip, port := udpBackend(t)
	cfg := udpListenerFor(ip, port)
	cfg.MaxConns = 1
	metrics := NewMetrics()
	relay, _ := udpFront(t, cfg, metrics)

	// Injected directly rather than through the socket, so the two clients
	// arrive in a deterministic order.
	relay.handle([]byte("one"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001})
	relay.handle([]byte("two"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002})

	if got := relay.liveCount(); got != 1 {
		t.Errorf("sessions = %d, want the cap to hold at 1", got)
	}
	got := metrics.udpCounters("games/factorio", EntrypointForPort(34197))
	if loadCounter(&got.mu, got.refused, ReasonListenerLimit) != 1 {
		t.Error("the cap refusal was not counted")
	}
}

// An idle session is swept, counted as expired, and the client's next datagram
// simply re-creates it — on the same backend, because the choice is a hash.
func TestUDPRelayExpiresIdleSessions(t *testing.T) {
	ip, port := udpBackend(t)
	metrics := NewMetrics()
	relay, _ := udpFront(t, udpListenerFor(ip, port), metrics)

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	relay.handle([]byte("hello"), client)
	if relay.liveCount() != 1 {
		t.Fatal("no session was created")
	}

	// Wait for the echo before touching the clock. The backend replies, and the
	// reply loop stamps the session with the *relay's* clock when it does — so
	// a stamp that lands after the clock moves puts lastActive two timeouts in
	// the future, where no deadline can ever be earlier than it. The session is
	// then immortal, the janitor finds nothing to collect, and the sweep below
	// waits out its two seconds for a session that was never going to go. That
	// is a real flake, seen on CI and reproduced by forcing this ordering; it
	// is not a bug in the janitor. Once the echo is accounted for nothing else
	// moves, so the clock is safe.
	waitFor(t, func() bool { return udpBytesOut(relay) > 0 }, "the echo to be relayed back")

	// The clock moves; the janitor runs.
	setClock(relay, func() time.Time { return time.Now().Add(2 * udpIdleTimeout) })
	relay.expireIdle()

	deadline := time.Now().Add(2 * time.Second)
	for relay.liveCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the idle session was never swept")
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := metrics.udpCounters("games/factorio", EntrypointForPort(34197))
	if got.expired.Load() != 1 {
		t.Error("the expiry was not counted as one")
	}

	setClock(relay, time.Now)
	relay.handle([]byte("again"), client)
	if relay.liveCount() != 1 {
		t.Error("the client's next datagram did not re-create the session")
	}
}

// A config update ends only the sessions whose backend left; everyone else's
// conversation continues on the socket it started with.
func TestUDPRelayUpdateDropsOnlyDepartedBackends(t *testing.T) {
	ip1, port1 := udpBackend(t)
	cfg := udpListenerFor(ip1, port1)
	cfg.Backends = []string{"127.0.0.1"}
	relay, _ := udpFront(t, cfg, NewMetrics())

	relay.handle([]byte("hi"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001})
	if relay.liveCount() != 1 {
		t.Fatal("no session was created")
	}

	// The one backend leaves; its session must go with it.
	gone := cfg
	gone.Backends = []string{"127.0.0.2"}
	if err := relay.update(gone); err != nil {
		t.Fatalf("update: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for relay.liveCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the departed backend's session survived the update")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Rendezvous hashing: a stable choice per client, and a departing backend
// moves only its own clients.
func TestPickBackendIsStableAndMinimallyDisruptive(t *testing.T) {
	backends := []string{"10.244.0.1", "10.244.0.2", "10.244.0.3"}
	clients := make([]string, 0, 100)
	for i := range 100 {
		clients = append(clients, "192.168.1."+strconv.Itoa(i))
	}

	before := map[string]string{}
	for _, c := range clients {
		choice := pickBackend(c, backends)
		if choice != pickBackend(c, backends) {
			t.Fatalf("client %s got two different backends for one set", c)
		}
		before[c] = choice
	}

	// Remove one backend: only its clients may move.
	survivors := []string{"10.244.0.1", "10.244.0.3"}
	for _, c := range clients {
		after := pickBackend(c, survivors)
		if before[c] != "10.244.0.2" && after != before[c] {
			t.Errorf("client %s moved from %s to %s though its backend never left",
				c, before[c], after)
		}
	}
}
