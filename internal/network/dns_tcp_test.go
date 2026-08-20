package network

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The TCP half of the resolver (PRD v1.86).
//
// The whole reason it exists is that three code paths set the TC bit and every
// one of them told a client to retry over a transport nothing was listening on.
// So the tests that matter are: the listener answers at all, it answers on the
// *same port* the datagram half bound, and an answer that UDP would truncate
// comes back whole here rather than truncated again.

// serveTCP starts d and returns its bound address, which is both transports'.
func serveTCP(t *testing.T, d *DNS) string {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx) }() //nolint:errcheck // Serve returns the context's error at shutdown

	var addr string
	for range 200 {
		if addr = d.Addr(); addr != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server never bound")
	}

	// Addr() reports the UDP bind, and Serve completes that before it binds TCP
	// on the resolved port (dns.go: the two must answer on one port, so the
	// order is forced). A non-empty Addr is therefore not proof that the TCP
	// listener exists, and dialling on that signal alone is a race that
	// surfaces as "connection refused" on a loaded machine - which is how it
	// failed in CI while passing 40 consecutive local runs.
	//
	// Observed rather than probed: a dial would consume a slot, and
	// TestTheTCPConnectionCapRefusesAndCounts runs with MaxTCPConns=1, where
	// spending the only one here refuses the connection the test came to make.
	// The bind is what matters anyway - the kernel queues connections from
	// ListenTCP onward, so there is nothing to wait for past this pointer.
	for range 200 {
		if d.listener.Load() != nil {
			return addr
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("tcp listener never bound")
	return addr
}

// askTCP sends one length-prefixed query and returns the reply body.
func askTCP(t *testing.T, addr string, request []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck // test cleanup
	return exchange(t, conn, request)
}

// exchange writes one framed query on an open connection and reads one reply,
// so a test can prove the connection is reused rather than one-shot.
func exchange(t *testing.T, conn net.Conn, request []byte) []byte {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(request)))
	if _, err := conn.Write(append(framed, request...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var header [2]byte
	if _, err := readFullTest(conn, header[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err := readFullTest(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

func readFullTest(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func TestTheResolverAnswersOverTCP(t *testing.T) {
	d := testDNS(t)
	addr := serveTCP(t, d)

	r := parseReply(t, askTCP(t, addr, buildQuery(t, 0x2468, "web.shop.kanea", typeA, true)))
	if r.ID != 0x2468 {
		t.Errorf("id = %#x, want 0x2468", r.ID)
	}
	if r.RCode != rcodeNoError || !r.AA {
		t.Fatalf("rcode = %d, authoritative = %v; want an authoritative answer", r.RCode, r.AA)
	}
	if len(r.Answers) != 1 || r.Answers[0].String() != "10.201.0.1" {
		t.Fatalf("answers = %v, want the frontend VIP", r.Answers)
	}
}

// The port is the whole point: a client that gets TC on UDP retries the same
// address, and two independent binds with a configured port of 0 would answer
// on two different ephemeral ports.
func TestBothTransportsShareOnePort(t *testing.T) {
	d := testDNS(t)
	addr := serveTCP(t, d)

	tcp, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("the TCP listener is not on the UDP port (%s): %v", addr, err)
	}
	_ = tcp.Close() //nolint:errcheck // test cleanup
}

// RFC 7766 asks for connection reuse, and the idle timeout is what bounds it;
// a one-shot connection would make every lookup a fresh handshake.
func TestATCPConnectionCarriesMoreThanOneQuery(t *testing.T) {
	d := testDNS(t)
	addr := serveTCP(t, d)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck // test cleanup

	for id := uint16(1); id <= 3; id++ {
		r := parseReply(t, exchange(t, conn, buildQuery(t, id, "web.shop.kanea", typeA, true)))
		if r.ID != id || len(r.Answers) != 1 {
			t.Fatalf("query %d on a reused connection: id = %d, answers = %v", id, r.ID, r.Answers)
		}
	}
}

// An answer too big for a datagram is exactly what TC exists to signal, so the
// transport it points at must be able to carry it. Same server, same question,
// two transports, two different outcomes: this is the defect in one test.
func TestALargeAnswerTruncatesOnUDPAndSurvivesOnTCP(t *testing.T) {
	d := testDNS(t)

	// One name holding far more addresses than 512 bytes can express. Record
	// names are written out in full rather than as compression pointers, so
	// each answer costs about thirty bytes and sixty of them is comfortably
	// over the datagram ceiling and comfortably under the frame's.
	const count = 60
	addrs := make([]netip.Addr, 0, count)
	for i := range count {
		addrs = append(addrs, netip.AddrFrom4([4]byte{10, 200, byte(i), 5}))
	}
	name := ServiceName("shop", "web")
	d.zone.Store(&zone{records: map[string][]netip.Addr{name: addrs}})

	udp := parseReply(t, d.respondUDP(t.Context(), buildQuery(t, 11, name, typeA, true)))
	if !udp.TC || udp.NumAnswr != 0 {
		t.Fatalf("over UDP: TC = %v, answers = %d; want truncated with no records", udp.TC, udp.NumAnswr)
	}

	addr := serveTCP(t, d)
	tcp := parseReply(t, askTCP(t, addr, buildQuery(t, 11, name, typeA, true)))
	if tcp.TC {
		t.Fatal("over TCP: TC is set; the retry the UDP answer asked for was truncated again")
	}
	if len(tcp.Answers) != count {
		t.Fatalf("over TCP: %d answers, want all %d", len(tcp.Answers), count)
	}
}

// A cap nobody can see is indistinguishable from packet loss (the v1.42 rule),
// so the refusal is counted; and it is a refusal rather than a queue, which is
// the discipline forwardSlots already applies one layer in.
func TestTheTCPConnectionCapRefusesAndCounts(t *testing.T) {
	d, err := NewDNS(DNSConfig{Listen: "127.0.0.1:0", MaxTCPConns: 1})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	d.SetZone([]Service{{Project: "shop", Service: "web", VIP: "10.201.0.1"}})
	addr := serveTCP(t, d)

	// Hold the only slot with a connection that has asked something, so the
	// handler is certainly past accept and inside its read loop.
	held, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer func() { _ = held.Close() }() //nolint:errcheck // test cleanup
	if r := parseReply(t, exchange(t, held, buildQuery(t, 1, "web.shop.kanea", typeA, true))); r.RCode != rcodeNoError {
		t.Fatalf("the held connection was not served: rcode = %d", r.RCode)
	}

	// The next one is accepted and closed immediately rather than answered.
	for range 100 {
		if d.tcpRefused.Load() > 0 {
			break
		}
		extra, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			break // the listener refused at the socket layer, which is also a refusal
		}
		_ = extra.SetDeadline(time.Now().Add(time.Second)) //nolint:errcheck // best effort
		framed := binary.BigEndian.AppendUint16(nil, uint16(12))
		_, _ = extra.Write(append(framed, make([]byte, 12)...)) //nolint:errcheck // the peer may already be gone
		_, _ = extra.Read(make([]byte, 2))                      //nolint:errcheck // expected to fail
		_ = extra.Close()                                       //nolint:errcheck // test cleanup
		time.Sleep(5 * time.Millisecond)
	}
	if d.tcpRefused.Load() == 0 {
		t.Fatal("no connection was refused, and none was counted; the cap is invisible")
	}
}

// Shutdown must not wait out an idle client's read deadline. Closing the
// listener unblocks Accept and nothing else: an accepted connection sitting in
// its read loop keeps its own goroutine, and Serve waits on that goroutine, so
// without a close on cancellation every idle client adds its idle timeout to
// shutdown. Verified against the unfixed code, where this takes the full 10s.
func TestShutdownDoesNotWaitForAnIdleTCPClient(t *testing.T) {
	d := testDNS(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Serve(ctx) }()

	var addr string
	for range 200 {
		if addr = d.Addr(); addr != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Ask once so the handler is certainly inside its read loop, then go idle.
	_ = exchange(t, conn, buildQuery(t, 1, "web.shop.kanea", typeA, true))

	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return; it is waiting out the idle timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s; an idle client held it", elapsed)
	}
}
