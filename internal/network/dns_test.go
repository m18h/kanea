package network

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// buildQuery encodes a question the way a resolver would.
func buildQuery(t *testing.T, id uint16, name string, qtype uint16, recursionDesired bool) []byte {
	t.Helper()
	encoded, err := encodeName(name)
	if err != nil {
		t.Fatalf("encode %q: %v", name, err)
	}
	var flags uint16
	if recursionDesired {
		flags |= flagRecursionDesired
	}
	buf := make([]byte, 0, dnsHeaderLen+len(encoded)+4)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, flags)
	buf = binary.BigEndian.AppendUint16(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = append(buf, encoded...)
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, classIN)
	return buf
}

// reply is a decoded response, enough to assert on.
type reply struct {
	ID       uint16
	RCode    uint16
	AA       bool
	TC       bool
	Answers  []netip.Addr
	NumAnswr int
}

// parseReply decodes a response produced by this server. It walks the answer
// section by hand rather than reusing production code, so a bug in the encoder
// cannot be cancelled out by the same bug in the decoder.
func parseReply(t *testing.T, buf []byte) reply {
	t.Helper()
	if len(buf) < dnsHeaderLen {
		t.Fatalf("reply is %d bytes, shorter than a header", len(buf))
	}
	var r reply
	r.ID = binary.BigEndian.Uint16(buf[0:2])
	flags := binary.BigEndian.Uint16(buf[2:4])
	r.RCode = flags & rcodeMask
	r.AA = flags&flagAuthoritative != 0
	r.TC = flags&flagTruncated != 0
	if flags&flagResponse == 0 {
		t.Error("response bit is not set on a reply")
	}
	r.NumAnswr = int(binary.BigEndian.Uint16(buf[6:8]))

	// Skip the question section.
	offset := dnsHeaderLen
	if binary.BigEndian.Uint16(buf[4:6]) == 1 {
		for offset < len(buf) {
			length := int(buf[offset])
			offset++
			if length == 0 {
				break
			}
			offset += length
		}
		offset += 4
	}

	for range r.NumAnswr {
		for offset < len(buf) {
			length := int(buf[offset])
			offset++
			if length == 0 {
				break
			}
			offset += length
		}
		if offset+10 > len(buf) {
			t.Fatalf("answer record truncated")
		}
		rrType := binary.BigEndian.Uint16(buf[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(buf[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(buf) {
			t.Fatalf("answer rdata truncated")
		}
		if (rrType == typeA && rdlen == 4) || (rrType == typeAAAA && rdlen == 16) {
			addr, _ := netip.AddrFromSlice(buf[offset : offset+rdlen])
			r.Answers = append(r.Answers, addr)
		}
		offset += rdlen
	}
	return r
}

func testDNS(t *testing.T, upstreams ...string) *DNS {
	t.Helper()
	d, err := NewDNS(DNSConfig{
		Listen: "127.0.0.1:0", Upstreams: upstreams,
		ForwardTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	d.SetZone([]Service{{
		Project: "shop", Service: "web", VIP: "10.201.0.1",
		Backends: []Backend{
			{AllocID: "shop-web-0", IPv4: "10.200.1.5"},
			{AllocID: "shop-web-1", IPv4: "10.200.1.6"},
		},
	}})
	return d
}

func TestDNSResolvesServiceToFrontend(t *testing.T) {
	d := testDNS(t)

	q := buildQuery(t, 0x1234, "web.shop.kanea", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.ID != 0x1234 {
		t.Errorf("id = %#x, want 0x1234", r.ID)
	}
	if r.RCode != rcodeNoError || !r.AA {
		t.Errorf("rcode = %d, authoritative = %v", r.RCode, r.AA)
	}
	// The service name must resolve to the VIP, not to a backend. Handing out
	// alloc addresses would let a client cache one and keep using it after the
	// alloc behind it went away.
	if len(r.Answers) != 1 || r.Answers[0].String() != "10.201.0.1" {
		t.Fatalf("answers = %v, want the frontend 10.201.0.1", r.Answers)
	}
}

func TestDNSResolvesAllocName(t *testing.T) {
	d := testDNS(t)

	q := buildQuery(t, 1, "alloc-shop-web-1.web.shop.kanea", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if len(r.Answers) != 1 || r.Answers[0].String() != "10.200.1.6" {
		t.Fatalf("answers = %v, want 10.200.1.6", r.Answers)
	}
}

func TestDNSIsCaseInsensitive(t *testing.T) {
	d := testDNS(t)

	q := buildQuery(t, 1, "WEB.Shop.KANEA", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if len(r.Answers) != 1 {
		t.Fatalf("answers = %v, want the service to resolve regardless of case", r.Answers)
	}
}

// NXDOMAIN means "this name does not exist". Returning it for AAAA on a name
// that does exist is a lie about the name, and a dual-stack client that
// believes it may never try the A query at all, so the answer is NODATA:
// NOERROR with an empty answer section.
func TestDNSAnswersNodataForAAAA(t *testing.T) {
	d := testDNS(t)

	q := buildQuery(t, 1, "web.shop.kanea", typeAAAA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeNoError {
		t.Errorf("rcode = %d, want NOERROR (NODATA) for AAAA on an existing name", r.RCode)
	}
	if r.NumAnswr != 0 {
		t.Errorf("answers = %d, want none", r.NumAnswr)
	}
	if !r.AA {
		t.Error("NODATA must still be authoritative")
	}
}

func TestDNSAnswersNXDomainForUnknownInternalName(t *testing.T) {
	d := testDNS(t)

	q := buildQuery(t, 1, "nope.shop.kanea", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN", r.RCode)
	}
	if !r.AA {
		t.Error("NXDOMAIN for our own zone must be authoritative")
	}
}

// With no upstream configured, an external name is refused rather than left to
// time out: a workload gets a definite answer immediately.
func TestDNSRefusesExternalNamesWithoutUpstreams(t *testing.T) {
	d := testDNS(t)

	q := buildQuery(t, 1, "example.com", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeRefused {
		t.Errorf("rcode = %d, want REFUSED", r.RCode)
	}
	if r.AA {
		t.Error("must not claim authority over a name outside the internal zone")
	}
}

// A dead upstream must produce SERVFAIL within the timeout, not a hang. DNS is
// in the path of every service call; a stall here stalls the workload.
func TestDNSFailsFastOnDeadUpstream(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3: reserved for documentation, so nothing
	// answers and the query can only end in a timeout.
	d := testDNS(t, "203.0.113.1:53")

	start := time.Now()
	q := buildQuery(t, 1, "example.com", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))
	elapsed := time.Since(start)

	if r.RCode != rcodeServFail {
		t.Errorf("rcode = %d, want SERVFAIL", r.RCode)
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v to fail; the forward timeout is not bounding it", elapsed)
	}
}

// Internal names are served from memory, so an upstream that never answers
// cannot delay them.
func TestDNSInternalNamesAreUnaffectedByDeadUpstream(t *testing.T) {
	d := testDNS(t, "203.0.113.1:53")

	start := time.Now()
	q := buildQuery(t, 1, "web.shop.kanea", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if len(r.Answers) != 1 {
		t.Fatalf("answers = %v", r.Answers)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("internal lookup took %v; it should touch no I/O at all", elapsed)
	}
}

// When the forward budget is exhausted the answer is an immediate SERVFAIL.
// Queueing would turn one slow upstream into a stalled node.
func TestDNSSheddsWhenForwardBudgetIsExhausted(t *testing.T) {
	d := testDNS(t, "203.0.113.1:53")
	// Occupy every slot.
	for range cap(d.forwardSlots) {
		d.forwardSlots <- struct{}{}
	}

	start := time.Now()
	q := buildQuery(t, 1, "example.com", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeServFail {
		t.Errorf("rcode = %d, want SERVFAIL", r.RCode)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("shedding took %v; it must not wait for a slot", elapsed)
	}
}

func TestDNSForwardsToUpstream(t *testing.T) {
	// A stand-in upstream that answers everything with one A record.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		buf := make([]byte, 512)
		for {
			n, client, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q, err := parseQuery(buf[:n])
			if err != nil {
				continue
			}
			b := newResponse(buf[:n], q, rcodeNoError, false)
			_ = b.addA(q.Name, netip.MustParseAddr("93.184.215.14"), 300)
			_, _ = conn.WriteToUDP(b.finish(), client)
		}
	}()

	d := testDNS(t, conn.LocalAddr().String())
	q := buildQuery(t, 0xABCD, "example.com", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeNoError {
		t.Fatalf("rcode = %d, want NOERROR", r.RCode)
	}
	if len(r.Answers) != 1 || r.Answers[0].String() != "93.184.215.14" {
		t.Fatalf("answers = %v, want the upstream's record", r.Answers)
	}
	if r.ID != 0xABCD {
		t.Errorf("id = %#x, want the client's id echoed back", r.ID)
	}
}

// A resolver that says "do not recurse" is asking for an authoritative answer
// only. Forwarding anyway would be answering a question it did not ask.
func TestDNSDoesNotForwardWithoutRecursionDesired(t *testing.T) {
	d := testDNS(t, "203.0.113.1:53")

	q := buildQuery(t, 1, "example.com", typeA, false)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeRefused {
		t.Errorf("rcode = %d, want REFUSED", r.RCode)
	}
}

// An empty zone is a normal state (no services deployed yet), not an error.
func TestDNSWithEmptyZone(t *testing.T) {
	d, err := NewDNS(DNSConfig{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	q := buildQuery(t, 1, "web.shop.kanea", typeA, true)
	r := parseReply(t, d.respond(t.Context(), q))

	if r.RCode != rcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN from an empty zone", r.RCode)
	}
}

// A wildcard bind publishes an open resolver on every interface the node has:
// a DNS amplification source, and an inventory of everything running here.
func TestNewDNSRefusesWildcardBind(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:53", "[::]:53"} {
		if _, err := NewDNS(DNSConfig{Listen: listen}); err == nil {
			t.Errorf("NewDNS(%q) = nil, want a refusal", listen)
		} else if !strings.Contains(err.Error(), "node-local") {
			t.Errorf("NewDNS(%q) = %v, want the reason explained", listen, err)
		}
	}
}

func TestDNSServeAndQueryOverUDP(t *testing.T) {
	d := testDNS(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() { defer close(done); _ = d.Serve(ctx) }()

	// Wait for the bind.
	var addr string
	for range 100 {
		if addr = d.Addr(); addr != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server never bound")
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	if _, err := conn.Write(buildQuery(t, 7, "web.shop.kanea", typeA, true)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	r := parseReply(t, buf[:n])
	if len(r.Answers) != 1 || r.Answers[0].String() != "10.201.0.1" {
		t.Fatalf("answers = %v over the wire", r.Answers)
	}

	cancel()
	<-done
}

// dualStackDNS is testDNS with v6 twins on the service and one backend:
// the other backend is a pre-v1.41 attachment with no v6 half.
func dualStackDNS(t *testing.T) *DNS {
	t.Helper()
	d, err := NewDNS(DNSConfig{
		Listen:         "127.0.0.1:0",
		ForwardTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	d.SetZone([]Service{{
		Project: "shop", Service: "web", VIP: "10.201.0.1", VIP6: "fd10:245::1",
		Backends: []Backend{
			{AllocID: "shop-web-0", IPv4: "10.200.1.5", IPv6: "fd10:244::5"},
			{AllocID: "shop-web-1", IPv4: "10.200.1.6"}, // v4-only, adopted across the upgrade
		},
	}})
	return d
}

// The per-type answer matrix (v1.41): A sees v4, AAAA sees v6, ANY both;
// and the deliberate NODATA survives for the halves a name does not have.
func TestDNSAnswersPerQueryType(t *testing.T) {
	d := dualStackDNS(t)

	t.Run("A stays v4", func(t *testing.T) {
		r := parseReply(t, d.respond(t.Context(), buildQuery(t, 1, "web.shop.kanea", typeA, true)))
		if len(r.Answers) != 1 || r.Answers[0].String() != "10.201.0.1" {
			t.Fatalf("A answers = %v, want only the v4 VIP", r.Answers)
		}
	})
	t.Run("AAAA answers the v6 twin", func(t *testing.T) {
		r := parseReply(t, d.respond(t.Context(), buildQuery(t, 2, "web.shop.kanea", typeAAAA, true)))
		if r.RCode != rcodeNoError || !r.AA {
			t.Fatalf("rcode = %d, authoritative = %v", r.RCode, r.AA)
		}
		if len(r.Answers) != 1 || r.Answers[0].String() != "fd10:245::1" {
			t.Fatalf("AAAA answers = %v, want the v6 VIP", r.Answers)
		}
	})
	t.Run("ANY answers both", func(t *testing.T) {
		r := parseReply(t, d.respond(t.Context(), buildQuery(t, 3, "web.shop.kanea", typeANY, true)))
		if len(r.Answers) != 2 {
			t.Fatalf("ANY answers = %v, want both families", r.Answers)
		}
	})
	t.Run("AAAA on a v6-less name stays NODATA", func(t *testing.T) {
		// shop-web-1 predates dual-stack: its alloc name has no v6 address,
		// and the deliberate NODATA is still the answer, never NXDOMAIN, and
		// never someone else's address.
		r := parseReply(t, d.respond(t.Context(),
			buildQuery(t, 4, "alloc-shop-web-1.web.shop.kanea", typeAAAA, true)))
		if r.RCode != rcodeNoError || r.NumAnswr != 0 || !r.AA {
			t.Fatalf("rcode = %d, answers = %d, AA = %v; want authoritative NODATA", r.RCode, r.NumAnswr, r.AA)
		}
	})
	t.Run("AAAA on a dual-stack alloc name", func(t *testing.T) {
		r := parseReply(t, d.respond(t.Context(),
			buildQuery(t, 5, "alloc-shop-web-0.web.shop.kanea", typeAAAA, true)))
		if len(r.Answers) != 1 || r.Answers[0].String() != "fd10:244::5" {
			t.Fatalf("answers = %v, want fd10:244::5", r.Answers)
		}
	})
}
