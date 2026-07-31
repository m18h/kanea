package network

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// The question name is the one piece of workload-controlled input this package
// parses. Everything here is a malformed message a container could send.
func TestParseQueryRejectsMalformedMessages(t *testing.T) {
	header := func(qdcount uint16, flags uint16) []byte {
		buf := make([]byte, dnsHeaderLen)
		binary.BigEndian.PutUint16(buf[0:2], 1)
		binary.BigEndian.PutUint16(buf[2:4], flags)
		binary.BigEndian.PutUint16(buf[4:6], qdcount)
		return buf
	}

	tests := []struct {
		name string
		msg  []byte
		want string
	}{
		{name: "empty", msg: nil, want: "shorter than a header"},
		{name: "truncated header", msg: make([]byte, 5), want: "shorter than a header"},
		{name: "no questions", msg: header(0, 0), want: "0 questions"},
		{name: "multiple questions", msg: header(2, 0), want: "2 questions"},
		{
			name: "response bit set on a query",
			msg:  append(header(1, flagResponse), 0),
			want: "response bit",
		},
		{
			// A compression pointer is legal elsewhere but never meaningful in a
			// question, and following one is how a parser gets led into a loop.
			name: "compression pointer in the question name",
			msg:  append(header(1, 0), 0xC0, 0x0C),
			want: "compression pointer",
		},
		{
			name: "label runs past the end of the message",
			msg:  append(header(1, 0), 0x10, 'a', 'b'),
			want: "runs past the end",
		},
		{
			name: "name never terminates",
			msg:  append(header(1, 0), 0x01, 'a'),
			want: "runs past the end",
		},
		{
			name: "question missing type and class",
			msg:  append(header(1, 0), 0x01, 'a', 0x00),
			want: "truncated before type and class",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseQuery(tc.msg)
			if err == nil {
				t.Fatalf("parseQuery = nil, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseQuery = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// A name longer than the protocol allows must be refused rather than
// accumulated — the bound is what stops a small datagram from producing an
// unbounded allocation.
func TestParseQueryRejectsOversizedName(t *testing.T) {
	buf := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	for range 10 {
		buf = append(buf, 63)
		buf = append(buf, []byte(strings.Repeat("a", 63))...)
	}
	buf = append(buf, 0, 0, 1, 0, 1)

	if _, err := parseQuery(buf); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("parseQuery = %v, want a length refusal", err)
	}
}

// A malformed message must still produce a reply carrying the client's
// transaction id. A silent drop leaves the client waiting out its full timeout
// for something that will never arrive.
func TestErrorResponseEchoesTransactionID(t *testing.T) {
	request := []byte{0xAB, 0xCD, 0x01, 0x00}

	reply := errorResponse(request, rcodeFormErr)
	if len(reply) != dnsHeaderLen {
		t.Fatalf("reply is %d bytes, want a bare header", len(reply))
	}
	if id := binary.BigEndian.Uint16(reply[0:2]); id != 0xABCD {
		t.Errorf("id = %#x, want 0xABCD", id)
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&flagResponse == 0 {
		t.Error("response bit not set")
	}
	if flags&rcodeMask != rcodeFormErr {
		t.Errorf("rcode = %d, want FORMERR", flags&rcodeMask)
	}
}

func TestEncodeName(t *testing.T) {
	encoded, err := encodeName("web.shop.kanea")
	if err != nil {
		t.Fatalf("encodeName: %v", err)
	}
	want := []byte{3, 'w', 'e', 'b', 4, 's', 'h', 'o', 'p', 5, 'k', 'a', 'n', 'e', 'a', 0}
	if string(encoded) != string(want) {
		t.Fatalf("encoded = %v, want %v", encoded, want)
	}

	// Round-trip through the parser: what we write must be what we read.
	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, encoded...)
	msg = append(msg, 0, 1, 0, 1)

	q, err := parseQuery(msg)
	if err != nil {
		t.Fatalf("parseQuery: %v", err)
	}
	if q.Name != "web.shop.kanea" {
		t.Errorf("round-trip = %q", q.Name)
	}
}

func TestEncodeNameRejectsBadLabels(t *testing.T) {
	for _, name := range []string{"a..b", strings.Repeat("x", 64) + ".kanea", strings.Repeat("a.", 200)} {
		if _, err := encodeName(name); err == nil {
			t.Errorf("encodeName(%.40q…) = nil, want an error", name)
		}
	}
}

// A response that does not fit in a datagram comes back empty with TC set, so
// the resolver retries over TCP. Clipping it mid-record is a parse error at the
// client instead.
func TestFinishTruncatesRatherThanClipping(t *testing.T) {
	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	encoded, err := encodeName("web.shop.kanea")
	if err != nil {
		t.Fatalf("encodeName: %v", err)
	}
	msg = append(msg, encoded...)
	msg = append(msg, 0, 1, 0, 1)

	q, err := parseQuery(msg)
	if err != nil {
		t.Fatalf("parseQuery: %v", err)
	}

	b := newResponse(msg, q, rcodeNoError, true)
	for range 40 {
		if err := b.addA(q.Name, netip.MustParseAddr("10.0.0.1"), 30); err != nil {
			t.Fatalf("addA: %v", err)
		}
	}
	out := b.finish()

	if len(out) > maxUDPPayload {
		t.Fatalf("response is %d bytes, over the %d limit", len(out), maxUDPPayload)
	}
	flags := binary.BigEndian.Uint16(out[2:4])
	if flags&flagTruncated == 0 {
		t.Error("TC bit not set on an oversized response")
	}
	if count := binary.BigEndian.Uint16(out[6:8]); count != 0 {
		t.Errorf("answer count = %d, want 0 alongside TC", count)
	}
	if len(out) != dnsHeaderLen+len(encoded)+4 {
		t.Errorf("truncated response is %d bytes, want header plus the question", len(out))
	}
}
