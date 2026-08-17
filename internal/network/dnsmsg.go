package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Minimal DNS wire-format handling (RFC 1035).
//
// This is hand-written rather than imported: it sits in the path of every
// service call a workload makes, and
// the subset actually needed is small; parse one question, build an A answer,
// or relay the query verbatim to an upstream. Forwarded responses are never
// parsed at all, they are passed back as bytes, so the parsing surface exposed
// to workload-controlled input is one question name.
//
// That surface is where the care goes. Everything below is bounds-checked
// against the buffer, label and name lengths are capped, and compression
// pointers are rejected outright in the question section: a question name is
// the first thing after the header, so there is nothing legitimate for it to
// point back at, and accepting one is how a parser ends up chasing a loop.

// DNS constants used here.
const (
	dnsHeaderLen  = 12
	maxDNSName    = 255
	maxDNSLabel   = 63
	maxUDPPayload = 512

	// maxForwardPayload is the upstream reply read size (K-28): 4096 covers
	// the standard EDNS UDP size; a reply that fills it may be clipped
	// mid-record, so it is answered as truncated rather than relayed with its
	// counts intact.
	maxForwardPayload = 4096

	// Header flag bits.
	flagResponse           = 1 << 15
	flagAuthoritative      = 1 << 10
	flagTruncated          = 1 << 9
	flagRecursionDesired   = 1 << 8
	flagRecursionAvailable = 1 << 7
	opcodeMask             = 0xF << 11
	rcodeMask              = 0xF
)

// Response codes.
const (
	rcodeNoError  = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeNotImpl  = 4
	rcodeRefused  = 5
)

// errUpstreamTruncated marks a reply that filled the forward read buffer
// (K-28): possibly clipped mid-record, so the client is told to retry over
// TCP rather than handed a parse error.
var errUpstreamTruncated = errors.New("dns: upstream reply exceeded the read buffer")

// Record types and classes.
const (
	typeA     = 1
	typeCNAME = 5
	typeAAAA  = 28
	typeANY   = 255
	classIN   = 1
)

var errMalformedQuery = errors.New("dns: malformed query")

// query is the part of a request this server acts on.
type query struct {
	// ID echoes back in the response.
	ID uint16
	// Flags is the raw header flag word of the request.
	Flags uint16
	// Name is the question name, lower-cased and without a trailing dot.
	Name string
	// Type and Class are the question's QTYPE and QCLASS.
	Type  uint16
	Class uint16
	// QuestionEnd is the offset just past the question section, so a response
	// can echo the question bytes verbatim rather than re-encoding them.
	QuestionEnd int
}

// recursionDesired reports whether the client asked us to resolve on its behalf.
func (q query) recursionDesired() bool { return q.Flags&flagRecursionDesired != 0 }

// opcode returns the request's opcode; only a standard query (0) is served.
func (q query) opcode() uint16 { return (q.Flags & opcodeMask) >> 11 }

// parseQuery reads the header and the single question a resolver sends.
func parseQuery(buf []byte) (query, error) {
	if len(buf) < dnsHeaderLen {
		return query{}, fmt.Errorf("%w: %d bytes is shorter than a header", errMalformedQuery, len(buf))
	}
	var q query
	q.ID = binary.BigEndian.Uint16(buf[0:2])
	q.Flags = binary.BigEndian.Uint16(buf[2:4])

	if qdcount := binary.BigEndian.Uint16(buf[4:6]); qdcount != 1 {
		// Zero questions is nothing to answer; more than one has no defined
		// semantics and every real resolver sends exactly one.
		return q, fmt.Errorf("%w: %d questions", errMalformedQuery, qdcount)
	}
	if q.Flags&flagResponse != 0 {
		return q, fmt.Errorf("%w: response bit set on a query", errMalformedQuery)
	}

	name, offset, err := parseName(buf, dnsHeaderLen)
	if err != nil {
		return q, err
	}
	if offset+4 > len(buf) {
		return q, fmt.Errorf("%w: question truncated before type and class", errMalformedQuery)
	}
	q.Name = name
	q.Type = binary.BigEndian.Uint16(buf[offset : offset+2])
	q.Class = binary.BigEndian.Uint16(buf[offset+2 : offset+4])
	q.QuestionEnd = offset + 4
	return q, nil
}

// parseName decodes a length-prefixed name, returning it lower-cased and
// without a trailing dot, plus the offset just past it.
func parseName(buf []byte, start int) (string, int, error) {
	var out strings.Builder
	offset := start
	total := 0

	for {
		if offset >= len(buf) {
			return "", 0, fmt.Errorf("%w: name runs past the end of the message", errMalformedQuery)
		}
		length := int(buf[offset])

		// Top two bits set marks a compression pointer. Legal elsewhere in a
		// message, never meaningful in a question, and following one is how a
		// parser gets led into a loop by a hostile client.
		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("%w: compression pointer in a question name", errMalformedQuery)
		}
		offset++
		if length == 0 {
			return out.String(), offset, nil // root label ends the name
		}
		if length > maxDNSLabel {
			return "", 0, fmt.Errorf("%w: label of %d bytes exceeds %d", errMalformedQuery, length, maxDNSLabel)
		}
		if offset+length > len(buf) {
			return "", 0, fmt.Errorf("%w: label runs past the end of the message", errMalformedQuery)
		}
		total += length + 1
		if total > maxDNSName {
			return "", 0, fmt.Errorf("%w: name exceeds %d bytes", errMalformedQuery, maxDNSName)
		}
		if out.Len() > 0 {
			out.WriteByte('.')
		}
		out.Write(lowerASCII(buf[offset : offset+length]))
		offset += length
	}
}

// lowerASCII lower-cases a label. DNS comparison is ASCII case-insensitive, and
// only ASCII: bytes above 0x7F are left untouched rather than run through a
// Unicode fold that would not match what a resolver sent.
func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// answerBuilder assembles a response by echoing the request's question section
// and appending records.
type answerBuilder struct {
	buf []byte
	// answers is uint16 because the header field is: the count cannot be
	// allowed to wrap past 65535 and silently under-report what follows it.
	answers uint16
}

// maxAnswers is the largest answer count the header can express. Far above
// anything a Kanea zone produces, and the point at which addA refuses.
const maxAnswers = ^uint16(0)

// newResponse starts a reply to q with the given response code.
func newResponse(request []byte, q query, rcode uint16, authoritative bool) *answerBuilder {
	flags := flagResponse | (q.Flags & opcodeMask) | (q.Flags & flagRecursionDesired) | rcode
	if authoritative {
		flags |= flagAuthoritative
	}
	// Recursion is available for names outside the internal zone; saying so
	// keeps resolvers from falling back to behaviour meant for stub servers.
	flags |= flagRecursionAvailable

	// Header plus the question copied verbatim: re-encoding it risks answering
	// a subtly different name than the one that was asked.
	buf := make([]byte, 0, dnsHeaderLen+q.QuestionEnd+64)
	buf = binary.BigEndian.AppendUint16(buf, q.ID)
	buf = binary.BigEndian.AppendUint16(buf, flags)
	buf = binary.BigEndian.AppendUint16(buf, 1) // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0) // ANCOUNT, patched on finish
	buf = binary.BigEndian.AppendUint16(buf, 0) // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0) // ARCOUNT
	buf = append(buf, request[dnsHeaderLen:q.QuestionEnd]...)

	return &answerBuilder{buf: buf}
}

// addA appends an A record for the question name.
//
// The record name is written out in full rather than as a compression pointer
// to the question. It costs a few bytes in a response that is already far
// inside one UDP datagram, and it keeps this encoder free of the one construct
// most likely to be got wrong.
func (b *answerBuilder) addA(name string, ip netip.Addr, ttl uint32) error {
	if b.answers == maxAnswers {
		return fmt.Errorf("dns: cannot add more than %d answers", maxAnswers)
	}
	v4 := ip.As4()
	encoded, err := encodeName(name)
	if err != nil {
		return err
	}
	b.buf = append(b.buf, encoded...)
	b.buf = binary.BigEndian.AppendUint16(b.buf, typeA)
	b.buf = binary.BigEndian.AppendUint16(b.buf, classIN)
	b.buf = binary.BigEndian.AppendUint32(b.buf, ttl)
	b.buf = binary.BigEndian.AppendUint16(b.buf, 4)
	b.buf = append(b.buf, v4[:]...)
	b.answers++
	return nil
}

// addAAAA appends an AAAA record for the question name (v1.41): addA with a
// sixteen-byte RDATA. Worth noting for the truncation path in finish: a v6
// answer set reaches the 512-byte TC threshold sooner than the same set of A
// records would.
func (b *answerBuilder) addAAAA(name string, ip netip.Addr, ttl uint32) error {
	if b.answers == maxAnswers {
		return fmt.Errorf("dns: cannot add more than %d answers", maxAnswers)
	}
	v6 := ip.As16()
	encoded, err := encodeName(name)
	if err != nil {
		return err
	}
	b.buf = append(b.buf, encoded...)
	b.buf = binary.BigEndian.AppendUint16(b.buf, typeAAAA)
	b.buf = binary.BigEndian.AppendUint16(b.buf, classIN)
	b.buf = binary.BigEndian.AppendUint32(b.buf, ttl)
	b.buf = binary.BigEndian.AppendUint16(b.buf, 16)
	b.buf = append(b.buf, v6[:]...)
	b.answers++
	return nil
}

// finish patches the answer count and applies UDP truncation semantics.
//
// A response that does not fit is returned empty with TC set rather than
// clipped mid-record: a resolver that sees TC retries over TCP, while a
// truncated record body is a parse error at the client.
func (b *answerBuilder) finish() []byte {
	binary.BigEndian.PutUint16(b.buf[6:8], b.answers)

	if len(b.buf) > maxUDPPayload {
		flags := binary.BigEndian.Uint16(b.buf[2:4]) | flagTruncated
		binary.BigEndian.PutUint16(b.buf[2:4], flags)
		binary.BigEndian.PutUint16(b.buf[6:8], 0)
		return b.buf[:b.questionOnlyLen()]
	}
	return b.buf
}

// questionOnlyLen is the length of the header plus the echoed question.
func (b *answerBuilder) questionOnlyLen() int {
	offset := dnsHeaderLen
	for offset < len(b.buf) {
		length := int(b.buf[offset])
		offset++
		if length == 0 {
			break
		}
		offset += length
	}
	return min(offset+4, len(b.buf))
}

// truncatedAnswers answers with the header and question only and TC set (K-28):
// the relayed upstream reply did not fit the read buffer, so the resolver
// retries over TCP - the same semantics finish() applies to an oversized built
// answer.
func (b *answerBuilder) truncatedAnswers() []byte {
	flags := binary.BigEndian.Uint16(b.buf[2:4]) | flagTruncated
	binary.BigEndian.PutUint16(b.buf[2:4], flags)
	binary.BigEndian.PutUint16(b.buf[6:8], 0) // ANCOUNT
	return b.buf[:b.questionOnlyLen()]
}

// encodeName writes a name in DNS label form.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxDNSName {
		return nil, fmt.Errorf("dns: name %q exceeds %d bytes", name, maxDNSName)
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		length := len(label)
		if length == 0 || length > maxDNSLabel {
			return nil, fmt.Errorf("dns: invalid label in %q", name)
		}
		// #nosec G115; length is bounded by maxDNSLabel (63) immediately above.
		out = append(out, byte(length))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// errorResponse builds a header-only reply carrying a response code. It is used
// when the request could not be parsed far enough to echo a question.
func errorResponse(request []byte, rcode uint16) []byte {
	if len(request) < 4 {
		return nil // not enough even to echo an ID; nothing useful to send
	}
	buf := make([]byte, dnsHeaderLen)
	copy(buf[0:2], request[0:2])
	flags := flagResponse | rcode
	if len(request) >= 4 {
		requested := binary.BigEndian.Uint16(request[2:4])
		flags |= requested & opcodeMask
		flags |= requested & flagRecursionDesired
	}
	binary.BigEndian.PutUint16(buf[2:4], flags)
	return buf
}
