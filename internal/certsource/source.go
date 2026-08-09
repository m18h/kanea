// Package certsource is where a certificate comes from (PRD §7.3).
//
// Kanea terminates TLS with certificates from three places — an ACME CA, a
// self-signed CA this node owns, and certificates an operator put on the node —
// and `kanea-edge` knows about none of them. It polls one bundle file and
// selects on SNI. Everything here runs in kanead, for the reason §5.2.6 gives:
// obtaining or minting a certificate is *writing*, and the process that
// terminates untrusted public traffic does not write.
//
// The package owns the certificate value type, the Source seam each origin
// implements, and the Publisher that merges them into that one file. It knows
// nothing about ACME; internal/acme depends on this and not the reverse, which
// is what keeps the package that talks to a CA from also knowing the shape of
// the ingress projection.
package certsource

import (
	"context"
	"time"
)

// Mode names a certificate source as a job spec spells it (PRD §6.2 R20).
type Mode string

const (
	// ModeACME obtains a certificate from an ACME CA.
	ModeACME Mode = "acme"
	// ModeSelfSigned issues one from a CA this node generated.
	ModeSelfSigned Mode = "self-signed"
	// ModeProvided selects one the operator configured on this node.
	ModeProvided Mode = "provided"
	// ModePlaintext is plain HTTP, declared. It has no Source: there is nothing
	// to obtain. It exists so that "this service is not served over TLS" is
	// something a spec can say rather than something that merely happens.
	ModePlaintext Mode = "plaintext"
)

// Modes lists the closed set, in the order an error message should offer them.
func Modes() []Mode {
	return []Mode{ModeACME, ModeSelfSigned, ModeProvided, ModePlaintext}
}

// Valid reports whether m is one of them.
//
// There is deliberately no zero value that resolves to something: an
// unrecognised mode is refused where it is written, because a mode nobody
// recognises would otherwise decide how a service is served by accident.
func (m Mode) Valid() bool {
	for _, known := range Modes() {
		if m == known {
			return true
		}
	}
	return false
}

func (m Mode) String() string { return string(m) }

// RenewalFraction is how far into a certificate's life renewal starts, as a
// fraction of its total validity (PRD §7.3: two thirds).
//
// It lives here rather than in internal/acme because it is a property of
// certificates and not of the CA that signed one. A self-signed leaf renewing
// on the same schedule exercises the same code every sixty days instead of once
// a decade, which is when a bug in it is still cheap.
const RenewalFraction = 2.0 / 3.0

// Certificate is one certificate and its key, whatever produced it.
type Certificate struct {
	// Domains are the names it covers, lowercased, primary first.
	Domains []string `json:"domains"`
	// CertPEM is the leaf followed by its intermediates.
	CertPEM string `json:"cert_pem"`
	// KeyPEM is the private key.
	KeyPEM string `json:"key_pem"`
	// NotBefore and NotAfter come from the leaf, decoded once at issuance so
	// the renewal check does not re-parse on every pass.
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// IssuedAt records when Kanea obtained it, which is not the same as
	// NotBefore and is what an operator asks about after a failed renewal.
	IssuedAt time.Time `json:"issued_at"`
}

// Key identifies a certificate in the Store: its primary domain.
func (c Certificate) Key() string {
	if len(c.Domains) == 0 {
		return ""
	}
	return c.Domains[0]
}

// RenewAfter is the moment renewal should begin.
func (c Certificate) RenewAfter() time.Time {
	life := c.NotAfter.Sub(c.NotBefore)
	if life <= 0 {
		// A certificate with no usable validity window is due immediately
		// rather than never — the alternative is a silent non-renewal.
		return c.NotBefore
	}
	return c.NotBefore.Add(time.Duration(float64(life) * RenewalFraction))
}

// NeedsRenewal reports whether it is time to replace this certificate.
func (c Certificate) NeedsRenewal(now time.Time) bool {
	return !now.Before(c.RenewAfter())
}

// Covers reports whether this certificate is for exactly this set of names.
//
// Exactly, not "at least": a service that gained a domain needs a certificate
// naming it, and one that lost a domain should stop asserting it. Both are
// reissues, and treating a superset as a match would skip them.
func (c Certificate) Covers(domains []string) bool {
	if len(c.Domains) != len(domains) {
		return false
	}
	for i := range domains {
		if c.Domains[i] != domains[i] {
			return false
		}
	}
	return true
}

// Store is the slice of the state store a source needs.
//
// Defined at the consumer, and deliberately the same shape internal/acme
// already asks for, so one adapter satisfies both.
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Put(ctx context.Context, key string, value []byte) error
	List(ctx context.Context, prefix string) (map[string][]byte, error)
}

// Request is one service's certificate need, as the route table resolved it.
type Request struct {
	// Domains, lowercased, primary first. The first is the Store key.
	Domains []string
	// Service is "project/service", for logs and events.
	Service string
	// Project is who is asking, and is what a provided certificate's `allow`
	// list is checked against (R20).
	Project string
	// Auto reports whether Domains are the generated FQDNs of §7.2.
	//
	// Only the ACME source reads it, and only to decide whether a project's
	// names may be collapsed into one wildcard — a rate-limit workaround no
	// other source needs, because no other source has a rate limit.
	Auto bool
	// Name selects one of the certificates an operator configured on this node.
	// Provided only; empty means any certificate this project is allowed and
	// whose names cover the request.
	Name string
}

// Failure is one request a source could not satisfy.
type Failure struct {
	Request Request
	Err     error
}

// Result is what one Ensure produced.
type Result struct {
	Certificates []Certificate
	// Failures names what produced nothing, and why.
	//
	// One bad domain must not suppress the rest — the rule acme.Sync already
	// follows, lifted into the interface so every source has to follow it.
	Failures []Failure
}

// Source produces the certificates for one mode.
//
// Ensure is called on every pass with the full set of requests for its mode,
// including the empty set: that is how a source learns it no longer has to hold
// anything, and it is why the Publisher replaces a source's whole contribution
// rather than diffing it.
type Source interface {
	Mode() Mode
	Ensure(ctx context.Context, reqs []Request) (Result, error)
}
