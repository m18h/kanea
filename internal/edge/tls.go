package edge

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// keyring holds the certificates and challenge answers currently in force.
//
// Replaced wholesale behind an atomic pointer, like the route table: a
// handshake that started against one set must not finish against another.
type keyring struct {
	// byName maps an exact lowercase hostname to its certificate.
	byName map[string]*tls.Certificate
	// wildcards maps a parent domain ("shop.example.com") to the certificate
	// covering "*.shop.example.com".
	wildcards map[string]*tls.Certificate
	// challenges answers HTTP-01, keyed by token.
	challenges map[string]string
	index      uint64
	expiry     map[string]time.Time
}

func emptyKeyring() *keyring {
	return &keyring{
		byName:     map[string]*tls.Certificate{},
		wildcards:  map[string]*tls.Certificate{},
		challenges: map[string]string{},
		expiry:     map[string]time.Time{},
	}
}

// newKeyring parses a bundle into the form the handshake path uses.
func newKeyring(b Bundle) (*keyring, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	k := emptyKeyring()
	k.index = b.Index

	for _, c := range b.Certificates {
		pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidBundle, strings.Join(c.Domains, ", "), err)
		}
		for _, domain := range c.Domains {
			if parent, ok := strings.CutPrefix(domain, "*."); ok {
				k.wildcards[parent] = &pair
			} else {
				k.byName[domain] = &pair
			}
			k.expiry[domain] = c.NotAfter
		}
	}
	for _, ch := range b.HTTPChallenges {
		k.challenges[ch.Token] = ch.KeyAuth
	}
	return k, nil
}

// CoversHost reports whether a certificate naming these domains covers a host.
//
// Exported because kanead has to answer the same question when it decides
// whether an operator's certificate satisfies a service (PRD §7.3, R20), and
// two implementations of "what does a wildcard cover" drift into a certificate
// that is published and never served.
//
// The rule is keyring.certificateFor's, stated once: exact match, or a wildcard
// over the immediate parent.
func CoversHost(domains []string, host string) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	_, parent, hasParent := strings.Cut(host, ".")
	for _, domain := range domains {
		domain = NormalizeHost(domain)
		if domain == host {
			return true
		}
		if wildcard, ok := strings.CutPrefix(domain, "*."); ok && hasParent && wildcard == parent {
			return true
		}
	}
	return false
}

// certificateFor resolves an SNI name.
//
// Exact match first, then a wildcard over the immediate parent. A wildcard
// covers one label — "*.shop.example.com" matches "web.shop.example.com" and
// not "a.b.shop.example.com" — because that is what the certificate actually
// asserts, and being looser here would present a certificate the client is
// right to reject.
//
// The maps are kept rather than deferring to CoversHost because this is the
// handshake path; tls_test.go drives both from one table so they cannot
// disagree.
func (k *keyring) certificateFor(name string) (*tls.Certificate, bool) {
	name = NormalizeHost(name)
	if name == "" {
		return nil, false
	}
	if cert, ok := k.byName[name]; ok {
		return cert, true
	}
	if _, parent, found := strings.Cut(name, "."); found {
		if cert, ok := k.wildcards[parent]; ok {
			return cert, true
		}
	}
	return nil, false
}

// challenge returns the HTTP-01 answer for a token.
func (k *keyring) challenge(token string) (string, bool) {
	answer, ok := k.challenges[token]
	return answer, ok
}

// covers reports whether the edge can terminate TLS for a host. It is what
// decides whether that host gets redirected to HTTPS.
func (k *keyring) covers(name string) bool {
	_, ok := k.certificateFor(name)
	return ok
}

func (k *keyring) len() int { return len(k.byName) + len(k.wildcards) }

// ErrNoCertificate is returned to the handshake for an unknown SNI.
var ErrNoCertificate = errors.New("edge: no certificate for that name")

// certStore is the mutable holder the server and the watcher share.
type certStore struct {
	ring atomic.Pointer[keyring]
}

func newCertStore() *certStore {
	s := &certStore{}
	s.ring.Store(emptyKeyring())
	return s
}

func (s *certStore) set(k *keyring) { s.ring.Store(k) }
func (s *certStore) get() *keyring  { return s.ring.Load() }

// tlsConfig builds the server's TLS configuration.
//
// GetCertificate rather than a static list: certificates arrive and are renewed
// while the process runs, and rebuilding the listener for a renewal would drop
// every connection on it.
func (s *certStore) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, ok := s.get().certificateFor(hello.ServerName)
			if !ok {
				// Refusing the handshake is the honest answer. Presenting some
				// other host's certificate would produce a name-mismatch error
				// in the browser, which reads as "this site is impersonated"
				// rather than "this site has no certificate yet".
				return nil, fmt.Errorf("%w: %q", ErrNoCertificate, hello.ServerName)
			}
			return cert, nil
		},
	}
}

// acmeChallengePrefix is the well-known path an HTTP-01 validation fetches.
const acmeChallengePrefix = "/.well-known/acme-challenge/"
