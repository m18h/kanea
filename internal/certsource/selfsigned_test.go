package certsource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// A leaf has to verify against the CA for the names it claims, and it has to be
// a key pair the edge can load. Both are checked here rather than trusted,
// because the failure mode is a handshake nobody sees until a browser does.
func TestSelfSignedIssuesUsableCertificates(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		// serves are names the certificate must be accepted for.
		serves []string
	}{
		{"single name", []string{"nas.home.lan"}, []string{"nas.home.lan"}},
		{
			"multiple names",
			[]string{"nas.home.lan", "media.home.lan"},
			[]string{"nas.home.lan", "media.home.lan"},
		},
		{
			"wildcard",
			[]string{"*.apps.home.lan"},
			[]string{"web.apps.home.lan", "api.apps.home.lan"},
		},
		{
			// A wildcard does not cover its own parent, so a project that wants
			// both asks for both — and we are the CA, so there is no validation
			// to fail.
			"wildcard and apex",
			[]string{"*.apps.home.lan", "apps.home.lan"},
			[]string{"web.apps.home.lan", "apps.home.lan"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := newTestSelfSigned(t, time.Now)
			res, err := src.Ensure(context.Background(), []Request{{Domains: tc.domains, Service: "p/s"}})
			if err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			if len(res.Failures) != 0 {
				t.Fatalf("failures = %+v", res.Failures)
			}
			if len(res.Certificates) != 1 {
				t.Fatalf("certificates = %d, want 1", len(res.Certificates))
			}
			cert := res.Certificates[0]

			// The edge loads the bundle with exactly this call, so a pass here
			// is a pass there.
			if _, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM)); err != nil {
				t.Fatalf("the edge could not load this key pair: %v", err)
			}

			pool := x509.NewCertPool()
			caPEM, err := src.CACertificate(context.Background())
			if err != nil {
				t.Fatalf("CACertificate: %v", err)
			}
			if !pool.AppendCertsFromPEM(caPEM) {
				t.Fatal("the CA certificate is not usable as a root")
			}
			leaf := parseLeaf(t, cert.CertPEM)
			for _, name := range tc.serves {
				if _, err := leaf.Verify(x509.VerifyOptions{
					Roots:       pool,
					DNSName:     name,
					CurrentTime: time.Now(),
					KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}); err != nil {
					t.Errorf("a client trusting the CA rejects %q: %v", name, err)
				}
			}
		})
	}
}

// A requested name that is an IP becomes an IP SAN (PRD v1.61): the API
// listener is dialled at a bare address, and a client matches an IP against
// IPAddresses, never against DNSNames. Service domains are DNS-1123 by
// construction, so only the listener's synthetic request takes this path.
func TestSelfSignedIssuesIPSANs(t *testing.T) {
	src := newTestSelfSigned(t, time.Now)
	res, err := src.Ensure(context.Background(),
		[]Request{{Domains: []string{"192.168.1.10"}, Service: "kanead/api"}})
	if err != nil || len(res.Failures) != 0 || len(res.Certificates) != 1 {
		t.Fatalf("Ensure: %v %+v", err, res)
	}
	leaf := parseLeaf(t, res.Certificates[0].CertPEM)
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("an IP request must not become a DNS SAN: %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.168.1.10" {
		t.Fatalf("IPAddresses = %v, want [192.168.1.10]", leaf.IPAddresses)
	}

	// The verification a real client performs when dialling by IP.
	pool := x509.NewCertPool()
	caPEM, err := src.CACertificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(caPEM)
	if err := leaf.VerifyHostname("192.168.1.10"); err != nil {
		t.Fatalf("a client dialling the IP rejects the certificate: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, CurrentTime: time.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("a client trusting the CA rejects the chain: %v", err)
	}
}

// A device whose clock runs a few minutes fast must not reject a certificate
// minted this second — to its owner that reads as "your CA is broken".
func TestSelfSignedBackdatesForClockSkew(t *testing.T) {
	now := time.Now()
	src := newTestSelfSigned(t, func() time.Time { return now })
	res, err := src.Ensure(context.Background(), []Request{{Domains: []string{"nas.home.lan"}}})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	cert := res.Certificates[0]
	if !cert.NotBefore.Before(now) {
		t.Errorf("NotBefore = %v, want it backdated before %v", cert.NotBefore, now)
	}
	if skew := now.Sub(cert.NotBefore); skew < clockSkewAllowance {
		t.Errorf("backdated by %v, want at least %v", skew, clockSkewAllowance)
	}
}

// The CA is generated once and reused. A second one would silently invalidate
// every device the operator had already set up.
func TestSelfSignedGeneratesTheCAOnce(t *testing.T) {
	store := &countingStore{memStore: newMemStore()}
	src := newTestSelfSignedWith(t, store, time.Now)

	for i := range 3 {
		if _, err := src.Ensure(context.Background(), []Request{
			{Domains: []string{"a.home.lan"}},
			{Domains: []string{"b.home.lan"}},
		}); err != nil {
			t.Fatalf("Ensure %d: %v", i, err)
		}
	}
	if got := store.puts(CAStoreKey); got != 1 {
		t.Errorf("the CA was written %d times, want once", got)
	}
}

// Renewal is at two thirds of validity, the same rule ACME certificates follow.
// Ninety-day leaves are what make this path run every two months rather than
// once a decade.
func TestSelfSignedRenewsAtTwoThirds(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	src := newTestSelfSigned(t, func() time.Time { return clock() })

	req := []Request{{Domains: []string{"nas.home.lan"}}}
	first, err := src.Ensure(context.Background(), req)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	// One day before renewal is due: the same certificate comes back.
	clock = func() time.Time { return first.Certificates[0].RenewAfter().Add(-24 * time.Hour) }
	before, err := src.Ensure(context.Background(), req)
	if err != nil {
		t.Fatalf("Ensure before renewal: %v", err)
	}
	if before.Certificates[0].CertPEM != first.Certificates[0].CertPEM {
		t.Error("reissued before renewal was due")
	}

	// One minute after: a new one.
	clock = func() time.Time { return first.Certificates[0].RenewAfter().Add(time.Minute) }
	after, err := src.Ensure(context.Background(), req)
	if err != nil {
		t.Fatalf("Ensure after renewal: %v", err)
	}
	if after.Certificates[0].CertPEM == first.Certificates[0].CertPEM {
		t.Error("did not renew once two thirds of validity had passed")
	}
}

// A service that gained or lost a domain needs a certificate naming exactly
// what it now claims — Covers is deliberately not a superset test.
func TestSelfSignedReissuesWhenTheDomainSetChanges(t *testing.T) {
	src := newTestSelfSigned(t, time.Now)
	first, err := src.Ensure(context.Background(), []Request{{Domains: []string{"nas.home.lan"}}})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	second, err := src.Ensure(context.Background(), []Request{
		{Domains: []string{"nas.home.lan", "media.home.lan"}},
	})
	if err != nil {
		t.Fatalf("Ensure with an added domain: %v", err)
	}
	if second.Certificates[0].CertPEM == first.Certificates[0].CertPEM {
		t.Error("kept a certificate that does not name the service's new domain")
	}
}

// A GET must not mutate state: a CA that exists because somebody looked is a CA
// nobody decided to have.
func TestCACertificateDoesNotGenerateOne(t *testing.T) {
	store := &countingStore{memStore: newMemStore()}
	src := newTestSelfSignedWith(t, store, time.Now)

	if _, err := src.CACertificate(context.Background()); !errors.Is(err, ErrNoCA) {
		t.Errorf("CACertificate before any issuance = %v, want ErrNoCA", err)
	}
	if got := store.puts(CAStoreKey); got != 0 {
		t.Errorf("looking at the CA wrote it %d times", got)
	}

	if _, err := src.Ensure(context.Background(), []Request{{Domains: []string{"nas.home.lan"}}}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	pem, err := src.CACertificate(context.Background())
	if err != nil {
		t.Fatalf("CACertificate after issuance: %v", err)
	}
	info, err := DescribeCA(pem)
	if err != nil {
		t.Fatalf("DescribeCA: %v", err)
	}
	if !strings.Contains(info.Subject, "Kanea local CA") {
		t.Errorf("subject = %q, want it identifiable in a trust list", info.Subject)
	}
	// Colon-separated hex is the form a device's trust dialog shows, which is
	// the only comparison an operator can actually make.
	if len(info.Fingerprint) != 32*3-1 || !strings.Contains(info.Fingerprint, ":") {
		t.Errorf("fingerprint = %q, want colon-separated SHA-256", info.Fingerprint)
	}
}

// The leaves live beside internal/acme's records, never under its prefix: that
// package lists "cert/" to find what it must renew, and would otherwise adopt
// certificates it cannot reissue.
func TestSelfSignedDoesNotWriteUnderTheACMEPrefix(t *testing.T) {
	store := newMemStore()
	src := newTestSelfSignedWith(t, store, time.Now)
	if _, err := src.Ensure(context.Background(), []Request{{Domains: []string{"nas.home.lan"}}}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for key := range store.data {
		if strings.HasPrefix(key, "cert/") {
			t.Errorf("wrote %q, which internal/acme lists as its own to renew", key)
		}
	}
}

// ---- helpers ----

func newTestSelfSigned(t *testing.T, now func() time.Time) *SelfSigned {
	t.Helper()
	return newTestSelfSignedWith(t, newMemStore(), now)
}

func newTestSelfSignedWith(t *testing.T, store Store, now func() time.Time) *SelfSigned {
	t.Helper()
	src, err := NewSelfSigned(SelfSignedConfig{
		Store:  store,
		Name:   "home.lan",
		Logger: slog.New(slog.DiscardHandler),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("NewSelfSigned: %v", err)
	}
	return src
}

func parseLeaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

// memStore is an in-memory Store.
type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: map[string][]byte{}} }

func (m *memStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.data[key]
	return body, ok, nil
}

func (m *memStore) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *memStore) List(_ context.Context, prefix string) (map[string][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]byte{}
	for key, body := range m.data {
		if strings.HasPrefix(key, prefix) {
			out[key] = body
		}
	}
	return out, nil
}

// countingStore records how often each key was written.
type countingStore struct {
	*memStore
	mu     sync.Mutex
	writes map[string]int
}

func (c *countingStore) Put(ctx context.Context, key string, value []byte) error {
	c.mu.Lock()
	if c.writes == nil {
		c.writes = map[string]int{}
	}
	c.writes[key]++
	c.mu.Unlock()
	return c.memStore.Put(ctx, key, value)
}

func (c *countingStore) puts(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes[key]
}
