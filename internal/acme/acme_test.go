package acme

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/edge"
)

// Renewal starts two thirds into the certificate's life, not a fixed number of
// days before expiry: for a 90-day Let's Encrypt certificate that leaves a full
// month of failed passes before anything actually stops working.
func TestRenewAfterIsTwoThirdsOfLife(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := Certificate{
		Domains:   []string{"web.example.com"},
		NotBefore: start,
		NotAfter:  start.Add(90 * 24 * time.Hour),
	}

	want := start.Add(60 * 24 * time.Hour)
	if got := cert.RenewAfter(); !got.Equal(want) {
		t.Errorf("RenewAfter = %v, want %v", got, want)
	}

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"fresh", start.Add(time.Hour), false},
		{"just before", want.Add(-time.Minute), false},
		{"exactly at the threshold", want, true},
		{"overdue", want.Add(24 * time.Hour), true},
		{"expired", cert.NotAfter.Add(time.Hour), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cert.NeedsRenewal(tc.now); got != tc.want {
				t.Errorf("NeedsRenewal(%v) = %v, want %v", tc.now, got, tc.want)
			}
		})
	}
}

// A certificate with no usable validity window is due immediately. Treating it
// as never-due is how a broken record becomes a silent non-renewal.
func TestRenewAfterHandlesAnEmptyValidityWindow(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := Certificate{NotBefore: at, NotAfter: at}
	if !cert.NeedsRenewal(at) {
		t.Error("a zero-length certificate is not due for renewal")
	}
}

// "Covers" is exact, not "at least". A service that gained a domain needs a
// certificate naming it; one that lost a domain should stop asserting it.
func TestCoversIsExact(t *testing.T) {
	cert := Certificate{Domains: []string{"a.example.com", "b.example.com"}}

	tests := []struct {
		name    string
		domains []string
		want    bool
	}{
		{"same set", []string{"a.example.com", "b.example.com"}, true},
		{"a name was added", []string{"a.example.com", "b.example.com", "c.example.com"}, false},
		{"a name was removed", []string{"a.example.com"}, false},
		{"reordered", []string{"b.example.com", "a.example.com"}, false},
		{"unrelated", []string{"z.example.com"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cert.Covers(tc.domains); got != tc.want {
				t.Errorf("Covers(%v) = %v, want %v", tc.domains, got, tc.want)
			}
		})
	}
}

func TestNewRequiresItsInputs(t *testing.T) {
	solver := &fakeSolver{}
	base := Config{Email: "ops@example.com", Store: &memStore{}, Solver: solver}

	if _, err := New(Config{Store: base.Store, Solver: solver}); err == nil {
		t.Error("accepted a config with no email")
	}
	if _, err := New(Config{Email: base.Email, Solver: solver}); err == nil {
		t.Error("accepted a config with no store")
	}
	if _, err := New(Config{Email: base.Email, Store: base.Store}); err == nil {
		t.Error("accepted a config with no solver")
	}
	if _, err := New(base); err != nil {
		t.Errorf("New = %v", err)
	}
}

// An operator who has not chosen deliberately should not be spending
// production rate limit.
func TestNewDefaultsToStaging(t *testing.T) {
	m, err := New(Config{Email: "ops@example.com", Store: &memStore{}, Solver: &fakeSolver{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.directory != LetsEncryptStaging {
		t.Errorf("directory = %q, want the staging CA", m.directory)
	}
}

// The account key is generated once and reused: it is the identity the CA rate
// limits, so a node that made a new one on every start would look like a new
// account each time.
func TestAccountKeyIsGeneratedOnceAndReused(t *testing.T) {
	st := &memStore{}
	m, err := New(Config{Email: "ops@example.com", Store: st, Solver: &fakeSolver{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	first, err := m.accountKey(ctx)
	if err != nil {
		t.Fatalf("accountKey: %v", err)
	}
	second, err := m.accountKey(ctx)
	if err != nil {
		t.Fatalf("accountKey: %v", err)
	}

	// Same key material, and only one record written.
	if first == nil || second == nil {
		t.Fatal("accountKey returned nil")
	}
	if len(st.data) != 1 {
		t.Errorf("stored %d records, want just the account key", len(st.data))
	}

	// And a fresh manager over the same store reuses it rather than registering
	// a second account at the CA.
	again, err := New(Config{Email: "ops@example.com", Store: st, Solver: &fakeSolver{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := again.accountKey(ctx); err != nil {
		t.Fatalf("accountKey after restart: %v", err)
	}
	if len(st.data) != 1 {
		t.Errorf("stored %d records after restart, want 1", len(st.data))
	}
}

// A stored certificate that is still fresh must not be reissued: every
// unnecessary issuance spends a duplicate-certificate slot.
func TestSyncSkipsAFreshCertificate(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	st := &memStore{}
	m, err := New(Config{
		Email: "ops@example.com", Store: st, Solver: &fakeSolver{},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fresh := Certificate{
		Domains: []string{"web.example.com"},
		CertPEM: "cert", KeyPEM: "key",
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(60 * 24 * time.Hour),
	}
	if err := m.save(context.Background(), fresh); err != nil {
		t.Fatalf("save: %v", err)
	}

	// No ACME directory is reachable in this test, so any attempt to issue
	// would fail — reaching the end with the stored certificate returned is
	// what proves nothing was requested.
	out, err := m.Sync(context.Background(), []Request{
		{Domains: []string{"web.example.com"}, Service: "shop/web"},
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(out) != 1 || out[0].CertPEM != "cert" {
		t.Fatalf("Sync = %+v, want the stored certificate", out)
	}
}

// An issuance that fails must leave the existing certificate in place. An
// expiring certificate still works; no certificate does not.
func TestSyncKeepsTheOldCertificateWhenIssuanceFails(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	st := &memStore{}
	m, err := New(Config{
		// An unreachable directory, so issuance is guaranteed to fail.
		Directory: "https://127.0.0.1:1/directory",
		Email:     "ops@example.com", Store: st, Solver: &fakeSolver{},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stale := Certificate{
		Domains: []string{"web.example.com"},
		CertPEM: "old", KeyPEM: "key",
		NotBefore: now.Add(-89 * 24 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour), // well past the renewal point
	}
	if err := m.save(context.Background(), stale); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !stale.NeedsRenewal(now) {
		t.Fatal("the fixture is not actually due for renewal")
	}

	out, err := m.Sync(context.Background(), []Request{
		{Domains: []string{"web.example.com"}, Service: "shop/web"},
	})
	if err != nil {
		t.Fatalf("Sync = %v, want the failure to be per-request", err)
	}
	if len(out) != 1 || out[0].CertPEM != "old" {
		t.Fatalf("Sync = %+v, want the old certificate kept", out)
	}
}

// ---- publisher ----

// Publishing is a file write the edge polls for, so returning before it is
// being served would race the CA — and losing that race spends a
// failed-validation slot rather than merely retrying.
func TestPresentWaitsForTheEdgeToServeTheChallenge(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "certs.json")

	// A stand-in for the edge: it serves whatever the published bundle holds,
	// but only after a delay, so the wait is doing real work.
	served := &servedBundle{path: bundlePath}
	srv := served.start(t, 150*time.Millisecond)

	pub, err := NewPublisher(PublisherConfig{
		Path:          bundlePath,
		VerifyURL:     srv,
		VerifyTimeout: 5 * time.Second,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}

	start := time.Now()
	if err := pub.Present(context.Background(), "web.example.com", "tok", "tok.auth"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("Present returned after %v; it did not wait for the edge", elapsed)
	}

	// The answer really is in the published bundle.
	bundle, err := edge.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if len(bundle.HTTPChallenges) != 1 || bundle.HTTPChallenges[0].KeyAuth != "tok.auth" {
		t.Errorf("bundle challenges = %+v", bundle.HTTPChallenges)
	}

	if err := pub.CleanUp(context.Background(), "web.example.com", "tok", "tok.auth"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	bundle, err = edge.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle after cleanup: %v", err)
	}
	if len(bundle.HTTPChallenges) != 0 {
		t.Errorf("challenge survived cleanup: %+v", bundle.HTTPChallenges)
	}
}

// Asking the CA to validate a challenge we cannot serve ourselves is guaranteed
// to fail, and failures are the rate limit that hurts. So the wait gives up
// rather than proceeding.
func TestPresentFailsWhenTheEdgeNeverServesIt(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "certs.json")

	// An "edge" that never picks anything up.
	silent := &servedBundle{path: bundlePath, ignore: true}
	srv := silent.start(t, 0)

	pub, err := NewPublisher(PublisherConfig{
		Path:          bundlePath,
		VerifyURL:     srv,
		VerifyTimeout: 300 * time.Millisecond,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}

	err = pub.Present(context.Background(), "web.example.com", "tok", "tok.auth")
	if err == nil {
		t.Fatal("Present succeeded without the edge serving the challenge")
	}
	if !strings.Contains(err.Error(), "not serving the challenge") {
		t.Errorf("error = %v", err)
	}
}

// Certificates already held must survive a challenge being published: they
// share one file, and an in-flight issuance must not take TLS down.
func TestChallengesDoNotDisturbPublishedCertificates(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "certs.json")
	pub, err := NewPublisher(PublisherConfig{Path: bundlePath, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}

	cert := testCertificate(t, "web.example.com")
	if err := pub.SetCertificates([]Certificate{cert}); err != nil {
		t.Fatalf("SetCertificates: %v", err)
	}
	if err := pub.Present(context.Background(), "other.example.com", "tok", "tok.auth"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	bundle, err := edge.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if len(bundle.Certificates) != 1 {
		t.Errorf("certificates = %d, want the one already published", len(bundle.Certificates))
	}
	if len(bundle.HTTPChallenges) != 1 {
		t.Errorf("challenges = %d, want 1", len(bundle.HTTPChallenges))
	}
}

func TestNewPublisherRequiresAPath(t *testing.T) {
	if _, err := NewPublisher(PublisherConfig{}); err == nil {
		t.Error("accepted a publisher with no path")
	}
}

// ---- fakes ----

type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (s *memStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok, nil
}

func (s *memStore) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = map[string][]byte{}
	}
	s.data[key] = value
	return nil
}

func (s *memStore) List(_ context.Context, prefix string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range s.data {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out, nil
}

type fakeSolver struct{}

func (fakeSolver) Present(context.Context, string, string, string) error { return nil }
func (fakeSolver) CleanUp(context.Context, string, string, string) error { return nil }
