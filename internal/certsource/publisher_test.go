package certsource

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/edge"
)

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
	if err := pub.SetCertificates(ModeACME, []Certificate{cert}); err != nil {
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

// ---- the merge ----

// The regression the whole seam exists for. Three sources publish into one
// file on their own schedules; a publisher that stored one flat list would
// serve whichever source wrote last and silently drop the other two.
func TestEachSourceKeepsItsOwnContribution(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "certs.json")
	pub, err := NewPublisher(PublisherConfig{Path: bundlePath, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}

	if err := pub.SetCertificates(ModeACME, []Certificate{testCertificate(t, "shop.example.com")}); err != nil {
		t.Fatalf("SetCertificates(acme): %v", err)
	}
	if err := pub.SetCertificates(ModeSelfSigned, []Certificate{testCertificate(t, "nas.home.lan")}); err != nil {
		t.Fatalf("SetCertificates(self-signed): %v", err)
	}
	if err := pub.SetCertificates(ModeProvided, []Certificate{testCertificate(t, "blog.example.com")}); err != nil {
		t.Fatalf("SetCertificates(provided): %v", err)
	}

	got := publishedDomains(t, bundlePath)
	want := []string{"blog.example.com", "nas.home.lan", "shop.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("published domains = %v, want %v (a source dropped another's certificates)", got, want)
	}
}

// A source is called with everything it should be holding, including nothing,
// so an empty set withdraws its certificates and only its certificates.
func TestAnEmptySetWithdrawsOnlyThatSource(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "certs.json")
	pub, err := NewPublisher(PublisherConfig{Path: bundlePath, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := pub.SetCertificates(ModeACME, []Certificate{testCertificate(t, "shop.example.com")}); err != nil {
		t.Fatalf("SetCertificates(acme): %v", err)
	}
	if err := pub.SetCertificates(ModeSelfSigned, []Certificate{testCertificate(t, "nas.home.lan")}); err != nil {
		t.Fatalf("SetCertificates(self-signed): %v", err)
	}
	if err := pub.SetCertificates(ModeACME, nil); err != nil {
		t.Fatalf("SetCertificates(acme, nil): %v", err)
	}

	got := publishedDomains(t, bundlePath)
	if !slices.Equal(got, []string{"nas.home.lan"}) {
		t.Errorf("published domains = %v, want only the self-signed one", got)
	}
}

// A name held by two sources resolves by mergeOrder, and the loser keeps the
// names it did win rather than being dropped whole.
func TestACollidingNameResolvesByPrecedence(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "certs.json")
	pub, err := NewPublisher(PublisherConfig{Path: bundlePath, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}

	// The self-signed source holds a wildcard covering two names; the operator
	// then provides a certificate for one of them.
	selfSigned := testCertificate(t, "a.home.lan", "b.home.lan")
	provided := testCertificate(t, "b.home.lan")
	if err := pub.SetCertificates(ModeSelfSigned, []Certificate{selfSigned}); err != nil {
		t.Fatalf("SetCertificates(self-signed): %v", err)
	}
	if err := pub.SetCertificates(ModeProvided, []Certificate{provided}); err != nil {
		t.Fatalf("SetCertificates(provided): %v", err)
	}

	bundle, err := edge.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	byPEM := map[string][]string{}
	for _, c := range bundle.Certificates {
		byPEM[c.CertPEM] = c.Domains
	}
	if got := byPEM[provided.CertPEM]; !slices.Equal(got, []string{"b.home.lan"}) {
		t.Errorf("provided certificate covers %v, want the contested name", got)
	}
	if got := byPEM[selfSigned.CertPEM]; !slices.Equal(got, []string{"a.home.lan"}) {
		t.Errorf("self-signed certificate covers %v, want only the name it still wins", got)
	}
}

// A certificate that wins no names at all is not published: a private key on
// disk that nothing will ever select is a key doing no work.
func TestAFullyShadowedCertificateIsDropped(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "certs.json")
	pub, err := NewPublisher(PublisherConfig{Path: bundlePath, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if err := pub.SetCertificates(ModeSelfSigned, []Certificate{testCertificate(t, "nas.home.lan")}); err != nil {
		t.Fatalf("SetCertificates(self-signed): %v", err)
	}
	if err := pub.SetCertificates(ModeProvided, []Certificate{testCertificate(t, "nas.home.lan")}); err != nil {
		t.Fatalf("SetCertificates(provided): %v", err)
	}

	bundle, err := edge.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if len(bundle.Certificates) != 1 {
		t.Errorf("certificates = %d, want the shadowed one dropped", len(bundle.Certificates))
	}
}

// The edge reloads on a byte difference, so republishing an identical set with
// a fresh index is a keyring rebuild that changed nothing. Harmless twice a day
// with ACME alone; once a file-backed source is stat-ed every minute it becomes
// a rebuild every minute, forever.
func TestAnUnchangedSetDoesNotRepublish(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "certs.json")
	pub, err := NewPublisher(PublisherConfig{Path: bundlePath, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}

	certs := []Certificate{testCertificate(t, "shop.example.com")}
	if err := pub.SetCertificates(ModeACME, certs); err != nil {
		t.Fatalf("SetCertificates: %v", err)
	}
	first, err := os.ReadFile(bundlePath) // #nosec G304 — a test path
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	if err := pub.SetCertificates(ModeACME, certs); err != nil {
		t.Fatalf("SetCertificates again: %v", err)
	}
	second, err := os.ReadFile(bundlePath) // #nosec G304 — a test path
	if err != nil {
		t.Fatalf("read bundle again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("republishing an unchanged set rewrote the bundle:\nfirst:  %s\nsecond: %s", first, second)
	}

	// A real change still moves the index, or the check above would have made
	// the bundle unupdatable.
	if err := pub.SetCertificates(ModeACME, []Certificate{testCertificate(t, "other.example.com")}); err != nil {
		t.Fatalf("SetCertificates with a change: %v", err)
	}
	third, err := os.ReadFile(bundlePath) // #nosec G304 — a test path
	if err != nil {
		t.Fatalf("read bundle after a change: %v", err)
	}
	if bytes.Equal(second, third) {
		t.Error("a changed set did not rewrite the bundle")
	}
}

// publishedDomains reads back every domain the bundle covers, sorted.
func publishedDomains(t *testing.T, path string) []string {
	t.Helper()
	bundle, err := edge.LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	var out []string
	for _, c := range bundle.Certificates {
		out = append(out, c.Domains...)
	}
	slices.Sort(out)
	return out
}
