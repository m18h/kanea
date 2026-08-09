package certsource

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// providedFixture writes a certificate and key pair to disk and returns their
// paths.
//
// The material is generated in-test by the self-signed issuer rather than
// checked into testdata: a committed certificate expires, and the suite then
// starts failing on a date nobody chose and for a reason nobody remembers.
func providedFixture(t *testing.T, dir, name string, domains ...string) (certPath, keyPath string) {
	t.Helper()
	return providedFixtureAt(t, dir, name, time.Now, domains...)
}

func providedFixtureAt(t *testing.T, dir, name string, now func() time.Time, domains ...string) (string, string) {
	t.Helper()
	src := newTestSelfSigned(t, now)
	res, err := src.Ensure(context.Background(), []Request{{Domains: domains, Service: "fixture/" + name}})
	if err != nil || len(res.Certificates) != 1 {
		t.Fatalf("issue fixture: err=%v certs=%d", err, len(res.Certificates))
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	writeFixture(t, certPath, res.Certificates[0].CertPEM)
	writeFixture(t, keyPath, res.Certificates[0].KeyPEM)
	return certPath, keyPath
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// providedWith writes a config file and returns a source over it.
func providedWith(t *testing.T, dir, config string) *Provided {
	t.Helper()
	path := filepath.Join(dir, "certs.hcl")
	writeFixture(t, path, config)
	return NewProvided(path, slog.New(slog.DiscardHandler))
}

// cfgBlock renders one certificate block. A single-line HCL block holds at
// most one argument, so this cannot be a one-liner.
func cfgBlock(name, certPath, keyPath, allow string) string {
	return fmt.Sprintf("certificate %q {\n  cert  = %q\n  key   = %q\n  allow = [%s]\n}\n",
		name, certPath, keyPath, allow)
}

func grantBlock(name, certPath, keyPath string, allow ...string) string {
	quoted := make([]string, 0, len(allow))
	for _, a := range allow {
		quoted = append(quoted, fmt.Sprintf("%q", a))
	}
	return cfgBlock(name, certPath, keyPath, strings.Join(quoted, ", "))
}

func ensureOne(t *testing.T, p *Provided, req Request) (Certificate, error) {
	t.Helper()
	res, err := p.Ensure(context.Background(), []Request{req})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(res.Failures) == 1 {
		return Certificate{}, res.Failures[0].Err
	}
	if len(res.Certificates) != 1 {
		t.Fatalf("certificates = %d, failures = %d; want one of each", len(res.Certificates), len(res.Failures))
	}
	return res.Certificates[0], nil
}

// The names come from the certificate, never from the config: that is what lets
// one wildcard certificate serve a whole project without a filename convention
// or a declared domain list that could disagree with what is on disk.
func TestProvidedReadsDomainsFromTheCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := providedFixture(t, dir, "wild", "*.apps.home.lan")
	p := providedWith(t, dir, grantBlock("wild", cert, key, "shop"))

	tests := []struct {
		name    string
		domains []string
		wantErr bool
	}{
		{"one label under the wildcard", []string{"web.apps.home.lan"}, false},
		{"every requested name must be covered", []string{"web.apps.home.lan", "api.apps.home.lan"}, false},
		// A wildcard covers one label, not two, and not its own parent. Getting
		// this wrong publishes a certificate the edge will never select.
		{"two labels", []string{"a.b.apps.home.lan"}, true},
		{"the apex itself", []string{"apps.home.lan"}, true},
		{"one covered, one not", []string{"web.apps.home.lan", "other.home.lan"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ensureOne(t, p, Request{Domains: tc.domains, Project: "shop", Service: "shop/web"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolved %v against a wildcard that does not cover it", tc.domains)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if len(got.Domains) != 1 || got.Domains[0] != "*.apps.home.lan" {
				t.Errorf("domains = %v, want the certificate's own SANs", got.Domains)
			}
		})
	}
}

// The allow list is the whole cross-project boundary here, and it is the same
// one R17/R18 draw. A project that is not on it gets nothing, and the error
// says which list it is not on rather than "no certificate".
func TestProvidedRefusesAProjectNotInAllow(t *testing.T) {
	dir := t.TempDir()
	cert, key := providedFixture(t, dir, "shop", "shop.example.com")
	p := providedWith(t, dir, grantBlock("shop", cert, key, "shop"))

	_, err := ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "blog", Service: "blog/www",
	})
	if err == nil {
		t.Fatal("a project not in the allow list was given the certificate")
	}
	if !strings.Contains(err.Error(), "blog") {
		t.Errorf("error = %v, want it to name the project that was refused", err)
	}

	// Naming a grant that exists but does not allow you is a different sentence
	// from naming one that does not exist, because they need different fixes.
	_, err = ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "blog", Service: "blog/www", Name: "shop",
	})
	if err == nil || !strings.Contains(err.Error(), "allows") {
		t.Errorf("error = %v, want it to name the allow list", err)
	}
	_, err = ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web", Name: "ghost",
	})
	if err == nil || !strings.Contains(err.Error(), "does not define") {
		t.Errorf("error = %v, want it to say the grant does not exist", err)
	}
}

// A `name` narrows the search to one grant even when another would have
// matched, because the spec asked for that one.
func TestProvidedNarrowsToTheNamedGrant(t *testing.T) {
	dir := t.TempDir()
	aCert, aKey := providedFixture(t, dir, "a", "shop.example.com")
	bCert, bKey := providedFixture(t, dir, "b", "shop.example.com")
	p := providedWith(t, dir,
		grantBlock("a", aCert, aKey, "shop")+grantBlock("b", bCert, bKey, "shop"))

	named, err := ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web", Name: "b",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	bPEM, _ := os.ReadFile(bCert)
	if named.CertPEM != string(bPEM) {
		t.Error("a name selected some other grant")
	}

	// With no name, both are candidates and the tie breaks by grant name — the
	// same choice on every node and every restart.
	unnamed, err := ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	aPEM, _ := os.ReadFile(aCert)
	if unnamed.CertPEM != string(aPEM) {
		t.Error("the tie did not break by grant name")
	}
}

// Cert and key from different pairs is the commonest operator error here, and
// it produces a handshake failure with nothing useful on the client side. It
// has to be named as itself.
func TestProvidedNamesAMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	cert, _ := providedFixture(t, dir, "a", "shop.example.com")
	_, otherKey := providedFixture(t, dir, "b", "shop.example.com")
	p := providedWith(t, dir, grantBlock("mixed", cert, otherKey, "shop"))

	_, err := ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web",
	})
	if err == nil {
		t.Fatal("a mismatched cert and key resolved")
	}
	if !strings.Contains(err.Error(), "matching pair") {
		t.Errorf("error = %v, want it to name the mismatch", err)
	}
}

// An expired certificate is published anyway. Refusing it at midnight turns a
// stale site into an unreachable one, and the operator finds out from the
// browser either way.
func TestProvidedServesAnExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	longAgo := func() time.Time { return time.Now().Add(-2 * LeafValidity) }
	cert, key := providedFixtureAt(t, dir, "stale", longAgo, "shop.example.com")
	p := providedWith(t, dir, grantBlock("stale", cert, key, "shop"))

	got, err := ensureOne(t, p, Request{
		Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web",
	})
	if err != nil {
		t.Fatalf("an expired certificate was refused: %v", err)
	}
	if !got.NotAfter.Before(time.Now()) {
		t.Error("the fixture was not actually expired")
	}
}

// Nothing here ever produces a certificate from somewhere else. A request the
// config cannot satisfy is a Failure, and the caller leaves the service on
// plaintext rather than quietly serving something untrusted.
func TestProvidedNeverFallsBack(t *testing.T) {
	p := NewProvided("", slog.New(slog.DiscardHandler))
	res, err := p.Ensure(context.Background(), []Request{
		{Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web"},
	})
	if err != nil {
		t.Fatalf("Ensure on an unconfigured node returned an error: %v", err)
	}
	if len(res.Certificates) != 0 {
		t.Fatal("an unconfigured node produced a certificate")
	}
	if len(res.Failures) != 1 || !errors.Is(res.Failures[0].Err, ErrNoCertificate) {
		t.Errorf("failures = %+v, want one ErrNoCertificate", res.Failures)
	}
}

// Renewal happens behind Kanea's back — certbot writes and renames — so the
// poll has to notice new bytes at the same path, and has to stay quiet when
// nothing moved.
func TestProvidedChangedTracksTheFiles(t *testing.T) {
	dir := t.TempDir()
	cert, key := providedFixture(t, dir, "shop", "shop.example.com")
	configPath := filepath.Join(dir, "certs.hcl")
	writeFixture(t, configPath, grantBlock("shop", cert, key, "shop"))
	p := NewProvided(configPath, slog.New(slog.DiscardHandler))

	if !p.Changed() {
		t.Fatal("the first poll saw no change")
	}
	if p.Changed() {
		t.Error("an unchanged config reported a change; every poll would rebuild the bundle")
	}

	// A renewal: same path, same grant, new bytes.
	newCert, newKey := providedFixture(t, dir, "renewed", "shop.example.com")
	newCertPEM, _ := os.ReadFile(newCert)
	newKeyPEM, _ := os.ReadFile(newKey)
	writeFixture(t, cert, string(newCertPEM))
	writeFixture(t, key, string(newKeyPEM))

	if !p.Changed() {
		t.Error("a renewed certificate at the same path was not noticed")
	}
	if p.Changed() {
		t.Error("the renewal was reported twice")
	}

	// And an edit to the config itself.
	writeFixture(t, configPath, grantBlock("shop", cert, key, "shop", "blog"))
	if !p.Changed() {
		t.Error("an edited config was not noticed")
	}
}

// A half-saved config must not take working sites down: the last one that
// parsed keeps serving, which is edge.Watcher's discipline.
func TestProvidedKeepsTheLastGoodConfig(t *testing.T) {
	dir := t.TempDir()
	cert, key := providedFixture(t, dir, "shop", "shop.example.com")
	configPath := filepath.Join(dir, "certs.hcl")
	writeFixture(t, configPath, grantBlock("shop", cert, key, "shop"))
	p := NewProvided(configPath, slog.New(slog.DiscardHandler))

	req := Request{Domains: []string{"shop.example.com"}, Project: "shop", Service: "shop/web"}
	if _, err := ensureOne(t, p, req); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	writeFixture(t, configPath, `certificate "shop" { cert = `)
	if _, err := ensureOne(t, p, req); err != nil {
		t.Errorf("a broken config stopped serving a certificate that still resolves: %v", err)
	}
}

// The config errors, all of which are things an operator does once and needs
// told about precisely.
func TestProvidedConfigErrors(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{
			"grant name is not a label",
			cfgBlock("Shop Cert", "/a.crt", "/a.key", `"shop"`),
			"DNS-1123",
		},
		{
			"defined twice",
			cfgBlock("shop", "/a.crt", "/a.key", `"shop"`) + cfgBlock("shop", "/b.crt", "/b.key", `"shop"`),
			"defined twice",
		},
		{
			"empty allow is not a permissive default",
			cfgBlock("shop", "/a.crt", "/a.key", ""),
			"not a permissive default",
		},
		{
			"relative path",
			cfgBlock("shop", "tls/a.crt", "/a.key", `"shop"`),
			"relative",
		},
		{
			"allowed project is not a label",
			cfgBlock("shop", "/a.crt", "/a.key", `"Shop"`),
			"not a DNS-1123 label",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCertPolicy("certs.hcl", []byte(tc.config))
			if err == nil {
				t.Fatal("the config was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}
