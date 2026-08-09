package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned mints a certificate for the given names. Enough to exercise
// everything up to the CA: SNI selection, expiry reporting, handshakes.
func selfSigned(t *testing.T, notAfter time.Time, names ...string) Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              names,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	lowered := make([]string, len(names))
	for i, n := range names {
		lowered[i] = strings.ToLower(n)
	}
	return Certificate{
		Domains:  lowered,
		CertPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		NotAfter: notAfter,
	}
}

func TestKeyringSelectsBySNI(t *testing.T) {
	exact := selfSigned(t, time.Now().Add(24*time.Hour), "web.shop.example.com")
	wildcard := selfSigned(t, time.Now().Add(24*time.Hour), "*.apps.example.com")

	ring, err := newKeyring(Bundle{Certificates: []Certificate{exact, wildcard}})
	if err != nil {
		t.Fatalf("newKeyring: %v", err)
	}

	tests := []struct {
		name string
		sni  string
		want bool
	}{
		{"exact", "web.shop.example.com", true},
		{"exact, different case", "WEB.Shop.Example.COM", true},
		{"exact with a port", "web.shop.example.com:443", true},
		{"wildcard covers one label", "api.apps.example.com", true},
		// A wildcard asserts one label. Matching deeper would present a
		// certificate the client is right to reject.
		{"wildcard does not cover two", "a.b.apps.example.com", false},
		{"wildcard does not cover the parent", "apps.example.com", false},
		{"unrelated", "other.example.com", false},
		{"empty", "", false},
	}
	// One table, both implementations. kanead answers this same question when
	// it decides whether an operator's certificate satisfies a service (§7.3),
	// and two versions of "what does a wildcard cover" drift into a certificate
	// that is published and never served.
	domains := append(append([]string{}, exact.Domains...), wildcard.Domains...)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ring.covers(tc.sni); got != tc.want {
				t.Errorf("covers(%q) = %v, want %v", tc.sni, got, tc.want)
			}
			if got := CoversHost(domains, tc.sni); got != tc.want {
				t.Errorf("CoversHost(%q) = %v, want %v", tc.sni, got, tc.want)
			}
		})
	}
}

// Presenting some other host's certificate produces a name-mismatch error,
// which reads to a user as "this site is impersonated" rather than "this site
// has no certificate yet". Refusing the handshake is the honest answer.
func TestTLSConfigRefusesAnUnknownName(t *testing.T) {
	store := newCertStore()
	ring, err := newKeyring(Bundle{
		Certificates: []Certificate{selfSigned(t, time.Now().Add(time.Hour), "known.example.com")},
	})
	if err != nil {
		t.Fatalf("newKeyring: %v", err)
	}
	store.set(ring)

	cfg := store.tlsConfig()
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "known.example.com"}); err != nil {
		t.Errorf("GetCertificate for a known name = %v", err)
	}
	_, err = cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "stranger.example.com"})
	if !errors.Is(err, ErrNoCertificate) {
		t.Errorf("GetCertificate for an unknown name = %v, want ErrNoCertificate", err)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certs.json")
	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	want := Bundle{
		Index:          7,
		Certificates:   []Certificate{selfSigned(t, expiry, "web.shop.example.com")},
		HTTPChallenges: []HTTPChallenge{{Token: "tok", KeyAuth: "tok.thumbprint"}},
	}

	if err := PublishBundle(path, want, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}
	got, err := LoadBundle(path)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if got.Index != 7 || len(got.Certificates) != 1 || len(got.HTTPChallenges) != 1 {
		t.Fatalf("bundle = %+v", got)
	}
	if !got.Certificates[0].NotAfter.Equal(expiry) {
		t.Errorf("NotAfter = %v, want %v", got.Certificates[0].NotAfter, expiry)
	}
}

// This file holds private keys, so it is the one thing in the projection that
// must not be world-readable.
func TestPublishBundleIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certs.json")
	bundle := Bundle{Certificates: []Certificate{selfSigned(t, time.Now().Add(time.Hour), "a.example.com")}}

	if err := PublishBundle(path, bundle, 0); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("mode = %v; the private key is readable by anyone", perm)
	}
	if perm := info.Mode().Perm(); perm&0o070 != 0 {
		t.Errorf("mode = %v; no group was configured, so the group should have no access", perm)
	}
}

func TestBundleRejectsUnusableMaterial(t *testing.T) {
	valid := selfSigned(t, time.Now().Add(time.Hour), "a.example.com")

	tests := []struct {
		name   string
		bundle Bundle
		want   string
	}{
		{"no domains", Bundle{Certificates: []Certificate{{
			CertPEM: valid.CertPEM, KeyPEM: valid.KeyPEM,
		}}}, "covers no domain"},
		{"uncanonical domain", Bundle{Certificates: []Certificate{{
			Domains: []string{"A.Example.com"}, CertPEM: valid.CertPEM, KeyPEM: valid.KeyPEM,
		}}}, "not canonical"},
		// A bundle that loads but cannot be used leaves the edge holding a
		// certificate it silently never serves, which looks exactly like TLS
		// never having been configured.
		{"key does not match", Bundle{Certificates: []Certificate{{
			Domains: []string{"a.example.com"},
			CertPEM: valid.CertPEM,
			KeyPEM:  selfSigned(t, time.Now().Add(time.Hour), "b.example.com").KeyPEM,
		}}}, "certificate 0"},
		{"garbage pem", Bundle{Certificates: []Certificate{{
			Domains: []string{"a.example.com"}, CertPEM: "not pem", KeyPEM: "not pem",
		}}}, "certificate 0"},
		{"challenge with no answer", Bundle{
			HTTPChallenges: []HTTPChallenge{{Token: "tok"}},
		}, "incomplete"},
		// The token becomes a URL path element.
		{"token with a separator", Bundle{
			HTTPChallenges: []HTTPChallenge{{Token: "a/b", KeyAuth: "x"}},
		}, "not a path element"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.bundle.Validate()
			if !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("Validate = %v, want ErrInvalidBundle", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not mention %q", err, tc.want)
			}
		})
	}
}

func TestEmptyKeyringCoversNothing(t *testing.T) {
	store := newCertStore()
	if store.get().covers("anything.example.com") {
		t.Error("the empty keyring claims to cover a host")
	}
	if _, ok := store.get().challenge("tok"); ok {
		t.Error("the empty keyring answered a challenge")
	}
}
