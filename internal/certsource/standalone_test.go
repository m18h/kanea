package certsource

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func TestStandalonePairPEM(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	t.Run("an IP host gets an IP SAN", func(t *testing.T) {
		certPEM, keyPEM, err := StandalonePairPEM("198.100.154.249", now)
		if err != nil {
			t.Fatalf("StandalonePairPEM: %v", err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("the minted pair must load: %v", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("198.100.154.249")) {
			t.Errorf("IPAddresses = %v, want [198.100.154.249]", leaf.IPAddresses)
		}
		if len(leaf.DNSNames) != 0 {
			t.Errorf("an IP-shaped host must not become a DNS SAN: %v", leaf.DNSNames)
		}
		if got := leaf.NotAfter.Sub(now); got != StandaloneValidity {
			t.Errorf("validity = %v, want %v (10 years)", got, StandaloneValidity)
		}
		if !leaf.NotBefore.Before(now) {
			t.Errorf("NotBefore = %v, want backdated for clock skew", leaf.NotBefore)
		}
		// Self-signed: it must verify against a pool holding only itself.
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName: "198.100.154.249", Roots: pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("the certificate must verify against itself: %v", err)
		}
	})

	t.Run("a name gets a DNS SAN", func(t *testing.T) {
		certPEM, _, err := StandalonePairPEM("kanea.example.com", now)
		if err != nil {
			t.Fatalf("StandalonePairPEM: %v", err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("the certificate is not PEM")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "kanea.example.com" {
			t.Errorf("DNSNames = %v, want [kanea.example.com]", leaf.DNSNames)
		}
		if len(leaf.IPAddresses) != 0 {
			t.Errorf("a name must not become an IP SAN: %v", leaf.IPAddresses)
		}
	})

	t.Run("an empty host is refused: a SAN needs something to name", func(t *testing.T) {
		if _, _, err := StandalonePairPEM("  ", now); err == nil {
			t.Fatal("a blank host must not produce a nameless certificate")
		}
	})
}
