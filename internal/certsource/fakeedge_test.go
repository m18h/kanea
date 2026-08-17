package certsource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/edge"
)

// servedBundle stands in for kanea-edge: it answers ACME challenge requests
// from the published bundle, after a settling delay that models the edge's
// poll. That delay is the whole reason Present has to wait.
type servedBundle struct {
	path string
	// ignore makes it never pick anything up, modelling an edge that is down or
	// pointed at a different file.
	ignore  bool
	settle  time.Duration
	written time.Time
}

// start serves the bundle and returns the base URL.
func (s *servedBundle) start(t *testing.T, settle time.Duration) string {
	t.Helper()
	s.settle = settle
	s.written = time.Now()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if s.ignore || time.Since(s.written) < s.settle {
			http.NotFound(w, r)
			return
		}
		bundle, err := edge.LoadBundle(s.path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		for _, ch := range bundle.HTTPChallenges {
			if ch.Token == token {
				_, _ = io.WriteString(w, ch.KeyAuth)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// testCertificate mints a usable certificate so the publisher's validation
// (which parses the key pair) has something real to accept.
func testCertificate(t *testing.T, names ...string) Certificate {
	name := names[0]
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
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
	return Certificate{
		Domains:   names,
		CertPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}
