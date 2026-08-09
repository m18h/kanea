package api_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
)

// fakeCA stands in for the self-signed source.
type fakeCA struct {
	pem []byte
	err error
}

func (f fakeCA) CACertificate(context.Context) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.pem, nil
}

// A node with no self-signed source has no CA, and says which mode would make
// one rather than reporting a bare failure.
func TestCACertificateIsAbsentWithoutASource(t *testing.T) {
	h := newHarness(t)

	_, err := h.client.CACertificate(context.Background())
	if err == nil {
		t.Fatal("a node with no self-signed source returned a CA certificate")
	}
	if !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("error = %v, want it to name the mode that would create one", err)
	}
}

// The route serves the certificate bytes verbatim: it is a PEM file an operator
// redirects into a trust store, not a JSON envelope to unwrap.
func TestCACertificateIsServedVerbatim(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.CA = fakeCA{pem: []byte(pem)}
	})

	got, err := h.client.CACertificate(context.Background())
	if err != nil {
		t.Fatalf("CACertificate: %v", err)
	}
	if string(got) != pem {
		t.Errorf("CA certificate = %q, want it byte-for-byte", got)
	}
}

// A source that cannot produce one reads to the caller the same as not having
// one: there is no CA to install. The detail belongs in the daemon's log.
func TestCACertificateReportsAnUngeneratedCA(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.CA = fakeCA{err: errors.New("this node has no self-signed CA")}
	})

	if _, err := h.client.CACertificate(context.Background()); err == nil {
		t.Fatal("a source with no CA returned one")
	}
}
