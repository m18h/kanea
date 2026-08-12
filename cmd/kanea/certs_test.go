package main

import (
	"context"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/acme"
	"github.com/m18h/kanea/internal/certsource"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/store"
)

// The v1.32 default was Let's Encrypt *staging*, so a node configured entirely
// correctly served certificates every browser rejects. The aliases exist so an
// operator never has to paste a URL to get the right one.
func TestResolveDirectory(t *testing.T) {
	tests := []struct{ in, want string }{
		{DirectoryProduction, acme.LetsEncryptProduction},
		{DirectoryStaging, acme.LetsEncryptStaging},
		// A private or test CA is still just a URL, passed through untouched.
		{"https://ca.internal/acme/directory", "https://ca.internal/acme/directory"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := resolveDirectory(tc.in); got != tc.want {
			t.Errorf("resolveDirectory(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The API listener's certificate (bind.api_tls, PRD v1.61) rides the ordinary
// §7.3 pass as a synthetic request: one sync must issue it, deliver it to the
// listener's holder — IP SAN and all — and keep it out of the edge bundle,
// which serves services and must not carry a private key no route names.
func TestSyncCertificatesDeliversTheListenerCertificate(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	discard := slog.New(slog.DiscardHandler)
	bundle := filepath.Join(t.TempDir(), "certs.json")
	publisher, err := certsource.NewPublisher(certsource.PublisherConfig{Path: bundle, Logger: discard})
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, err := certsource.NewSelfSigned(certsource.SelfSignedConfig{
		Store: certStoreAdapter{store: st}, Logger: discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &certificates{
		sources:   []certsource.Source{selfSigned},
		publisher: publisher,
		ca:        selfSigned,
		listener: &listenerCertificate{
			mode: certsource.ModeSelfSigned, domains: []string{"192.168.1.10"},
		},
	}

	// Before the first pass the handshake fails by name, never serves wrong.
	if _, err := c.listener.GetCertificate(nil); err == nil {
		t.Fatal("a handshake before the first issuance must fail, not serve nothing")
	}

	emit := func(notify.Event) {}
	if err := syncCertificates(context.Background(), c, st,
		"", string(certsource.ModeSelfSigned), discard, emit, map[string]time.Time{}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	pair, err := c.listener.GetCertificate(nil)
	if err != nil {
		t.Fatalf("the pass did not deliver the listener certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("192.168.1.10"); err != nil {
		t.Fatalf("a client dialling the IP rejects the certificate: %v", err)
	}

	body, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "192.168.1.10") {
		t.Fatal("the listener certificate leaked into the edge bundle")
	}

	// A second pass is the renewal shape: not yet due, so the same
	// certificate is re-delivered without a reissue.
	before := leaf.SerialNumber.String()
	if err := syncCertificates(context.Background(), c, st,
		"", string(certsource.ModeSelfSigned), discard, emit, map[string]time.Time{}); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	pair, err = c.listener.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.String() != before {
		t.Fatal("an undue certificate was reissued on an ordinary pass")
	}
}
