package acme

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// caTrustingClient builds an HTTP client that trusts an extra CA bundle when
// talking to the ACME directory.
//
// This exists for a private or test ACME server (Pebble in CI). It *adds* a
// root; it never disables verification, which is the difference between
// pointing at a different CA and not checking who you are talking to.
func caTrustingClient(bundle []byte) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		// A system pool that cannot be read is not a reason to trust nothing
		// else, but it is worth not silently starting from empty.
		return nil, fmt.Errorf("acme: system cert pool: %w", err)
	}
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, errors.New("acme: the supplied CA bundle contains no certificate")
	}

	return &http.Client{
		Timeout: acmeHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        8,
			IdleConnTimeout:     30 * time.Second,
		},
	}, nil
}

// acmeHTTPTimeout bounds a single call to the CA. Generous, because issuance
// involves the CA doing work, but not unbounded: a hung directory must not
// wedge the renewal pass forever.
const acmeHTTPTimeout = 60 * time.Second

// encode and decode are the store's value codec. JSON, matching the rest of
// Kanea's Store usage, so a certificate record is readable in a backup.
func encode(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("acme: encode: %w", err)
	}
	return body, nil
}

func decode(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("acme: decode: %w", err)
	}
	return nil
}
