package secretsource

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Transport hygiene (PRD §5.2.13, §14 A10).
//
// Provider endpoints are operator-written node config (the same trust class
// as the replication S3 endpoint) so the notification egress guard is
// deliberately not consulted: it exists for attacker-influencable text, and
// Vault legitimately answers on RFC1918. What is kept regardless: redirects
// are refused (a 302 to the metadata service is the classic residual risk),
// response bodies are read under a hard cap, every dial carries a short
// timeout, and error bodies are decoded into typed shapes or dropped; an
// error string must never be able to carry a value.

// maxResponseBytes bounds every provider response. Secrets Manager caps a
// secret at 64 KiB; a megabyte is generous for every API here and refuses
// pathology.
const maxResponseBytes = 1 << 20

// errRedirect is what every provider dial returns for a 3xx.
var errRedirect = errors.New("secretsource: redirects are refused")

// DefaultHTTPClient is the shared transport for every provider: short
// timeout, no redirects.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

// clientWithCA clones a client with one extra trusted root, for a Vault
// behind a private CA. The system pool stays: an extra root is additive, not
// a replacement.
func clientWithCA(base *http.Client, caFile string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile) // #nosec G304; operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("secretsource: read ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("secretsource: %s holds no PEM certificates", caFile)
	}
	clone := *base
	clone.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return &clone, nil
}

// readAndClose reads a 2xx response's body under the cap and closes it. A
// body that exceeds the cap is refused rather than truncated: a truncated
// secret stored whole is a corruption nobody would trace back here.
func readAndClose(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err == nil && len(body) > maxResponseBytes {
		err = fmt.Errorf("secretsource: response exceeds %d bytes", maxResponseBytes)
	}
	if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}

// httpStatusError renders a non-2xx response as an error, closing its body
// without echoing it. Providers wrap a JSON message shape around their
// errors; anything that parses as one is quoted, anything else is dropped: a
// raw body echoed into an error is a path for a value to reach a log line.
func httpStatusError(resp *http.Response) error {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if readErr != nil {
		body = nil
	}
	closeErr := resp.Body.Close()
	if msg := errorMessage(body); msg != "" {
		return errors.Join(fmt.Errorf("secretsource: %s: %s", resp.Status, msg), closeErr)
	}
	return errors.Join(fmt.Errorf("secretsource: %s", resp.Status), closeErr)
}

// errorMessage pulls a human-readable message out of the JSON error shapes
// the five providers use.
func errorMessage(body []byte) string {
	var shape struct {
		Message  string   `json:"message"`  // AWS, GCP token endpoint
		Errors   []string `json:"errors"`   // Vault
		Messages []string `json:"messages"` // Doppler
		Error    struct {
			Message string `json:"message"` // Azure, GCP API
		} `json:"error"`
		Type string `json:"__type"` // AWS's exception name
	}
	if err := json.Unmarshal(body, &shape); err != nil {
		return ""
	}
	switch {
	case shape.Message != "":
		return shape.Message
	case len(shape.Errors) > 0:
		return strings.Join(shape.Errors, "; ")
	case len(shape.Messages) > 0:
		return strings.Join(shape.Messages, "; ")
	case shape.Error.Message != "":
		return shape.Error.Message
	case shape.Type != "":
		return shape.Type
	}
	return ""
}

// readCredentialFile loads a provider credential, refusing a file another
// user could read: master.key's exact rule (§14 A02), because both files
// unlock the same class of thing. One trailing newline is trimmed, the
// `kanea secret put` stdin rule: `echo token > file` should mean the token.
func readCredentialFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secretsource: credential file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf(
			"secretsource: credential file %s has mode %04o; refusing a credential another "+
				"user can read; chmod 600 it", path, mode)
	}
	body, err := os.ReadFile(path) // #nosec G304; operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("secretsource: credential file: %w", err)
	}
	body = []byte(strings.TrimSuffix(string(body), "\n"))
	if len(body) == 0 {
		return nil, fmt.Errorf("secretsource: credential file %s is empty", path)
	}
	return body, nil
}

// failAll marks every mapping failed with one cause: the shape for a
// provider-level failure (unreadable credential, unreachable endpoint) where
// per-mapping detail would be the same line repeated.
func failAll(mappings []syncMapping, refFn func(syncMapping) string, err error) Result {
	var res Result
	for _, m := range mappings {
		res.Failures = append(res.Failures, Failure{To: m.To, Ref: refFn(m), Err: err})
	}
	return res
}
