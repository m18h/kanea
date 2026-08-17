// Package sigv4 implements AWS Signature Version 4 request signing.
//
// It exists because two subsystems sign AWS-shaped requests (the backup S3
// sink (§15.3) and the Secrets Manager provider (§5.2.13)) and a signing
// algorithm duplicated is a signing algorithm that drifts. The scope is
// deliberately the signature and nothing else: no credential-provider chain,
// no IMDS client, no retry framework. TLS, HTTP and the hashing come from the
// standard library (the S3 sink's original argument, PRD v1.20/v1.27).
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// UnsignedPayload tells S3 not to include a body hash in the signature.
//
// The alternative is hashing the payload before sending it, which for a
// multi-hundred-megabyte snapshot means reading it twice: once to hash, once
// to send. Only S3 accepts it; the JSON APIs (Secrets Manager) sign the real
// body hash, which is cheap because their bodies are small.
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// Options carries what the signature needs beyond the request itself.
type Options struct {
	AccessKey string
	SecretKey string
	// Region and Service scope the signing key, e.g. "eu-west-1" and "s3" or
	// "secretsmanager".
	Region  string
	Service string
	// PayloadHash is the hex SHA-256 of the request body, or UnsignedPayload.
	// It is part of the canonical request for every service; S3 additionally
	// wants it in an X-Amz-Content-Sha256 header, which Sign sets when the
	// service is "s3".
	PayloadHash string
	// Now is the signing time. The zero value means time.Now, but callers
	// with an injectable clock should pass it through: a skewed signature is
	// a 403 with an unhelpful message.
	Now time.Time
}

// Sign applies AWS Signature Version 4 to a request.
//
// It sets X-Amz-Date (and X-Amz-Content-Sha256 for S3), then signs the host,
// content-type when present, and every x-amz-* header already on the request,
// sorted. Signing everything x-amz-* is not generosity: AWS rejects a request
// carrying an x-amz-* header the signature does not cover, so a caller adding
// X-Amz-Target must have it signed without this package knowing the header
// exists.
func Sign(req *http.Request, opts Options) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	stamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	req.Header.Set("X-Amz-Date", stamp)
	if opts.Service == "s3" {
		req.Header.Set("X-Amz-Content-Sha256", opts.PayloadHash)
	}

	// Host is not in Header for an outgoing request; it lives on the URL, and
	// the canonical request needs it explicitly.
	headers := map[string]string{"host": req.URL.Host}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			headers[lower] = strings.TrimSpace(strings.Join(values, ","))
		}
	}
	signed := make([]string, 0, len(headers))
	for name := range headers {
		signed = append(signed, name)
	}
	sort.Strings(signed)

	var canonicalHeaders strings.Builder
	for _, name := range signed {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(headers[name])
		canonicalHeaders.WriteString("\n")
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.EscapedPath()),
		CanonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		strings.Join(signed, ";"),
		opts.PayloadHash,
	}, "\n")

	scope := strings.Join([]string{date, opts.Region, opts.Service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		stamp,
		scope,
		HashHex([]byte(canonicalRequest)),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+opts.SecretKey), date)
	key = hmacSHA256(key, opts.Region)
	key = hmacSHA256(key, opts.Service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		opts.AccessKey, scope, strings.Join(signed, ";"), signature))
}

// canonicalURI is the path, already percent-encoded, with an empty path
// becoming "/".
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

// CanonicalQuery is the query string sorted by name, with values encoded the
// way SigV4 requires.
//
// url.Values.Encode sorts by key and percent-encodes to the same rules, with
// one exception that matters: it encodes a space as "+", and SigV4 requires
// "%20". None of the query parameters here contain spaces, but relying on that
// is relying on a fact about today's callers.
func CanonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		vs := append([]string(nil), values[key]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, escapeSigV4(key)+"="+escapeSigV4(v))
		}
	}
	return strings.Join(parts, "&")
}

// escapeSigV4 percent-encodes to RFC 3986, which is what SigV4 canonicalises
// with.
func escapeSigV4(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// HashHex is the hex SHA-256 SigV4 uses for payloads and canonical requests.
func HashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
