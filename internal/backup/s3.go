package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The S3 sink, written against the REST API rather than an SDK.
//
// The same call PRD v1.20 made about lego's DNS providers, for the same reason:
// this platform's premise is one small binary, and aws-sdk-go-v2 brings a
// service-model runtime, a credential-provider chain, an IMDS client and a
// retry framework to perform four verbs. Signature Version 4 is fully specified
// and about two hundred lines. What is *not* reimplemented is TLS, HTTP or the
// hashing — those come from the standard library.
//
// "S3-compatible" is the target, not S3: MinIO, Garage, Backblaze B2, Wasabi
// and Cloudflare R2 all speak this, which matters for a platform whose users
// are running one node.

// S3Config configures the sink.
type S3Config struct {
	// Endpoint is the service URL, e.g. https://s3.eu-west-1.amazonaws.com or
	// https://minio.internal:9000. Required — there is no built-in region
	// endpoint table, because guessing an endpoint is how backups end up in
	// the wrong jurisdiction.
	Endpoint string
	// Bucket holds the archives.
	Bucket string
	// Prefix scopes this node's archives within the bucket, so several nodes
	// can share one.
	Prefix string
	// Region is the SigV4 region. Defaults to "us-east-1", which is what
	// non-AWS implementations conventionally accept.
	Region string
	// AccessKey and SecretKey authenticate. The secret comes from the secrets
	// store as a `secret:` reference (R3) and is resolved before it gets here.
	AccessKey string
	SecretKey string
	// PathStyle addresses the bucket as /bucket/key rather than as a subdomain.
	// Required by most self-hosted implementations, and harmless on AWS.
	PathStyle bool
	// HTTPClient is injectable for tests. Nil takes a bounded default.
	HTTPClient *http.Client
	Logger     *slog.Logger
	// Now is injectable so a signature can be tested against a known vector.
	Now func() time.Time
}

// S3Sink stores archives in an S3-compatible bucket.
type S3Sink struct {
	endpoint  *url.URL
	bucket    string
	prefix    string
	region    string
	accessKey string
	secretKey string
	pathStyle bool
	client    *http.Client
	log       *slog.Logger
	now       func() time.Time
}

// NewS3Sink validates the configuration and returns a sink.
func NewS3Sink(cfg S3Config) (*S3Sink, error) {
	switch {
	case cfg.Endpoint == "":
		return nil, errors.New("backup: an S3 endpoint is required")
	case cfg.Bucket == "":
		return nil, errors.New("backup: an S3 bucket is required")
	case cfg.AccessKey == "" || cfg.SecretKey == "":
		return nil, errors.New("backup: S3 credentials are required")
	}

	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("backup: S3 endpoint: %w", err)
	}
	if endpoint.Host == "" {
		return nil, fmt.Errorf("backup: S3 endpoint %q has no host", cfg.Endpoint)
	}
	// http is allowed and https is the default, because a MinIO on the same
	// private network is a real deployment. It is a decision the operator makes
	// by writing the scheme, and a plaintext one is said out loud below.
	if endpoint.Scheme == "" {
		endpoint.Scheme = "https"
	}
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" {
		return nil, fmt.Errorf("backup: S3 endpoint scheme %q is not http or https", endpoint.Scheme)
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			// Generous: a snapshot upload is not a control-plane request and can
			// legitimately take minutes on a slow link. Bounded all the same,
			// because a replicator blocked forever on a dead endpoint stops
			// shipping and never says why.
			Timeout: 30 * time.Minute,
		}
	}
	if endpoint.Scheme == "http" {
		cfg.Logger.Warn("shipping backups over plain HTTP",
			"endpoint", endpoint.String(),
			"detail", "archive contents are encrypted, but the request signature and "+
				"object names are not — prefer https unless this is a private network")
	}

	return &S3Sink{
		endpoint: endpoint, bucket: cfg.Bucket,
		prefix:    strings.Trim(cfg.Prefix, "/"),
		region:    cfg.Region,
		accessKey: cfg.AccessKey, secretKey: cfg.SecretKey,
		pathStyle: cfg.PathStyle, client: cfg.HTTPClient,
		log: cfg.Logger, now: cfg.Now,
	}, nil
}

// Describe names the sink. The credentials are not in it — this string ends up
// in logs and in error messages an operator pastes into an issue.
func (s *S3Sink) Describe() string {
	target := "s3://" + s.bucket
	if s.prefix != "" {
		target += "/" + s.prefix
	}
	return target + " at " + s.endpoint.Host
}

// key maps an object name onto its full bucket key.
func (s *S3Sink) key(name string) string {
	if s.prefix == "" {
		return name
	}
	return s.prefix + "/" + name
}

// Put uploads an object.
//
// A single PUT, not a multipart upload. That caps an archive at the 5 GiB
// single-object limit, which is far above a bbolt database holding the state of
// one node — and multipart is a second protocol with its own abort-and-clean-up
// failure modes, which is not worth carrying for a case that does not arise.
// The size is required for the same reason: a signed request needs a
// Content-Length, and chunked signing is a third protocol again.
func (s *S3Sink) Put(ctx context.Context, name string, size int64, body io.Reader) (err error) {
	if size < 0 {
		return fmt.Errorf("backup: %s has unknown size; the S3 sink needs one to sign the request", name)
	}
	if size > maxSingleObject {
		return fmt.Errorf("backup: %s is %d bytes, above the %d-byte single-upload limit",
			name, size, int64(maxSingleObject))
	}

	req, err := s.request(ctx, http.MethodPut, s.key(name), nil, body)
	if err != nil {
		return err
	}
	req.ContentLength = size

	resp, err := s.do(req)
	if err != nil {
		return fmt.Errorf("backup: upload %s: %w", name, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	return s.expect(resp, name, http.StatusOK)
}

// maxSingleObject is S3's limit for a non-multipart PUT.
const maxSingleObject = 5 << 30

// Get downloads an object.
func (s *S3Sink) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	req, err := s.request(ctx, http.MethodGet, s.key(name), nil, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.do(req)
	if err != nil {
		return nil, fmt.Errorf("backup: download %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		err := s.expect(resp, name, http.StatusOK)
		return nil, errors.Join(err, resp.Body.Close())
	}
	// The caller closes it. This is the one path that hands back an open body,
	// because a snapshot is decrypted as it arrives rather than buffered.
	return resp.Body, nil
}

// Delete removes an object. S3 answers 204 whether or not it existed, which is
// exactly the idempotence the Sink contract asks for.
func (s *S3Sink) Delete(ctx context.Context, name string) (err error) {
	req, err := s.request(ctx, http.MethodDelete, s.key(name), nil, nil)
	if err != nil {
		return err
	}
	resp, err := s.do(req)
	if err != nil {
		return fmt.Errorf("backup: delete %s: %w", name, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	return s.expect(resp, name, http.StatusNoContent, http.StatusOK)
}

// listResult is the ListObjectsV2 response.
type listResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	// NextContinuationToken drives pagination. A bucket with more than a
	// thousand archives is not expected, but a listing that silently stopped at
	// a thousand would hide the oldest ones from retention and grow the bill
	// forever.
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// List enumerates objects under a prefix.
func (s *S3Sink) List(ctx context.Context, prefix string) ([]Object, error) {
	full := s.key(prefix)
	var out []Object
	token := ""

	for {
		query := url.Values{
			"list-type": {"2"},
			"prefix":    {full},
			"max-keys":  {"1000"},
		}
		if token != "" {
			query.Set("continuation-token", token)
		}

		page, err := s.listPage(ctx, query)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Contents {
			// Names are reported relative to the sink's prefix, so callers
			// address objects the same way whichever sink they hold.
			name := strings.TrimPrefix(item.Key, s.prefix+"/")
			if s.prefix == "" {
				name = item.Key
			}
			out = append(out, Object{Name: name, Size: item.Size, Modified: item.LastModified})
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		token = page.NextContinuationToken
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *S3Sink) listPage(ctx context.Context, query url.Values) (_ listResult, err error) {
	req, reqErr := s.request(ctx, http.MethodGet, "", query, nil)
	if reqErr != nil {
		return listResult{}, reqErr
	}
	resp, err := s.do(req)
	if err != nil {
		return listResult{}, fmt.Errorf("backup: list %s: %w", s.Describe(), err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if err := s.expect(resp, "the bucket listing", http.StatusOK); err != nil {
		return listResult{}, err
	}
	var page listResult
	if err := xml.NewDecoder(io.LimitReader(resp.Body, maxListBytes)).Decode(&page); err != nil {
		return listResult{}, fmt.Errorf("backup: decode the bucket listing: %w", err)
	}
	return page, nil
}

// maxListBytes bounds one listing page. A thousand keys of a hundred bytes is
// well under this; anything larger is a response worth refusing rather than
// buffering.
const maxListBytes = 8 << 20

// do sends a request, without retrying.
//
// Retries belong to the replicator, which knows whether the operation is worth
// repeating and how long the caller is prepared to wait. A transport that
// retried on its own would double-upload snapshots and multiply a slow link's
// problems.
func (s *S3Sink) do(req *http.Request) (*http.Response, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		// The URL is in the error and the signature is not: the Authorization
		// header never appears in an error, which is why this wraps rather than
		// dumping the request.
		return nil, err
	}
	return resp, nil
}

// s3Error is the XML error body every S3 implementation returns.
type s3Error struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// expect checks a status and turns anything else into a readable error.
func (s *S3Sink) expect(resp *http.Response, what string, allowed ...int) error {
	for _, status := range allowed {
		if resp.StatusCode == status {
			return nil
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	}

	// The body is read for its Code, which is the difference between "your
	// clock is wrong", "that bucket does not exist" and "those credentials are
	// not allowed to write here" — three failures an operator fixes in three
	// completely different places.
	var body s3Error
	detail := resp.Status
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err == nil && body.Code != "" {
		detail = fmt.Sprintf("%s: %s (%s)", resp.Status, body.Message, body.Code)
	}
	return fmt.Errorf("backup: %s in %s: %s", what, s.Describe(), detail)
}

// ---- request signing ----

// request builds a signed request.
func (s *S3Sink) request(
	ctx context.Context, method, key string, query url.Values, body io.Reader,
) (*http.Request, error) {
	target := *s.endpoint
	switch {
	case s.pathStyle:
		target.Path = "/" + s.bucket
		if key != "" {
			target.Path += "/" + key
		}
	default:
		target.Host = s.bucket + "." + target.Host
		target.Path = "/"
		if key != "" {
			target.Path = "/" + key
		}
	}
	if query != nil {
		target.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("backup: build request: %w", err)
	}
	s.sign(req)
	return req, nil
}

// unsignedPayload tells S3 not to include a body hash in the signature.
//
// The alternative is hashing the payload before sending it, which for a
// multi-hundred-megabyte snapshot means reading it twice — once to hash, once
// to send. The body's integrity is not left to the transport: it is an AEAD
// stream whose every chunk is authenticated, and the manifest records its
// SHA-256 independently. TLS covers the wire.
const unsignedPayload = "UNSIGNED-PAYLOAD"

// sign applies AWS Signature Version 4 to a request.
func (s *S3Sink) sign(req *http.Request) {
	now := s.now().UTC()
	stamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	// Host is not in Header for an outgoing request; it lives on the URL, and
	// the canonical request needs it explicitly.
	host := req.URL.Host

	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + unsignedPayload + "\n" +
		"x-amz-date:" + stamp + "\n"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.EscapedPath()),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders,
		strings.Join(signed, ";"),
		unsignedPayload,
	}, "\n")

	scope := strings.Join([]string{date, s.region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		stamp,
		scope,
		hashHex([]byte(canonicalRequest)),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+s.secretKey), date)
	key = hmacSHA256(key, s.region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, strings.Join(signed, ";"), signature))
}

// canonicalURI is the path, already percent-encoded, with an empty path
// becoming "/".
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

// canonicalQuery is the query string sorted by name, with values encoded the
// way SigV4 requires.
//
// url.Values.Encode sorts by key and percent-encodes to the same rules, with
// one exception that matters: it encodes a space as "+", and SigV4 requires
// "%20". None of the query parameters here contain spaces, but relying on that
// is relying on a fact about today's callers.
func canonicalQuery(values url.Values) string {
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

func hashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
