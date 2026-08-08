package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 is enough of an S3-compatible service to exercise the sink: whole
// objects in a map, ListObjectsV2 with pagination, and the error shapes.
//
// These tests establish that the sink drives the protocol correctly. They do
// not establish interoperability with any particular implementation — only a
// real endpoint does that, and the signature is the part where a real endpoint
// would disagree.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	// requests records what arrived, for assertions about signing.
	requests []*http.Request
	// pageSize forces pagination when set.
	pageSize int
	// failWith answers every request with this status when set.
	failWith int
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]byte{}} }

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Clone(context.Background()))

	if f.failWith != 0 {
		w.WriteHeader(f.failWith)
		_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code>`+
			`<Message>the credentials may not write here</Message></Error>`)
		return
	}

	// Path style: /bucket/key...
	key := strings.TrimPrefix(r.URL.Path, "/")
	if bucket, rest, found := strings.Cut(key, "/"); found && bucket == "archives" {
		key = rest
	} else if key == "archives" {
		key = ""
	}

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.objects[key] = body
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			f.list(w, r)
			return
		}
		body, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>not here</Message></Error>`)
			return
		}
		_, _ = w.Write(body)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3) list(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	var keys []string
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	// Deterministic order, so pagination is reproducible.
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	start := 0
	if token := r.URL.Query().Get("continuation-token"); token != "" {
		for i, key := range keys {
			if key == token {
				start = i
				break
			}
		}
	}
	size := len(keys)
	if f.pageSize > 0 {
		size = f.pageSize
	}
	end := min(start+size, len(keys))

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	for _, key := range keys[start:end] {
		fmt.Fprintf(&b, `<Contents><Key>%s</Key><Size>%d</Size>`+
			`<LastModified>2026-08-08T12:00:00.000Z</LastModified></Contents>`,
			key, len(f.objects[key]))
	}
	if end < len(keys) {
		fmt.Fprintf(&b, `<IsTruncated>true</IsTruncated>`+
			`<NextContinuationToken>%s</NextContinuationToken>`, keys[end])
	} else {
		b.WriteString(`<IsTruncated>false</IsTruncated>`)
	}
	b.WriteString(`</ListBucketResult>`)
	_, _ = io.WriteString(w, b.String())
}

func newS3Sink(t *testing.T, fake *fakeS3, adjust ...func(*S3Config)) (*S3Sink, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	cfg := S3Config{
		Endpoint: server.URL, Bucket: "archives", Prefix: "node-1",
		Region: "eu-west-1", AccessKey: "AKIAEXAMPLE", SecretKey: "wJalrXUtnFEMI",
		PathStyle: true, HTTPClient: server.Client(),
		Now: func() time.Time { return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC) },
	}
	for _, apply := range adjust {
		apply(&cfg)
	}
	sink, err := NewS3Sink(cfg)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	return sink, server
}

func TestS3RoundTrip(t *testing.T) {
	ctx := context.Background()
	fake := newFakeS3()
	sink, _ := newS3Sink(t, fake)

	if err := sink.Put(ctx, "snapshots/a.snap", 5, strings.NewReader("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}

	body, err := sink.Get(ctx, "snapshots/a.snap")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}

	objects, err := sink.List(ctx, "snapshots/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Names come back relative to the sink prefix, so a caller addresses an
	// object the same way whichever sink it holds.
	if len(objects) != 1 || objects[0].Name != "snapshots/a.snap" {
		t.Fatalf("objects = %+v, want the one written under its relative name", objects)
	}
	if objects[0].Size != 5 {
		t.Errorf("size = %d, want 5", objects[0].Size)
	}

	if err := sink.Delete(ctx, "snapshots/a.snap"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := sink.Get(ctx, "snapshots/a.snap"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

func TestS3ObjectsLandUnderThePrefix(t *testing.T) {
	// Several nodes sharing one bucket is the reason the prefix exists; an
	// object written outside it is another node's archive.
	ctx := context.Background()
	fake := newFakeS3()
	sink, _ := newS3Sink(t, fake)

	if err := sink.Put(ctx, "manifests/x.json", 2, strings.NewReader("{}")); err != nil {
		t.Fatalf("put: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, ok := fake.objects["node-1/manifests/x.json"]; !ok {
		t.Fatalf("object keys = %v, want one under node-1/", keysOf(fake.objects))
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestS3ListPaginates(t *testing.T) {
	// A listing that silently stopped at the first page would hide the oldest
	// archives from retention and grow the bill forever.
	ctx := context.Background()
	fake := newFakeS3()
	fake.pageSize = 2
	sink, _ := newS3Sink(t, fake)

	for i := range 7 {
		name := fmt.Sprintf("manifests/%02d.json", i)
		if err := sink.Put(ctx, name, 2, strings.NewReader("{}")); err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
	}

	objects, err := sink.List(ctx, "manifests/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(objects) != 7 {
		t.Fatalf("listed %d objects, want 7 — pagination stopped early", len(objects))
	}
}

func TestS3ErrorsCarryTheServiceCode(t *testing.T) {
	// "Your clock is wrong", "no such bucket" and "not allowed to write here"
	// are fixed in three different places, and the code is what tells them
	// apart.
	ctx := context.Background()
	fake := newFakeS3()
	fake.failWith = http.StatusForbidden
	sink, _ := newS3Sink(t, fake)

	err := sink.Put(ctx, "snapshots/a.snap", 1, strings.NewReader("x"))
	if err == nil {
		t.Fatal("a 403 was reported as success")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("the error drops the service code: %v", err)
	}
	if strings.Contains(err.Error(), "wJalrXUtnFEMI") {
		t.Fatalf("the secret key is in the error: %v", err)
	}
}

func TestS3DescribeHidesCredentials(t *testing.T) {
	fake := newFakeS3()
	sink, _ := newS3Sink(t, fake)
	described := sink.Describe()
	for _, secret := range []string{"AKIAEXAMPLE", "wJalrXUtnFEMI"} {
		if strings.Contains(described, secret) {
			t.Errorf("Describe() leaks %q: %s", secret, described)
		}
	}
	if !strings.Contains(described, "archives") {
		t.Errorf("Describe() does not name the bucket: %s", described)
	}
}

// ---- signing ----

func signedRequest(t *testing.T, adjust ...func(*S3Config)) *http.Request {
	t.Helper()
	fake := newFakeS3()
	sink, _ := newS3Sink(t, fake, adjust...)
	if err := sink.Put(context.Background(), "snapshots/a.snap", 1, strings.NewReader("x")); err != nil {
		t.Fatalf("put: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.requests[len(fake.requests)-1]
}

func TestSignatureHasTheRequiredShape(t *testing.T) {
	req := signedRequest(t)

	auth := req.Header.Get("Authorization")
	for _, want := range []string{
		"AWS4-HMAC-SHA256 ",
		"Credential=AKIAEXAMPLE/20260808/eu-west-1/s3/aws4_request",
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization is missing %q:\n%s", want, auth)
		}
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20260808T120000Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != unsignedPayload {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %s", got, unsignedPayload)
	}
	if strings.Contains(auth, "wJalrXUtnFEMI") {
		t.Fatal("the secret key is in the Authorization header")
	}
}

func TestSignatureDependsOnTheRequest(t *testing.T) {
	// A signature that did not change with the key, the region or the time
	// would be a signature that is not signing anything — the failure mode a
	// hand-written implementation is most likely to have and least likely to
	// notice, because a fake server accepts it either way.
	base := signatureOf(t, signedRequest(t))

	cases := map[string]func(*S3Config){
		"a different secret key": func(c *S3Config) { c.SecretKey = "another-secret" },
		"a different access key": func(c *S3Config) { c.AccessKey = "AKIAOTHER" },
		"a different region":     func(c *S3Config) { c.Region = "us-west-2" },
		"a different time": func(c *S3Config) {
			c.Now = func() time.Time { return time.Date(2026, 8, 9, 13, 0, 0, 0, time.UTC) }
		},
		"a different bucket": func(c *S3Config) { c.Bucket = "other" },
		"a different prefix": func(c *S3Config) { c.Prefix = "node-2" },
	}
	for name, adjust := range cases {
		t.Run(name, func(t *testing.T) {
			if got := signatureOf(t, signedRequest(t, adjust)); got == base {
				t.Errorf("the signature did not change with %s", name)
			}
		})
	}
}

func signatureOf(t *testing.T, req *http.Request) string {
	t.Helper()
	_, sig, found := strings.Cut(req.Header.Get("Authorization"), "Signature=")
	if !found {
		t.Fatalf("no signature in %q", req.Header.Get("Authorization"))
	}
	return sig
}

func TestCanonicalQueryEncodesSpacesTheWaySigV4Requires(t *testing.T) {
	// url.Values.Encode would write "+", which SigV4 does not accept. No
	// current parameter contains a space, and relying on that is relying on a
	// fact about today's callers.
	got := canonicalQuery(url.Values{"prefix": {"a b"}, "list-type": {"2"}})
	want := "list-type=2&prefix=a%20b"
	if got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
}

func TestS3ConfigRefusesTheIncomplete(t *testing.T) {
	// Each of these is a way to end up with a backup destination that silently
	// is not one.
	cases := map[string]S3Config{
		"no endpoint":    {Bucket: "b", AccessKey: "a", SecretKey: "s"},
		"no bucket":      {Endpoint: "https://s3.example.com", AccessKey: "a", SecretKey: "s"},
		"no credentials": {Endpoint: "https://s3.example.com", Bucket: "b"},
		"bad scheme":     {Endpoint: "ftp://s3.example.com", Bucket: "b", AccessKey: "a", SecretKey: "s"},
		"no host":        {Endpoint: "https://", Bucket: "b", AccessKey: "a", SecretKey: "s"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewS3Sink(cfg); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestS3RefusesAnObjectAboveTheSingleUploadLimit(t *testing.T) {
	// Signed as one PUT, so the limit is real. Reporting it beats a 400 from
	// the service that names no number.
	fake := newFakeS3()
	sink, _ := newS3Sink(t, fake)
	err := sink.Put(context.Background(), "snapshots/huge.snap", maxSingleObject+1, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "single-upload limit") {
		t.Fatalf("err = %v, want the limit named", err)
	}
}
