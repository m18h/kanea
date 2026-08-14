package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/store"
)

// Interoperability tests against a real S3-compatible service.
//
// The unit tests in s3_test.go establish that the sink drives the protocol
// correctly and that the signature depends on the request. They cannot
// establish that the signature is one a *service* accepts — a fake server that
// does not verify signatures accepts a broken signer just as happily as a
// correct one, and the signature is precisely the part a hand-written client
// gets wrong.
//
// So these run against something that verifies. They skip unless
// KANEA_S3_ENDPOINT is set, so `go test ./...` on a laptop does not need a
// bucket; CI runs MinIO and sets it. To run locally:
//
//	docker run -d --rm -p 19000:9000 \
//	  -e MINIO_ROOT_USER=kaneatest -e MINIO_ROOT_PASSWORD=kaneatestsecret \
//	  minio/minio:latest server /data
//	KANEA_S3_ENDPOINT=http://127.0.0.1:19000 \
//	  KANEA_S3_ACCESS_KEY=kaneatest KANEA_S3_SECRET_KEY=kaneatestsecret \
//	  go test ./internal/backup/ -run Live -v
//
// The knobs, all optional, so the same binary can be aimed at any provider:
//
//	KANEA_S3_ENDPOINT            required; absent means skip
//	KANEA_S3_ACCESS_KEY          default kaneatest
//	KANEA_S3_SECRET_KEY          default kaneatestsecret
//	KANEA_S3_REGION              default us-east-1 — set it for a real provider,
//	                             or the signature is scoped to the wrong region
//	KANEA_S3_BUCKET              default kanea-test
//	KANEA_S3_PATH_STYLE          "false" selects virtual-hosted addressing
//	KANEA_S3_SKIP_BUCKET_CREATE  set for a bucket provisioned out of band

// liveSink builds a sink against the configured service, creating the bucket.
func liveSink(t *testing.T, prefix string) *S3Sink {
	t.Helper()
	endpoint := os.Getenv("KANEA_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("KANEA_S3_ENDPOINT is not set; skipping the live S3 interoperability test")
	}
	accessKey := envOr("KANEA_S3_ACCESS_KEY", "kaneatest")
	secretKey := envOr("KANEA_S3_SECRET_KEY", "kaneatestsecret")
	region := envOr("KANEA_S3_REGION", "us-east-1")
	bucket := envOr("KANEA_S3_BUCKET", "kanea-test")

	sink, err := NewS3Sink(S3Config{
		Endpoint: endpoint, Bucket: bucket, Prefix: runPrefix() + "/" + prefix, Region: region,
		AccessKey: accessKey, SecretKey: secretKey, PathStyle: livePathStyle(),
	})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	createBucket(t, sink)
	return sink
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// livePathStyle selects the addressing style under test.
//
// It defaults to path-style, which is what MinIO wants and what every release
// before this knob existed exercised. The other branch is not cosmetic: in
// virtual-hosted style the bucket moves into the *host* header, and the host
// header is signed — so it is a different signature over a different canonical
// request, and it is the style AWS prefers. Leaving it untested meant the
// addressing half of what Archiver.Probe claims to prove had never run against
// a service that verifies.
func livePathStyle() bool {
	return envOr("KANEA_S3_PATH_STYLE", "true") != "false"
}

// runPrefix is one random path segment per test process.
//
// The suite used to write under fixed prefixes ("sig", "page") and delete
// everything beneath them, which is safe only while exactly one run exists.
// Against a shared cloud bucket — two providers in a matrix, a re-run of a job
// whose predecessor is still finishing — that cleanup deletes another run's
// objects and the failure looks like the object store losing data. A unique
// prefix makes concurrent runs disjoint, and makes a leaked one identifiable.
var runPrefix = sync.OnceValue(func() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Only reached if the system CSPRNG fails, at which point the test
		// binary has larger problems; a fixed name is still better than a panic.
		return "live-norand"
	}
	return "live-" + hex.EncodeToString(b[:])
})

// createBucket makes the test bucket, tolerating one that already exists.
//
// It reuses the sink's own signing path rather than shelling out to a client,
// which makes bucket creation itself a signature test: if the signer were
// wrong, this would fail first and say so.
//
// KANEA_S3_SKIP_BUCKET_CREATE turns it off for a bucket that is provisioned
// out of band, which every real provider needs: the bare `PUT /<bucket>` below
// carries no CreateBucketConfiguration, so AWS refuses it outside us-east-1,
// and a key scoped to one existing bucket — the right way to hand credentials
// to CI — cannot create anything anywhere. Skipping loses nothing: the first
// Put still proves the signature, which is what this call was standing in for.
// It is an explicit switch rather than blanket 403 tolerance on purpose, since
// a 403 against MinIO means the signer is wrong and must stay fatal.
func createBucket(t *testing.T, sink *S3Sink) {
	t.Helper()
	if os.Getenv("KANEA_S3_SKIP_BUCKET_CREATE") != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := *sink.endpoint
	target.Path = "/" + sink.bucket
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), nil)
	if err != nil {
		t.Fatalf("build create-bucket request: %v", err)
	}
	req.ContentLength = 0
	sink.sign(req)

	resp, err := sink.client.Do(req)
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusConflict:
		// Created, or already there.
	case strings.Contains(string(body), "BucketAlreadyOwnedByYou"),
		strings.Contains(string(body), "BucketAlreadyExists"):
	default:
		// A 403 here almost always means the signature is wrong, which is the
		// whole point of running against a real service.
		t.Fatalf("create bucket returned %s: %s", resp.Status, body)
	}
}

func TestLiveS3AcceptsOurSignature(t *testing.T) {
	// The test the fake server cannot perform: a service that verifies SigV4
	// accepting a request this client signed.
	ctx := context.Background()
	sink := liveSink(t, "sig")

	if err := sink.Put(ctx, "probe.txt", 5, strings.NewReader("hello")); err != nil {
		t.Fatalf("a real S3 service refused our signed PUT: %v", err)
	}
	body, err := sink.Get(ctx, "probe.txt")
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
	if err := sink.Delete(ctx, "probe.txt"); err != nil {
		t.Errorf("delete: %v", err)
	}
}

func TestLiveS3ListPaginatesAgainstARealService(t *testing.T) {
	// MinIO's pagination is the real thing: continuation tokens it generates,
	// not ones a fake echoed back. A listing that stopped at the first page
	// would hide the oldest archives from retention forever.
	ctx := context.Background()
	sink := liveSink(t, "page")

	const count = 12
	for i := range count {
		name := fmt.Sprintf("manifests/%03d.json", i)
		if err := sink.Put(ctx, name, 2, strings.NewReader("{}")); err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		for i := range count {
			_ = sink.Delete(ctx, fmt.Sprintf("manifests/%03d.json", i))
		}
	})

	objects, err := sink.List(ctx, "manifests/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(objects) != count {
		t.Fatalf("listed %d objects, want %d", len(objects), count)
	}
	// Names come back relative to the sink prefix on a real service too, not
	// just against the fake.
	if objects[0].Name != "manifests/000.json" {
		t.Errorf("first object is %q; names are not relative to the sink prefix", objects[0].Name)
	}
}

func TestLiveS3CarriesAWholeArchiveRoundTrip(t *testing.T) {
	// The end-to-end shape: a Store, replicated to a real object store, restored
	// from it. This is M10's exit criterion with the fake taken out.
	ctx := context.Background()
	sink := liveSink(t, "archive")
	keys := testKeys(t, 40)

	src := openStore(t)
	archiver := newStoreArchiver(t, src, sink, keys)
	rep := newReplicator(t, src, archiver)

	put(t, src, store.KindService, "shop/web", "before")
	if err := rep.Snapshot(ctx, "live-test"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	put(t, src, store.KindService, "shop/web", "after")
	put(t, src, store.KindService, "shop/api", "new")
	if err := rep.ShipOnce(ctx); err != nil {
		t.Fatalf("ship: %v", err)
	}
	t.Cleanup(func() { cleanPrefix(t, sink) })

	target := filepath.Join(t.TempDir(), "restored.db")
	result, err := archiver.Restore(ctx, RestoreOptions{Target: target})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if result.Replayed == 0 {
		t.Error("nothing was replayed from the real bucket")
	}

	restored, err := store.Open(store.Options{Path: target})
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer func() { _ = restored.Close() }()
	if value, ok := get(t, restored, store.KindService, "shop/web"); !ok || value != "after" {
		t.Errorf("shop/web = %q (present=%v), want the post-snapshot value", value, ok)
	}
	if _, ok := get(t, restored, store.KindService, "shop/api"); !ok {
		t.Error("shop/api did not survive the round trip")
	}
}

func TestLiveS3RejectsABadSecret(t *testing.T) {
	// The negative control. Without it, a signer that a service ignores
	// entirely would pass every test above.
	endpoint := os.Getenv("KANEA_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("KANEA_S3_ENDPOINT is not set")
	}
	sink, err := NewS3Sink(S3Config{
		Endpoint: endpoint, Bucket: envOr("KANEA_S3_BUCKET", "kanea-test"),
		Region:    envOr("KANEA_S3_REGION", "us-east-1"),
		AccessKey: envOr("KANEA_S3_ACCESS_KEY", "kaneatest"),
		SecretKey: "this-is-not-the-secret-key",
		PathStyle: livePathStyle(),
	})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Put(context.Background(), "should-not-land.txt", 1, strings.NewReader("x")); err == nil {
		t.Fatal("a wrong secret key was accepted; the service is not verifying signatures, " +
			"so the tests above prove nothing about the signer")
	}
}

func TestLiveS3HandlesAMultiChunkArchive(t *testing.T) {
	// A payload larger than one AEAD chunk, uploaded and fetched whole. Chunk
	// framing over a real HTTP body is where an off-by-one in the reader would
	// show up as a corrupt restore rather than as a test failure.
	ctx := context.Background()
	sink := liveSink(t, "chunks")
	keys := testKeys(t, 41)

	payload := make([]byte, 2*chunkSize+1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("random payload: %v", err)
	}

	var sealed bytes.Buffer
	if _, _, err := encryptStream(&sealed, bytes.NewReader(payload), keys); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	size := int64(sealed.Len())
	if err := sink.Put(ctx, "big.snap", size, &sealed); err != nil {
		t.Fatalf("put: %v", err)
	}
	t.Cleanup(func() { _ = sink.Delete(ctx, "big.snap") })

	body, err := sink.Get(ctx, "big.snap")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var back bytes.Buffer
	decryptErr := decryptStream(&back, body, keys)
	if err := body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if decryptErr != nil {
		t.Fatalf("decrypt after a real round trip: %v", decryptErr)
	}
	if !bytes.Equal(back.Bytes(), payload) {
		t.Errorf("the payload changed across a real object store (%d bytes back, want %d)",
			back.Len(), len(payload))
	}
}

// cleanPrefix removes everything the test wrote, so a shared bucket does not
// accumulate.
func cleanPrefix(t *testing.T, sink *S3Sink) {
	t.Helper()
	ctx := context.Background()
	objects, err := sink.List(ctx, "")
	if err != nil {
		t.Logf("cannot list for cleanup: %v", err)
		return
	}
	for _, obj := range objects {
		if err := sink.Delete(ctx, obj.Name); err != nil {
			t.Logf("cannot delete %s: %v", obj.Name, err)
		}
	}
}
