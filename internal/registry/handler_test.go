package registry_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes/docker"
)

func TestBlobRoundTrip(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	content := []byte("layer bytes")
	dgst := h.pushBlob(t, "shop/web", content)

	head := h.do(t, http.MethodHead, "/v2/shop/web/blobs/"+dgst, nil, false, nil)
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD blob = %d", head.StatusCode)
	}
	if got := head.Header.Get("Docker-Content-Digest"); got != dgst {
		t.Errorf("HEAD Docker-Content-Digest = %q", got)
	}
	if got := head.Header.Get("Content-Length"); got != fmt.Sprint(len(content)) {
		t.Errorf("HEAD Content-Length = %q", got)
	}

	get := h.do(t, http.MethodGet, "/v2/shop/web/blobs/"+dgst, nil, false, nil)
	body, err := io.ReadAll(get.Body)
	if err != nil || string(body) != string(content) {
		t.Fatalf("GET blob = %q (%v)", body, err)
	}

	// A ranged read is what containerd's fetcher sends when it resumes.
	ranged := h.do(t, http.MethodGet, "/v2/shop/web/blobs/"+dgst, nil, false,
		map[string]string{"Range": "bytes=6-"})
	if ranged.StatusCode != http.StatusPartialContent {
		t.Fatalf("ranged GET = %d, want 206", ranged.StatusCode)
	}
	part, _ := io.ReadAll(ranged.Body) //nolint:errcheck // asserted by content below
	if string(part) != "bytes" {
		t.Errorf("ranged body = %q", part)
	}
}

func TestMissingBlobIs404(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	resp := h.do(t, http.MethodGet,
		"/v2/shop/web/blobs/sha256:"+repeat64("0"), nil, false, nil)
	if resp.StatusCode != http.StatusNotFound || errorCode(t, resp) != "BLOB_UNKNOWN" {
		t.Fatalf("missing blob = %d", resp.StatusCode)
	}
}

func repeat64(s string) string {
	out := ""
	for range 64 {
		out += s
	}
	return out
}

func TestUploadVerifiesTheDigest(t *testing.T) {
	h := newHarness(t, allowShopWeb)

	post := h.do(t, http.MethodPost, "/v2/shop/web/blobs/uploads/", nil, true, nil)
	location := post.Header.Get("Location")

	lie := "sha256:" + repeat64("a")
	put := h.do(t, http.MethodPut, location+"?digest="+lie, []byte("not those bytes"), true, nil)
	if put.StatusCode != http.StatusBadRequest || errorCode(t, put) != "DIGEST_INVALID" {
		t.Fatalf("mismatched PUT = %d, want 400 DIGEST_INVALID", put.StatusCode)
	}

	// Fail closed: the lied-about digest must not have landed.
	stat := h.do(t, http.MethodHead, "/v2/shop/web/blobs/"+lie, nil, false, nil)
	if stat.StatusCode != http.StatusNotFound {
		t.Fatalf("the refused blob is being served (%d)", stat.StatusCode)
	}
	_, _, digests, _, _ := h.reg.Refusals()
	if digests == 0 {
		t.Error("the digest refusal was not counted")
	}
}

func TestChunkedUploadIsSequential(t *testing.T) {
	h := newHarness(t, allowShopWeb)

	post := h.do(t, http.MethodPost, "/v2/shop/web/blobs/uploads/", nil, true, nil)
	location := post.Header.Get("Location")

	first := h.do(t, http.MethodPatch, location, []byte("hello "), true,
		map[string]string{"Content-Range": "0-5"})
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first PATCH = %d", first.StatusCode)
	}

	// A chunk that skips ahead is refused with the session's real offset.
	skip := h.do(t, http.MethodPatch, location, []byte("!"), true,
		map[string]string{"Content-Range": "10-10"})
	if skip.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("out-of-order PATCH = %d, want 416", skip.StatusCode)
	}

	second := h.do(t, http.MethodPatch, location, []byte("world"), true,
		map[string]string{"Content-Range": "6-10"})
	if second.StatusCode != http.StatusAccepted {
		t.Fatalf("second PATCH = %d", second.StatusCode)
	}

	content := []byte("hello world")
	put := h.do(t, http.MethodPut, location+"?digest="+digestOf(content), nil, true, nil)
	if put.StatusCode != http.StatusCreated {
		t.Fatalf("finalising PUT = %d", put.StatusCode)
	}
	get := h.do(t, http.MethodGet, "/v2/shop/web/blobs/"+digestOf(content), nil, false, nil)
	body, _ := io.ReadAll(get.Body) //nolint:errcheck // asserted below
	if string(body) != "hello world" {
		t.Errorf("assembled blob = %q", body)
	}
}

func TestUploadSessionsAreCapped(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	for i := 0; i < 8; i++ {
		resp := h.do(t, http.MethodPost, "/v2/shop/web/blobs/uploads/", nil, true, nil)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("session %d = %d", i, resp.StatusCode)
		}
	}
	over := h.do(t, http.MethodPost, "/v2/shop/web/blobs/uploads/", nil, true, nil)
	if over.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ninth session = %d, want 429", over.StatusCode)
	}
	_, _, _, bounds, _ := h.reg.Refusals()
	if bounds == 0 {
		t.Error("the bound refusal was not counted")
	}
}

func TestMountAnswersFromTheGlobalBlobSet(t *testing.T) {
	h := newHarness(t, func(_ context.Context, project, _ string) bool {
		return project == "shop"
	})
	dgst := h.pushBlob(t, "shop/web", []byte("shared layer"))

	// The same blob mounted into a sibling repository costs no copy.
	resp := h.do(t, http.MethodPost,
		"/v2/shop/api/blobs/uploads/?mount="+dgst+"&from=shop%2Fweb", nil, true, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mount = %d, want 201", resp.StatusCode)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != dgst {
		t.Errorf("mount digest = %q", got)
	}
}

func TestManifestRoundTripAndHeadResolve(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	manifest, dgst := h.pushImage(t, "shop/web", "v1", 1)

	// HEAD by tag is containerd's resolve path and requires all three
	// headers, or the client falls back to hashing a GET.
	head := h.do(t, http.MethodHead, "/v2/shop/web/manifests/v1", nil, false, nil)
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD manifest = %d", head.StatusCode)
	}
	if got := head.Header.Get("Docker-Content-Digest"); got != dgst {
		t.Errorf("resolve digest = %q, want %q", got, dgst)
	}
	if got := head.Header.Get("Content-Type"); got != "application/vnd.oci.image.manifest.v1+json" {
		t.Errorf("resolve media type = %q", got)
	}
	if got := head.Header.Get("Content-Length"); got != fmt.Sprint(len(manifest)) {
		t.Errorf("resolve length = %q", got)
	}

	// The GET returns the stored bytes verbatim: they are the digest's
	// preimage, and any re-serialisation breaks the pull.
	get := h.do(t, http.MethodGet, "/v2/shop/web/manifests/"+dgst, nil, false, nil)
	body, err := io.ReadAll(get.Body)
	if err != nil || string(body) != string(manifest) {
		t.Fatalf("manifest bytes changed in storage: %q (%v)", body, err)
	}
}

func TestManifestRequiresItsBlobs(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"sha256:` + repeat64("b") + `"},"layers":[]}`)
	resp := h.do(t, http.MethodPut, "/v2/shop/web/manifests/v1", manifest, true,
		map[string]string{"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != "MANIFEST_BLOB_UNKNOWN" {
		t.Fatalf("dangling manifest = %d, want 400 MANIFEST_BLOB_UNKNOWN", resp.StatusCode)
	}
}

func TestManifestPushedByDigestMustMatch(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	manifest := []byte(`{"schemaVersion":2,"layers":[]}`)
	resp := h.do(t, http.MethodPut, "/v2/shop/web/manifests/sha256:"+repeat64("c"),
		manifest, true, map[string]string{"Content-Type": "application/vnd.oci.image.manifest.v1+json"})
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != "DIGEST_INVALID" {
		t.Fatalf("mismatched manifest = %d, want 400 DIGEST_INVALID", resp.StatusCode)
	}
}

func TestWritesAreBoundedToDeclaredPipelines(t *testing.T) {
	h := newHarness(t, allowShopWeb)

	resp := h.do(t, http.MethodPost, "/v2/other/svc/blobs/uploads/", nil, true, nil)
	if resp.StatusCode != http.StatusForbidden || errorCode(t, resp) != "DENIED" {
		t.Fatalf("undeclared repo POST = %d, want 403 DENIED", resp.StatusCode)
	}

	// A nil bound refuses everything: fail closed.
	closed := newHarness(t, nil)
	shut := closed.do(t, http.MethodPost, "/v2/shop/web/blobs/uploads/", nil, true, nil)
	if shut.StatusCode != http.StatusForbidden {
		t.Fatalf("nil-bound POST = %d, want 403", shut.StatusCode)
	}
}

func TestRepositoryNamesAreShaped(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	for _, path := range []string{
		"/v2/Shop/web/blobs/uploads/",   // uppercase
		"/v2/-shop/web/blobs/uploads/",  // leading hyphen
		"/v2/shop/we..b/blobs/uploads/", // dots
	} {
		resp := h.do(t, http.MethodPost, path, nil, true, nil)
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != "NAME_INVALID" {
			t.Errorf("%s = %d, want 400 NAME_INVALID", path, resp.StatusCode)
		}
	}
}

func TestTheRestOfTheProtocolIsUnsupported(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/v2/_catalog"},
		{http.MethodGet, "/v2/shop/web/tags/list"},
		{http.MethodDelete, "/v2/shop/web/manifests/sha256:" + repeat64("d")},
		{http.MethodGet, "/anything"},
	} {
		resp := h.do(t, probe.method, probe.path, nil, true, nil)
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s %s answered 200; it is not implemented", probe.method, probe.path)
		}
	}
	_, _, _, _, unknown := h.reg.Refusals()
	if unknown == 0 {
		t.Error("unsupported requests were not counted")
	}
}

// TestAnonymousContainerdPullSpeaksPlainHTTP is the contract pin: the
// reconciler's pull of an internal image uses containerd's default resolver
// with no credential, and that path is plain-HTTP-for-localhost by
// containerd's own default. If this breaks, every internal-registry deploy
// breaks with it.
func TestAnonymousContainerdPullSpeaksPlainHTTP(t *testing.T) {
	h := newHarness(t, allowShopWeb)
	manifest, dgst := h.pushImage(t, "shop/web", "v1", 7)

	resolver := docker.NewResolver(docker.ResolverOptions{})
	ref := h.addr + "/shop/web:v1"

	name, desc, err := resolver.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("containerd resolve of %s: %v", ref, err)
	}
	if desc.Digest.String() != dgst {
		t.Fatalf("resolved digest = %s, want %s", desc.Digest, dgst)
	}

	fetcher, err := resolver.Fetcher(context.Background(), name)
	if err != nil {
		t.Fatalf("fetcher: %v", err)
	}
	rc, err := fetcher.Fetch(context.Background(), desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	defer rc.Close() //nolint:errcheck // a test read
	body, err := io.ReadAll(rc)
	if err != nil || string(body) != string(manifest) {
		t.Fatalf("fetched manifest differs from the pushed one (%v)", err)
	}
}
