package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// testSource hands out fixed bytes, standing in for either real Source.
type testSource struct {
	body    string
	err     error
	offline bool
}

func (t *testSource) Open(context.Context, *Component, string) (io.ReadCloser, error) {
	if t.err != nil {
		return nil, t.err
	}
	return io.NopCloser(strings.NewReader(t.body)), nil
}
func (t *testSource) Describe() string { return "the test source" }
func (t *testSource) Offline() bool    { return t.offline }

func archiveComponent(body string) *Component {
	return &Component{
		Name: "testcomp", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/x.tar.gz",
		Hashes: map[string]string{"amd64": sha256Hex(body), "arm64": sha256Hex(body)},
		Files:  []File{{From: "bin/x", To: "bin/x", Mode: "0755"}},
	}
}

func TestStageVerifiesAGoodArtefact(t *testing.T) {
	body := "the real containerd tarball"
	c := archiveComponent(body)

	f, err := Stage(context.Background(), &testSource{body: body}, c, "amd64", t.TempDir())
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("staged %q, want %q", got, body)
	}
}

// The property that matters: a mismatched artefact leaves nothing behind. A
// half-written or tampered `containerd` must never exist at a path anything
// would execute.
func TestStageLeavesNothingOnAHashMismatch(t *testing.T) {
	c := archiveComponent("what the manifest pins")
	tmpDir := t.TempDir()

	_, err := Stage(context.Background(), &testSource{body: "what the server sent"}, c, "amd64", tmpDir)
	if err == nil {
		t.Fatal("Stage accepted an artefact that does not match the pinned hash")
	}
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("error was %v, want ErrHashMismatch", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("staging directory still holds %d file(s): %v", len(entries), entries)
	}
}

// "hash mismatch" on an empty body is a proxy serving an error page, and the
// message should be enough to work that out without a packet capture.
func TestStageErrorNamesTheSourceAndSize(t *testing.T) {
	c := archiveComponent("expected")
	_, err := Stage(context.Background(), &testSource{body: ""}, c, "amd64", t.TempDir())
	if err == nil {
		t.Fatal("Stage accepted an empty body")
	}
	for _, want := range []string{"the test source", "0 bytes", "testcomp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestVerifiedReaderCatchesTruncation(t *testing.T) {
	full := "0123456789"
	v := NewVerifiedReader(strings.NewReader(full[:5]), sha256Hex(full))
	if _, err := io.ReadAll(v); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("truncated read returned %v, want ErrHashMismatch", err)
	}
}

// A caller that stops before EOF — an extractor that has what it wants — must
// still be able to prove the artefact was whole.
func TestVerifiedReaderRequiresAnExplicitVerifyOnAShortRead(t *testing.T) {
	full := "0123456789"
	v := NewVerifiedReader(strings.NewReader(full), sha256Hex(full))
	buf := make([]byte, 4)
	if _, err := v.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Verify after a partial read returned %v, want ErrHashMismatch", err)
	}
}

func TestHTTPSourceRejectsANonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	c := archiveComponent("x")
	c.URL = srv.URL + "/x.tar.gz"

	src := NewHTTPSource()
	if _, err := src.Open(context.Background(), c, "amd64"); err == nil {
		t.Fatal("Open accepted a 404")
	}
}

// A redirect chain that leaves HTTPS leaks which runtime version this node is
// about to install, even though the hash still protects the bytes.
func TestHTTPSourceRefusesAPlaintextRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer plain.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x.tar.gz", http.StatusFound)
	}))
	defer redirector.Close()

	c := archiveComponent("payload")
	c.URL = redirector.URL + "/x.tar.gz"

	src := NewHTTPSource()
	// The test server's certificate is not trusted; accept it so the redirect
	// policy is what the test actually exercises.
	src.client.Transport = redirector.Client().Transport

	_, err := src.Open(context.Background(), c, "amd64")
	if err == nil {
		t.Fatal("Open followed a redirect off https")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error %q does not explain the refusal", err)
	}
}

func TestHTTPSourceRefusesImageComponents(t *testing.T) {
	c := &Component{Name: "cilium", Kind: KindImage, Image: "quay.io/cilium/cilium", Digest: "sha256:" + strings.Repeat("a", 64)}
	if _, err := NewHTTPSource().Open(context.Background(), c, "amd64"); err == nil {
		t.Fatal("Open accepted an image component")
	}
}

func TestWriteFileAtomicSetsModeAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "tool")

	if err := writeFileAtomic(path, strings.NewReader("payload"), 0o755); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode is %04o, want 0755", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want just the file: %v", len(entries), entries)
	}
}
