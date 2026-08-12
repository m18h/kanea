package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// releaseArchive builds a tar.gz holding one `kanea` file, the shape
// release.yml publishes.
func releaseArchive(t *testing.T, contents string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "kanea", Mode: 0o755, Size: int64(len(contents)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeRelease serves the GitHub surface selfUpdate speaks: the /releases/latest
// redirect and the per-asset download URLs. No signature assets — the
// checksum-only posture, which is also the honest CI environment.
func fakeRelease(t *testing.T, tag string, assets map[string][]byte) *releaseSource {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(_ http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("/releases/download/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		body, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &releaseSource{base: server.URL, client: &http.Client{Timeout: 5 * time.Second}}
}

func TestLatestResolvesFromTheRedirect(t *testing.T) {
	source := fakeRelease(t, "v9.9.9", nil)
	tag, err := source.latest(context.Background())
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if tag != "v9.9.9" {
		t.Fatalf("tag = %q, want v9.9.9", tag)
	}
}

// A repository with no release redirects to /releases, and the literal
// "releases" must not compose into an archive name — the install script's
// lesson, kept in the binary.
func TestLatestRefusesANonReleaseRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases", http.StatusFound)
	})
	mux.HandleFunc("/releases", func(_ http.ResponseWriter, _ *http.Request) {})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	source := &releaseSource{base: server.URL, client: &http.Client{Timeout: 5 * time.Second}}

	if _, err := source.latest(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "no published release") {
		t.Fatalf("err = %v, want the no-release refusal", err)
	}
}

func TestChecksumForFindsTheAssetLine(t *testing.T) {
	sums := []byte("abc123  kanea_1.0.0_linux_amd64.tar.gz\ndef456  kanea_1.0.0_linux_arm64.tar.gz\n")
	got, err := checksumFor(sums, "kanea_1.0.0_linux_arm64.tar.gz")
	if err != nil || got != "def456" {
		t.Fatalf("checksumFor = %q, %v; want def456", got, err)
	}
	if _, err := checksumFor(sums, "kanea_1.0.0_linux_riscv64.tar.gz"); err == nil ||
		!strings.Contains(err.Error(), "no entry") {
		t.Fatalf("err = %v, want the missing-entry refusal", err)
	}
}

func TestSelfUpdateInstallsAVerifiedRelease(t *testing.T) {
	archive := releaseArchive(t, "the new binary")
	sum := sha256.Sum256(archive)
	asset := "kanea_9.9.9_linux_amd64.tar.gz"
	source := fakeRelease(t, "v9.9.9", map[string][]byte{
		asset:           archive,
		"checksums.txt": []byte(hex.EncodeToString(sum[:]) + "  " + asset + "\n"),
	})

	target := filepath.Join(t.TempDir(), "kanea")
	if err := os.WriteFile(target, []byte("the old binary"), 0o755); err != nil { // #nosec G306 — a binary
		t.Fatal(err)
	}

	notes, err := source.selfUpdate(context.Background(), "v9.9.9", asset, target)
	if err != nil {
		t.Fatalf("selfUpdate: %v", err)
	}
	got, err := os.ReadFile(target) // #nosec G304 — a test path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the new binary" {
		t.Fatalf("target holds %q, want the new binary", got)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "installed v9.9.9") {
		t.Errorf("notes = %q, want the install note", joined)
	}
	// The signature posture is always said out loud, whichever branch ran —
	// cosign absent and signature absent both read as "not fully verified".
	if !strings.Contains(joined, "signature") && !strings.Contains(joined, "cosign") {
		t.Errorf("notes = %q, want the signature posture stated", joined)
	}
}

// The checksum gate is not optional and there is no flag to skip it.
func TestSelfUpdateRefusesACorruptArchive(t *testing.T) {
	archive := releaseArchive(t, "the new binary")
	asset := "kanea_9.9.9_linux_amd64.tar.gz"
	source := fakeRelease(t, "v9.9.9", map[string][]byte{
		asset:           archive,
		"checksums.txt": []byte(strings.Repeat("0", 64) + "  " + asset + "\n"),
	})

	target := filepath.Join(t.TempDir(), "kanea")
	if err := os.WriteFile(target, []byte("the old binary"), 0o755); err != nil { // #nosec G306 — a binary
		t.Fatal(err)
	}

	_, err := source.selfUpdate(context.Background(), "v9.9.9", asset, target)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want the checksum refusal", err)
	}
	got, _ := os.ReadFile(target) // #nosec G304 — a test path
	if string(got) != "the old binary" {
		t.Fatal("a refused archive still replaced the binary")
	}
}

func TestSelfUpdateRefusesAReleaseMissingItsChecksums(t *testing.T) {
	asset := "kanea_9.9.9_linux_amd64.tar.gz"
	source := fakeRelease(t, "v9.9.9", map[string][]byte{
		asset: releaseArchive(t, "x"),
		// no checksums.txt
	})
	target := filepath.Join(t.TempDir(), "kanea")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil { // #nosec G306 — a binary
		t.Fatal(err)
	}
	if _, err := source.selfUpdate(context.Background(), "v9.9.9", asset, target); err == nil {
		t.Fatal("a release without checksums.txt was installed")
	}
}

func TestExtractBinaryIgnoresStrayEntriesAndFindsKanea(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct{ name, body string }{
		{"README", "not it"},
		{"./kanea", "it"},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: entry.name, Mode: 0o755, Size: int64(len(entry.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	if err := extractBinary(archive, dest); err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "it" { // #nosec G304 — a test path
		t.Fatalf("extracted %q, want the kanea entry", got)
	}
}

func TestExtractBinaryRefusesAnArchiveWithoutKanea(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "something-else", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("xx")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractBinary(archive, filepath.Join(dir, "out")); err == nil ||
		!strings.Contains(err.Error(), "no kanea binary") {
		t.Fatalf("err = %v, want the no-binary refusal", err)
	}
}

func TestAssetNameMatchesTheReleaseContract(t *testing.T) {
	// The naming is a contract with release.yml (and install.sh); this test
	// is the tripwire for renaming one side without the other.
	name, err := assetName("v1.2.3")
	if err != nil {
		// Not linux: the refusal must say so rather than compose a URL that
		// 404s. (CI is linux; a dev laptop may not be.)
		if !strings.Contains(err.Error(), "linux") {
			t.Fatalf("err = %v, want the linux-only refusal", err)
		}
		return
	}
	if !strings.HasPrefix(name, "kanea_1.2.3_linux_") || !strings.HasSuffix(name, ".tar.gz") {
		t.Fatalf("assetName = %q, want kanea_1.2.3_linux_<arch>.tar.gz", name)
	}
}

func TestReleaseTagGrammar(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.12.0":         true,
		"v10.2.33":        true,
		"releases":        false,
		"0.12.0":          false,
		"v0.12":           false,
		"v0.12.0/../evil": false,
	} {
		if got := releaseTag.MatchString(tag); got != want {
			t.Errorf("releaseTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

func TestInstallOverIsAtomicAcrossFilesystemsByCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged")
	target := filepath.Join(dir, "kanea")
	if err := os.WriteFile(src, []byte("new"), 0o755); err != nil { // #nosec G306 — a binary
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil { // #nosec G306 — a binary
		t.Fatal(err)
	}
	if err := installOver(src, target); err != nil {
		t.Fatalf("installOver: %v", err)
	}
	got, err := os.ReadFile(target) // #nosec G304 — a test path
	if err != nil || string(got) != "new" {
		t.Fatalf("target = %q, %v; want the new binary", got, err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("target mode = %v, want 0755", fi.Mode())
	}
	if _, err := os.Stat(target + ".next"); !os.IsNotExist(err) {
		t.Fatal("the staging file was left behind")
	}
}

func TestSelfUpdateBaseURLComposition(t *testing.T) {
	// KANEA_REPO parity with the install script: a fork upgrades from itself.
	t.Setenv("KANEA_REPO", "someone/fork")
	source := newReleaseSource()
	if want := "https://github.com/someone/fork"; source.base != want {
		t.Fatalf("base = %q, want %q", source.base, want)
	}
}
