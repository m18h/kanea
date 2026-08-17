package provision

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// tarSource serves a synthesised archive whose hash it computes, so a test can
// exercise the whole install without a network or the real 50 MiB tarballs.
type tarSource struct {
	payloads map[string][]byte
	offline  bool
}

func (s *tarSource) Open(_ context.Context, c *Component, _ string) (io.ReadCloser, error) {
	body, ok := s.payloads[c.Name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}
func (s *tarSource) Describe() string { return "a synthesised archive" }
func (s *tarSource) Offline() bool    { return s.offline }

func gzTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testInstall builds an installer over one synthetic archive component.
func testInstall(t *testing.T) (*Installer, *Component, []byte) {
	t.Helper()
	payload := gzTar(t, map[string]string{"bin/tool": "the binary"})
	h := hashOf(payload)
	c := &Component{
		Name: "tool", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/tool.tar.gz",
		Hashes: map[string]string{"amd64": h, "arm64": h},
		Files:  []File{{From: "bin/tool", To: "bin/tool", Mode: "0755"}},
	}
	l := testLayout(t)
	return &Installer{
		Source: &tarSource{payloads: map[string][]byte{"tool": payload}},
		Layout: l,
		Arch:   "amd64",
	}, c, payload
}

func TestInstallPlacesAndRecords(t *testing.T) {
	inst, c, _ := testInstall(t)

	results, err := inst.Install(context.Background(), []*Component{c})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if results[0].Action != ActionInstalled {
		t.Errorf("action was %q, want %q", results[0].Action, ActionInstalled)
	}
	got, err := os.ReadFile(filepath.Join(inst.Layout.Prefix, "bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the binary" {
		t.Errorf("installed %q", got)
	}
	if version, _, ok := inst.Installed("tool"); !ok || version != "1.0.0" {
		t.Errorf("receipt says %q, %v", version, ok)
	}
}

// A re-run must be a no-op: `kanea install` is re-runnable by design, and an
// installer that re-downloads six components every time is one people avoid.
func TestInstallIsIdempotent(t *testing.T) {
	inst, c, _ := testInstall(t)
	if _, err := inst.Install(context.Background(), []*Component{c}); err != nil {
		t.Fatal(err)
	}
	results, err := inst.Install(context.Background(), []*Component{c})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Action != ActionCurrent {
		t.Errorf("second install reported %q, want %q", results[0].Action, ActionCurrent)
	}
}

func TestForceReinstalls(t *testing.T) {
	inst, c, _ := testInstall(t)
	if _, err := inst.Install(context.Background(), []*Component{c}); err != nil {
		t.Fatal(err)
	}
	inst.Force = true
	results, err := inst.Install(context.Background(), []*Component{c})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Action != ActionInstalled {
		t.Errorf("--force reported %q, want %q", results[0].Action, ActionInstalled)
	}
}

// A receipt is a cache of a fact the filesystem holds. If an operator wipes
// the prefix, the installer must notice rather than skip the work it exists
// to do.
func TestInstallNoticesAWipedPrefix(t *testing.T) {
	inst, c, _ := testInstall(t)
	if _, err := inst.Install(context.Background(), []*Component{c}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(inst.Layout.Prefix, "bin/tool")); err != nil {
		t.Fatal(err)
	}
	results, err := inst.Install(context.Background(), []*Component{c})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Action != ActionInstalled {
		t.Errorf("a missing binary with a receipt present reported %q; it must reinstall", results[0].Action)
	}
}

// An upstream that re-tags a release keeps the version and changes the bytes.
// Comparing the pin rather than the version is what catches it.
func TestInstallReinstallsWhenThePinChanges(t *testing.T) {
	inst, c, _ := testInstall(t)
	if _, err := inst.Install(context.Background(), []*Component{c}); err != nil {
		t.Fatal(err)
	}

	replacement := gzTar(t, map[string]string{"bin/tool": "different bytes, same version"})
	h := hashOf(replacement)
	c.Hashes = map[string]string{"amd64": h, "arm64": h}
	inst.Source = &tarSource{payloads: map[string][]byte{"tool": replacement}}

	results, err := inst.Install(context.Background(), []*Component{c})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Action != ActionInstalled {
		t.Errorf("a re-pinned artefact reported %q; it must reinstall", results[0].Action)
	}
}

// --dry-run still verifies: "would this install work" is mostly "is the
// artefact reachable and does it match its pin".
func TestDryRunVerifiesButWritesNothing(t *testing.T) {
	inst, c, _ := testInstall(t)
	inst.DryRun = true

	results, err := inst.Install(context.Background(), []*Component{c})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if results[0].Action != ActionPlanned {
		t.Errorf("action was %q, want %q", results[0].Action, ActionPlanned)
	}
	if _, err := os.Stat(filepath.Join(inst.Layout.Prefix, "bin/tool")); err == nil {
		t.Error("a dry run installed the binary")
	}
	if _, _, ok := inst.Installed("tool"); ok {
		t.Error("a dry run wrote a receipt")
	}
}

func TestDryRunFailsOnAHashMismatch(t *testing.T) {
	inst, c, _ := testInstall(t)
	inst.DryRun = true
	inst.Source = &tarSource{payloads: map[string][]byte{"tool": []byte("not what is pinned")}}

	if _, err := inst.Install(context.Background(), []*Component{c}); err == nil {
		t.Fatal("dry run passed an artefact that does not match its pin")
	}
}

// An image component with no containerd yet is a skip with a reason, not a
// failure: the install bootstraps in one direction.
func TestImageComponentSkipsWithoutAPuller(t *testing.T) {
	inst, _, _ := testInstall(t)
	img := &Component{
		Name: "buildkit", Version: "0.32.0", Kind: KindImage,
		Image: "docker.io/moby/buildkit", Tag: "v0.32.0-rootless",
		Digest: "sha256:" + hashOf([]byte("x")),
		Files:  []File{{From: "usr/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
	}

	results, err := inst.Install(context.Background(), []*Component{img})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if results[0].Action != ActionSkipped {
		t.Errorf("action was %q, want %q", results[0].Action, ActionSkipped)
	}
	if results[0].Reason == "" {
		t.Error("a skip with no reason tells the operator nothing")
	}
}

func TestInstallRejectsAnUnsupportedArch(t *testing.T) {
	inst, c, _ := testInstall(t)
	inst.Arch = "mips"
	if _, err := inst.Install(context.Background(), []*Component{c}); err == nil {
		t.Fatal("Install accepted an architecture Kanea does not publish")
	}
}

// A failed component stops the run: the rest depend on it in one direction, so
// carrying on produces a longer list of failures that all say the same thing.
func TestInstallStopsAtTheFirstFailure(t *testing.T) {
	inst, c, _ := testInstall(t)
	broken := &Component{
		Name: "broken", Version: "1", Kind: KindArchive,
		URL:    "https://example.invalid/broken.tar.gz",
		Hashes: map[string]string{"amd64": hashOf([]byte("expected")), "arm64": hashOf([]byte("expected"))},
		Files:  []File{{From: "bin/x", To: "bin/x", Mode: "0755"}},
	}

	results, err := inst.Install(context.Background(), []*Component{broken, c})
	if err == nil {
		t.Fatal("Install continued past a component it could not fetch")
	}
	if len(results) != 1 {
		t.Errorf("Install produced %d results after a failure, want 1", len(results))
	}
}
