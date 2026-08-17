package provision

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBundle stages a bundle directory by hand, so a test can make its
// contents wrong on purpose.
func writeBundle(t *testing.T, meta string, artefacts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if meta != "" {
		if err := os.WriteFile(filepath.Join(dir, bundleMetaName), []byte(meta), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if len(artefacts) > 0 {
		artDir := filepath.Join(dir, bundleArtefact)
		if err := os.MkdirAll(artDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range artefacts {
			if err := os.WriteFile(filepath.Join(artDir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

const goodMeta = `{"kind":"kanea-bundle","kaneaVersion":"v9.9.9","arch":"amd64","components":[]}`

// The property the whole air-gapped design rests on: a bundle is not trusted
// more than the network. Its contents are checked against the hashes compiled
// into this binary, never against anything the bundle carries: a bundle that
// supplied its own hashes would be a bundle that authenticates itself.
func TestBundleContentsAreVerifiedAgainstTheEmbeddedHashes(t *testing.T) {
	dir := writeBundle(t, goodMeta, map[string]string{"tool": "not what is pinned"})

	bundle, err := OpenBundle(dir)
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	defer func() { _ = bundle.Close() }()

	payload := gzTar(t, map[string]string{"bin/tool": "the real thing"})
	h := hashOf(payload)
	c := &Component{
		Name: "tool", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/tool.tar.gz",
		Hashes: map[string]string{"amd64": h, "arm64": h},
		Files:  []File{{From: "bin/tool", To: "bin/tool", Mode: "0755"}},
	}

	inst := &Installer{Source: bundle, Layout: testLayout(t), Arch: "amd64"}
	if _, err := inst.Install(context.Background(), []*Component{c}); err == nil {
		t.Fatal("a bundle with tampered contents installed without complaint")
	}
}

func TestBundleInstallsVerifiedContents(t *testing.T) {
	payload := gzTar(t, map[string]string{"bin/tool": "the real thing"})
	dir := writeBundle(t, goodMeta, map[string]string{"tool": string(payload)})

	bundle, err := OpenBundle(dir)
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	defer func() { _ = bundle.Close() }()

	h := hashOf(payload)
	c := &Component{
		Name: "tool", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/tool.tar.gz",
		Hashes: map[string]string{"amd64": h, "arm64": h},
		Files:  []File{{From: "bin/tool", To: "bin/tool", Mode: "0755"}},
	}

	inst := &Installer{Source: bundle, Layout: testLayout(t), Arch: "amd64"}
	if _, err := inst.Install(context.Background(), []*Component{c}); err != nil {
		t.Fatalf("Install from a bundle: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(inst.Layout.Prefix, "bin/tool")); err != nil ||
		string(got) != "the real thing" {
		t.Errorf("installed %q, %v", got, err)
	}
}

// Selecting a bundle turns network fetching off entirely. An air-gapped
// install that silently reaches upstream for one component fails later, on a
// node nobody can reach.
func TestBundleSourceIsOffline(t *testing.T) {
	bundle, err := OpenBundle(writeBundle(t, goodMeta, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bundle.Close() }()

	if !bundle.Offline() {
		t.Error("a bundle source reports itself as online")
	}
	if NewHTTPSource().Offline() {
		t.Error("the HTTP source reports itself as offline")
	}
}

// The wrong bundle should say so, rather than producing six hash mismatches.
func TestBundleRefusesTheWrongArch(t *testing.T) {
	bundle, err := OpenBundle(writeBundle(t, goodMeta, map[string]string{"tool": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bundle.Close() }()

	c := &Component{Name: "tool", Version: "1", Kind: KindArchive}
	_, err = bundle.Open(context.Background(), c, "arm64")
	if err == nil {
		t.Fatal("an amd64 bundle served an arm64 install")
	}
	for _, want := range []string{"amd64", "arm64"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// A missing component is usually a bundle authored by a different Kanea
// version, and saying so beats "no such file or directory".
func TestBundleNamesTheAuthoringVersionForAMissingComponent(t *testing.T) {
	bundle, err := OpenBundle(writeBundle(t, goodMeta, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bundle.Close() }()

	c := &Component{Name: "containerd", Version: "2.3.3", Kind: KindArchive}
	_, err = bundle.Open(context.Background(), c, "amd64")
	if err == nil {
		t.Fatal("a bundle served a component it does not have")
	}
	if !strings.Contains(err.Error(), "v9.9.9") {
		t.Errorf("error %q does not name the authoring version", err)
	}
}

func TestOpenBundleRejectsSomethingElse(t *testing.T) {
	tests := []struct {
		name string
		meta string
		want string
	}{
		{"no metadata", "", "not a Kanea bundle"},
		{"wrong kind", `{"kind":"something-else"}`, "not a Kanea bundle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OpenBundle(writeBundle(t, tt.meta, nil))
			if err == nil {
				t.Fatal("OpenBundle accepted a directory that is not a bundle")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// A bundle tarball is an archive from outside this machine like any other, so
// it goes through the same traversal-safe extractor the components do.
func TestOpenBundleExtractsSafely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.tar.gz")
	body := buildTarGz(t, []tarEntry{{name: "../escaped", body: "x"}})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenBundle(path); err == nil {
		t.Fatal("OpenBundle unpacked an archive that escapes its destination")
	}
}

func TestCreateBundleRejectsAnUnsupportedArch(t *testing.T) {
	err := CreateBundle(context.Background(), MustLoad(), NewHTTPSource(), BundleOptions{
		Arch: "mips", Dest: t.TempDir(),
	})
	if err == nil {
		t.Fatal("CreateBundle accepted an architecture Kanea does not publish")
	}
}

// Authoring verifies too: a bundle built from a tampered download is a
// tampered bundle that a human then trusts because they carried it.
func TestCreateBundleVerifiesWhatItPacks(t *testing.T) {
	m := &Manifest{Schema: schemaVersion, Components: []Component{{
		Name: "tool", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/tool.tar.gz",
		Hashes: map[string]string{"amd64": hashOf([]byte("expected")), "arm64": hashOf([]byte("expected"))},
		Files:  []File{{From: "bin/tool", To: "bin/tool", Mode: "0755"}},
	}}}

	err := CreateBundle(context.Background(), m,
		&tarSource{payloads: map[string][]byte{"tool": []byte("tampered")}},
		BundleOptions{Arch: "amd64", Dest: t.TempDir(), KaneaVersion: "v1"})
	if err == nil {
		t.Fatal("CreateBundle packed an artefact that does not match its pin")
	}
}

func TestCreateBundleRoundTrips(t *testing.T) {
	payload := gzTar(t, map[string]string{"bin/tool": "payload"})
	h := hashOf(payload)
	m := &Manifest{Schema: schemaVersion, Components: []Component{{
		Name: "tool", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/tool.tar.gz",
		Hashes: map[string]string{"amd64": h, "arm64": h},
		Files:  []File{{From: "bin/tool", To: "bin/tool", Mode: "0755"}},
	}}}

	dest := t.TempDir()
	if err := CreateBundle(context.Background(), m,
		&tarSource{payloads: map[string][]byte{"tool": payload}},
		BundleOptions{Arch: "amd64", Dest: dest, KaneaVersion: "v1.2.3"}); err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}

	bundle, err := OpenBundle(dest)
	if err != nil {
		t.Fatalf("OpenBundle on what CreateBundle wrote: %v", err)
	}
	defer func() { _ = bundle.Close() }()

	if bundle.Arch() != "amd64" {
		t.Errorf("bundle arch is %q", bundle.Arch())
	}
	if bundle.KaneaVersion() != "v1.2.3" {
		t.Errorf("bundle version is %q", bundle.KaneaVersion())
	}

	inst := &Installer{Source: bundle, Layout: testLayout(t), Arch: "amd64"}
	if _, err := inst.Install(context.Background(), m.All()); err != nil {
		t.Fatalf("install from the round-tripped bundle: %v", err)
	}
}

// CreateBundle stages into a temporary file and renames, so an interrupted
// authoring run must not leave a .part behind that looks like an artefact.
func TestCreateBundleLeavesNoPartialFiles(t *testing.T) {
	payload := gzTar(t, map[string]string{"bin/tool": "payload"})
	h := hashOf(payload)
	m := &Manifest{Schema: schemaVersion, Components: []Component{{
		Name: "tool", Version: "1.0.0", Kind: KindArchive,
		URL:    "https://example.invalid/tool.tar.gz",
		Hashes: map[string]string{"amd64": h, "arm64": h},
		Files:  []File{{From: "bin/tool", To: "bin/tool", Mode: "0755"}},
	}}}

	dest := t.TempDir()
	if err := CreateBundle(context.Background(), m,
		&tarSource{payloads: map[string][]byte{"tool": payload}},
		BundleOptions{Arch: "amd64", Dest: dest, KaneaVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dest, bundleArtefact))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".part") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("bundle holds a staging leftover: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("bundle holds %d artefacts, want 1: %v", len(entries), entries)
	}
}
