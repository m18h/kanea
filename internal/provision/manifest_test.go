package provision

import (
	"strings"
	"testing"
)

func TestLoadEmbeddedManifest(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("the embedded manifest has no components")
	}
}

// The manifest is the §15.4 version matrix, so a component that covers one
// architecture is an install that fails on the other at download time — on a
// node, months from now — rather than here.
func TestEveryComponentCoversEveryArch(t *testing.T) {
	m := MustLoad()
	for _, c := range m.All() {
		if c.Kind == KindImage {
			// One index digest covers both; containerd resolves the per-arch
			// manifest itself.
			continue
		}
		for _, arch := range Arches {
			h, err := c.Hash(arch)
			if err != nil {
				t.Errorf("%s: %v", c.Name, err)
				continue
			}
			if len(h) != 64 {
				t.Errorf("%s/%s: hash is %d chars, want 64", c.Name, arch, len(h))
			}
			if url := c.ArtefactURL(arch); strings.Contains(url, "{{") {
				t.Errorf("%s/%s: url still has an unexpanded template: %s", c.Name, arch, url)
			}
		}
	}
}

func TestArtefactURLsAreHTTPS(t *testing.T) {
	for _, c := range MustLoad().All() {
		if c.Kind == KindImage {
			continue
		}
		for _, arch := range Arches {
			if url := c.ArtefactURL(arch); !strings.HasPrefix(url, "https://") {
				t.Errorf("%s/%s: %s is not https", c.Name, arch, url)
			}
		}
	}
}

// A tag is a mutable pointer to a root filesystem. Pinning by digest is the
// only reason an image install is reproducible at all.
func TestImagesArePinnedByDigest(t *testing.T) {
	for _, c := range MustLoad().All() {
		if c.Kind != KindImage {
			continue
		}
		if !strings.HasPrefix(c.Digest, "sha256:") {
			t.Errorf("%s: digest %q is not a sha-256 digest", c.Name, c.Digest)
		}
		if ref := c.Ref(); !strings.Contains(ref, "@sha256:") {
			t.Errorf("%s: pull ref %q is not digest-pinned", c.Name, ref)
		}
	}
}

// Install order is load-bearing (PRD §5.2.12): containerd has to be running
// before the image components can be pulled through it. Select must therefore
// ignore the order it is asked for.
func TestSelectPreservesInstallOrder(t *testing.T) {
	m := MustLoad()
	got, err := m.Select([]string{"buildkit", "containerd"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Select returned %d components, want 2", len(got))
	}
	if got[0].Name != "containerd" {
		t.Errorf("Select put %q first; containerd must be installed before any image is pulled through it", got[0].Name)
	}
}

func TestSelectRejectsUnknown(t *testing.T) {
	if _, err := MustLoad().Select([]string{"kubernetes"}); err == nil {
		t.Fatal("Select accepted a component that is not in the manifest")
	}
}

// containerd must come before the image components in the manifest itself,
// since manifest order *is* install order.
func TestContainerdIsInstalledFirst(t *testing.T) {
	names := MustLoad().Names()
	if names[0] != "containerd" {
		t.Fatalf("first component is %q; containerd bootstraps the rest and must be first", names[0])
	}
	for i, c := range MustLoad().All() {
		if c.Kind == KindImage && i == 0 {
			t.Fatal("an image component cannot be first: nothing can pull it yet")
		}
	}
}

func TestFileModeParsing(t *testing.T) {
	tests := []struct {
		mode    string
		want    uint32
		wantErr bool
	}{
		{"0755", 0o755, false},
		{"0644", 0o644, false},
		{"", 0o644, false},
		{"nonsense", 0, true},
		{"77777", 0, true},
	}
	for _, tt := range tests {
		got, err := File{Mode: tt.mode}.FileMode()
		if tt.wantErr {
			if err == nil {
				t.Errorf("FileMode(%q): want an error", tt.mode)
			}
			continue
		}
		if err != nil {
			t.Errorf("FileMode(%q): %v", tt.mode, err)
			continue
		}
		if got != tt.want {
			t.Errorf("FileMode(%q) = %o, want %o", tt.mode, got, tt.want)
		}
	}
}

func TestValidateRejectsBadManifests(t *testing.T) {
	tests := []struct {
		name string
		m    Manifest
		want string
	}{
		{
			name: "no components",
			m:    Manifest{Schema: schemaVersion},
			want: "empty",
		},
		{
			name: "plaintext url",
			m: Manifest{Schema: schemaVersion, Components: []Component{{
				Name: "x", Version: "1", Kind: KindArchive,
				URL:    "http://example.invalid/x.tar.gz",
				Hashes: map[string]string{"amd64": strings.Repeat("a", 64), "arm64": strings.Repeat("b", 64)},
				Files:  []File{{From: "x", To: "bin/x", Mode: "0755"}},
			}}},
			want: "https",
		},
		{
			name: "image pinned by tag only",
			m: Manifest{Schema: schemaVersion, Components: []Component{{
				Name: "x", Version: "1", Kind: KindImage,
				Image: "example.invalid/x", Tag: "v1",
				Files: []File{{From: "usr/bin/x", To: "bin/x", Mode: "0755"}},
			}}},
			want: "digest",
		},
		{
			name: "uppercase hash",
			m: Manifest{Schema: schemaVersion, Components: []Component{{
				Name: "x", Version: "1", Kind: KindArchive,
				URL:    "https://example.invalid/x.tar.gz",
				Hashes: map[string]string{"amd64": strings.ToUpper(strings.Repeat("a", 64)), "arm64": strings.Repeat("b", 64)},
				Files:  []File{{From: "x", To: "bin/x", Mode: "0755"}},
			}}},
			want: "sha-256",
		},
		{
			name: "missing arch",
			m: Manifest{Schema: schemaVersion, Components: []Component{{
				Name: "x", Version: "1", Kind: KindArchive,
				URL:    "https://example.invalid/x.tar.gz",
				Hashes: map[string]string{"amd64": strings.Repeat("a", 64)},
				Files:  []File{{From: "x", To: "bin/x", Mode: "0755"}},
			}}},
			want: "arm64",
		},
		{
			name: "installs nothing",
			m: Manifest{Schema: schemaVersion, Components: []Component{{
				Name: "x", Version: "1", Kind: KindArchive,
				URL:    "https://example.invalid/x.tar.gz",
				Hashes: map[string]string{"amd64": strings.Repeat("a", 64), "arm64": strings.Repeat("b", 64)},
			}}},
			want: "installs no files",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.validate()
			if err == nil {
				t.Fatalf("validate accepted a manifest that %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}
