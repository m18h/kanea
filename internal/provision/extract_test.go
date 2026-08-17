package provision

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// tarEntry is one member to synthesise.
type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
	mode     int64
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		flag := e.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o755
		}
		hdr := &tar.Header{
			Name: e.name, Typeflag: flag, Linkname: e.linkname,
			Mode: mode, Size: int64(len(e.body)),
		}
		if flag != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if flag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %s: %v", e.name, err)
			}
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

// This is the test that matters. Every path in an archive comes from somebody
// else's build and is used to write a file that runs as root: the same shape
// as GO-2026-5597, the go-billy traversal AGENTS.md pins a floor for.
func TestExtractRefusesEscapingMembers(t *testing.T) {
	tests := []struct {
		name  string
		entry tarEntry
	}{
		{"parent traversal", tarEntry{name: "../escaped", body: "x"}},
		{"deep traversal", tarEntry{name: "bin/../../escaped", body: "x"}},
		{"absolute path", tarEntry{name: "/etc/cron.d/escaped", body: "x"}},
		{"dot-slash traversal", tarEntry{name: "./../escaped", body: "x"}},
		{"bare parent", tarEntry{name: "..", body: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := t.TempDir()
			archive := buildTarGz(t, []tarEntry{tt.entry})

			err := extractTarGz(bytes.NewReader(archive), extractOptions{
				dest: dest, defaultMode: 0o755,
			})
			if err == nil {
				t.Fatalf("extracted %q without complaint", tt.entry.name)
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("error was %v, want ErrUnsafePath", err)
			}
			// The point is not the error, it is that nothing was written.
			outside := filepath.Join(filepath.Dir(dest), "escaped")
			if _, statErr := os.Stat(outside); statErr == nil {
				t.Fatalf("%s was created outside the destination", outside)
			}
		})
	}
}

// A symlink is how an extractor writes through a path it already checked. A
// tarball of binaries has no reason to carry one, so they are dropped rather
// than resolved.
func TestExtractIgnoresNonRegularMembers(t *testing.T) {
	dest := t.TempDir()
	archive := buildTarGz(t, []tarEntry{
		{name: "evil", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "hard", typeflag: tar.TypeLink, linkname: "bin/containerd"},
		{name: "bin/real", body: "payload"},
	})

	if err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest: dest, defaultMode: 0o755,
	}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "evil")); err == nil {
		t.Error("a symlink member was extracted")
	}
	if _, err := os.Lstat(filepath.Join(dest, "hard")); err == nil {
		t.Error("a hard-link member was extracted")
	}
	if got, err := os.ReadFile(filepath.Join(dest, "bin/real")); err != nil || string(got) != "payload" {
		t.Errorf("the regular member did not survive: %q, %v", got, err)
	}
}

// A destination that is itself a symlink is ordinary (/usr/local is one on
// some distributions) so the check has to resolve it rather than refuse it.
func TestExtractFollowsASymlinkedDestination(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	archive := buildTarGz(t, []tarEntry{{name: "bin/tool", body: "payload"}})
	if err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest: link, defaultMode: 0o755,
	}); err != nil {
		t.Fatalf("extract into a symlinked destination: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "bin/tool")); err != nil {
		t.Errorf("file did not land in the resolved destination: %v", err)
	}
}

func TestExtractSelectsNamedFiles(t *testing.T) {
	dest := t.TempDir()
	archive := buildTarGz(t, []tarEntry{
		{name: "bin/containerd", body: "daemon"},
		{name: "bin/ctr", body: "cli"},
		{name: "bin/unwanted", body: "no"},
	})

	err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest: dest,
		files: []File{
			{From: "bin/containerd", To: "bin/containerd", Mode: "0755"},
			{From: "bin/ctr", To: "bin/ctr", Mode: "0755"},
		},
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"bin/containerd", "bin/ctr"} {
		info, err := os.Stat(filepath.Join(dest, want))
		if err != nil {
			t.Errorf("%s: %v", want, err)
			continue
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("%s is mode %04o, want 0755", want, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "bin/unwanted")); err == nil {
		t.Error("an unselected member was extracted")
	}
}

// Upstream archives move binaries between releases, so a second location is
// tried rather than failing the install.
func TestExtractFallsBackToAltPath(t *testing.T) {
	dest := t.TempDir()
	archive := buildTarGz(t, []tarEntry{{name: "usr/bin/tool", body: "binary"}})

	err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest:  dest,
		files: []File{{From: "opt/bin/tool", Alt: "usr/bin/tool", To: "bin/tool", Mode: "0755"}},
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "bin/tool")); err != nil || string(got) != "binary" {
		t.Errorf("alt path was not used: %q, %v", got, err)
	}
}

// A missing binary has to say which of the two names is wrong.
func TestExtractReportsAMissingSelection(t *testing.T) {
	dest := t.TempDir()
	archive := buildTarGz(t, []tarEntry{{name: "bin/other", body: "x"}})

	err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest:  dest,
		files: []File{{From: "usr/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
	})
	if err == nil {
		t.Fatal("extract accepted an archive missing a selected file")
	}
	for _, want := range []string{"buildctl", "usr/bin/buildctl"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestExtractFlattensADirectoryCapture(t *testing.T) {
	dest := t.TempDir()
	archive := buildTarGz(t, []tarEntry{
		{name: "./bridge", body: "a"},
		{name: "./host-local", body: "b"},
		{name: "./portmap", body: "c"},
	})

	err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest:  dest,
		files: []File{{From: ".", To: "cni/bin", Mode: "0755"}},
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"bridge", "host-local", "portmap"} {
		if _, err := os.Stat(filepath.Join(dest, "cni/bin", want)); err != nil {
			t.Errorf("%s: %v", want, err)
		}
	}
}

// Upstream archives carry a LICENSE and a README next to the binaries, and a
// bin directory where two entries are documents installed 0755 invites exactly
// one question from every operator who looks.
func TestExtractHonoursExclusions(t *testing.T) {
	dest := t.TempDir()
	archive := buildTarGz(t, []tarEntry{
		{name: "./bridge", body: "a"},
		{name: "./LICENSE", body: "Apache"},
		{name: "./README.md", body: "# plugins"},
	})

	err := extractTarGz(bytes.NewReader(archive), extractOptions{
		dest:  dest,
		files: []File{{From: ".", To: "cni/bin", Mode: "0755", Exclude: []string{"LICENSE", "README.md"}}},
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "cni/bin/bridge")); err != nil {
		t.Errorf("the plugin was not installed: %v", err)
	}
	for _, unwanted := range []string{"LICENSE", "README.md"} {
		if _, err := os.Stat(filepath.Join(dest, "cni/bin", unwanted)); err == nil {
			t.Errorf("%s was installed into a bin directory", unwanted)
		}
	}
}

func TestResolveUnderRejectsAPrefixSibling(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "kanea")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// "kanea-evil" shares a string prefix with "kanea" but is not inside it:
	// the case strings.HasPrefix gets wrong.
	if _, err := resolveUnder(dest, "../kanea-evil/x"); err == nil {
		t.Fatal("resolveUnder accepted a prefix-sharing sibling directory")
	}
}
