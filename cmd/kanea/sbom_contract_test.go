package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release publishes these six archives (release.yml's build and bundle
// steps). The version is arbitrary; the shapes are the contract.
func releaseArchives(version string) []string {
	return []string{
		fmt.Sprintf("kanea_%s_linux_amd64.tar.gz", version),
		fmt.Sprintf("kanea_%s_linux_arm64.tar.gz", version),
		fmt.Sprintf("kanea_%s_darwin_amd64.tar.gz", version),
		fmt.Sprintf("kanea_%s_darwin_arm64.tar.gz", version),
		fmt.Sprintf("kanea_%s_linux_amd64_bundle.tar.gz", version),
		fmt.Sprintf("kanea_%s_linux_arm64_bundle.tar.gz", version),
	}
}

// sbomNames runs the real scripts/sbom.sh in its names-only mode against a dist
// directory holding the given archives, and returns the base names it would
// write. Driving the script rather than restating its rules is the point: a
// naming change there has to fail here.
func sbomNames(t *testing.T, version string, archives []string) []string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dist := t.TempDir()
	for _, a := range archives {
		if err := os.WriteFile(filepath.Join(dist, a), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("bash", "../../scripts/sbom.sh", "--dry-run", dist, "v"+version).CombinedOutput()
	if err != nil {
		t.Fatalf("sbom.sh --dry-run: %v\n%s", err, out)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, filepath.Base(line))
		}
	}
	if len(names) == 0 {
		t.Fatalf("sbom.sh produced no names:\n%s", out)
	}
	return names
}

// Exactly one checksum line ends in any given archive name.
//
// scripts/install.sh selects its line with `grep " <archive>$"` and pipes the
// result to `sha256sum -c -`, so a second line ending in the same name hands it
// a file the installer never downloaded and fails the installation. The leading
// space in that pattern is what bounds the hazard: a merely similar name
// ("sbom-<archive>") cannot match, so what this guards against is an SBOM
// *duplicating* an archive's name — writing the document over the archive's own
// path, or naming it identically alongside.
func TestSBOMNamesCannotCollideWithArchiveNames(t *testing.T) {
	const version = "1.2.3"
	archives := releaseArchives(version)
	names := sbomNames(t, version, archives)

	checksums := buildChecksums(archives, names)
	for _, archive := range archives {
		// The exact expression install.sh uses.
		re := regexp.MustCompile(`(?m) ` + regexp.QuoteMeta(archive) + `$`)
		if n := len(re.FindAllString(checksums, -1)); n != 1 {
			t.Errorf("install.sh's `grep \" %s$\"` matches %d lines, want exactly 1.\n"+
				"Two lines ending in one archive name break checksum verification "+
				"for every installation of the release.\nchecksums.txt:\n%s",
				archive, n, checksums)
		}
	}
}

// Every published name is one whitespace-free field.
//
// scripts/update-formula.sh reads the checksum file with awk '$2 == name', and
// checksumFor (selfupdate.go) requires exactly two fields per line. A name
// containing a space would silently break both.
func TestSBOMNamesAreSingleFields(t *testing.T) {
	const version = "1.2.3"
	names := sbomNames(t, version, releaseArchives(version))
	for _, name := range names {
		if len(strings.Fields(name)) != 1 {
			t.Errorf("SBOM name %q is not a single field; awk '$2 == name' and "+
				"checksumFor both read it as two", name)
		}
		if !strings.HasSuffix(name, ".spdx.json") {
			t.Errorf("SBOM name %q does not end in .spdx.json", name)
		}
	}
}

// The offline bundles are deliberately not catalogued (see scripts/sbom.sh):
// syft does not descend into the nested archives a bundle carries, so it would
// emit a near-empty document reading as "this bundle contains nothing". What a
// bundle carries is published by internal/provision/components.json instead.
// This test states that decision so a future change to it is a deliberate one.
func TestBundlesAreNotCatalogued(t *testing.T) {
	const version = "1.2.3"
	archives := releaseArchives(version)
	names := sbomNames(t, version, archives)

	joined := strings.Join(names, " ")
	for _, archive := range archives {
		want := strings.HasSuffix(archive, "_bundle.tar.gz")
		got := strings.Contains(joined, archive+".spdx.json")
		if want && got {
			t.Errorf("bundle %s was catalogued; syft cannot see inside it", archive)
		}
		if !want && !got {
			t.Errorf("archive %s has no SBOM; every published binary needs one", archive)
		}
	}
}

// The production parser must still find an archive's hash in a checksums.txt
// that carries SBOM lines. This drives checksumFor itself rather than a
// restatement of it, so `kanea upgrade` cannot be broken by the SBOM rows
// without this failing.
func TestChecksumForIgnoresSBOMLines(t *testing.T) {
	const version = "1.2.3"
	archives := releaseArchives(version)
	names := sbomNames(t, version, archives)
	checksums := []byte(buildChecksums(archives, names))

	for _, archive := range archives {
		got, err := checksumFor(checksums, archive)
		if err != nil {
			t.Errorf("checksumFor(%s) = %v, want the archive's hash", archive, err)
			continue
		}
		if got != hashFor(archive) {
			t.Errorf("checksumFor(%s) = %s, want %s — it matched the wrong line",
				archive, got, hashFor(archive))
		}
	}
	// And a document itself is addressable, which is what makes the signature
	// over checksums.txt extend to the SBOMs.
	for _, name := range names {
		if _, err := checksumFor(checksums, name); err != nil {
			t.Errorf("checksumFor(%s) = %v, want the SBOM's hash", name, err)
		}
	}
}

// The Go side of the naming contract agrees with the shell side: the archive
// `kanea upgrade` composes is one the release actually publishes, and so is
// covered by an SBOM.
func TestUpgradeTargetIsCatalogued(t *testing.T) {
	const version = "1.2.3"
	name, err := assetName("v" + version)
	if err != nil {
		t.Skipf("not a release platform: %v", err)
	}
	names := sbomNames(t, version, releaseArchives(version))
	if !strings.Contains(strings.Join(names, " "), name+".spdx.json") {
		t.Errorf("assetName gives %q, which scripts/sbom.sh does not catalogue; "+
			"the two halves of the naming contract have drifted", name)
	}
}

// hashFor is a stable stand-in for a real digest: distinct per name, so a test
// can tell which line a parser matched.
func hashFor(name string) string {
	h := make([]byte, 0, 64)
	for i := 0; i < 64; i++ {
		h = append(h, "0123456789abcdef"[(int(name[i%len(name)])+i)%16])
	}
	return string(h)
}

// buildChecksums renders the sha256sum output release.yml writes: two spaces
// between the hash and the name, archives before documents, exactly as the
// widened glob produces.
func buildChecksums(archives, sboms []string) string {
	var b strings.Builder
	for _, n := range append(append([]string{}, archives...), sboms...) {
		fmt.Fprintf(&b, "%s  %s\n", hashFor(n), n)
	}
	return b.String()
}
