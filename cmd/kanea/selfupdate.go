package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// The fetch half of `kanea upgrade` (PRD §15.4, v1.59). This is the one
// download whose hash cannot live in the embedded manifest (a binary cannot
// know the digest of its successor) so verification is the installer's:
// sha256 against the release's checksums.txt always, cosign keyless
// verification of that file when cosign is on the node, a loud note when it
// is not. Verifying Sigstore in-process was rejected: sigstore-go is the
// dependency tree the hand-written-HTTP rule exists to refuse.

// defaultRepo is where releases live. KANEA_REPO overrides it, exactly like
// the install script, so a fork upgrades from itself.
const defaultRepo = "m18h/kanea"

// oidcIssuer pins who vouched for the signing certificate: the same identity
// the release workflow verifies against itself before publishing.
const oidcIssuer = "https://token.actions.githubusercontent.com"

// maxArchiveBytes caps the download and the extraction alike. The real
// archive is tens of MiB; a cap ~10x over is a tripwire, not a budget.
const maxArchiveBytes = 512 << 20

// releaseTag is the grammar a resolved tag must match before it composes
// into a URL. GitHub's /releases/latest redirect for a repo with no release
// ends in the literal "releases", which would otherwise become a
// plausible-looking archive name and an unreadable 404: the install
// script's lesson, kept here.
var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// releaseSource fetches release artifacts. The base URL is a field so tests
// can point it at an httptest server; everything else is the contract
// release.yml publishes: kanea_<ver>_linux_<arch>.tar.gz beside a
// checksums.txt that covers it, signed as checksums.txt.sig/.pem.
type releaseSource struct {
	base   string // e.g. https://github.com/m18h/kanea
	client *http.Client
}

func newReleaseSource() *releaseSource {
	repo := os.Getenv("KANEA_REPO")
	if repo == "" {
		repo = defaultRepo
	}
	return &releaseSource{
		base:   "https://github.com/" + repo,
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

// latest resolves the newest release tag from the redirect GitHub serves:
// no JSON API, no unauthenticated rate limit, the install script's method.
func (s *releaseSource) latest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.base+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s/releases/latest: %w "+
			"(no egress on this node? build a bundle and use the install script's offline flow)",
			s.base, err)
	}
	defer resp.Body.Close() //nolint:errcheck // a HEAD body carries nothing
	tag := resp.Request.URL.Path
	tag = tag[strings.LastIndex(tag, "/")+1:]
	if !releaseTag.MatchString(tag) {
		return "", fmt.Errorf("no published release found at %s (resolved %q); "+
			"pin one with --version", s.base, tag)
	}
	return tag, nil
}

// assetName is the naming contract with release.yml.
func assetName(tag string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("kanea releases are linux binaries; this is %s; "+
			"upgrade the node, not this machine", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("no release is published for linux/%s", runtime.GOARCH)
	}
	return fmt.Sprintf("kanea_%s_linux_%s.tar.gz", strings.TrimPrefix(tag, "v"), runtime.GOARCH), nil
}

// fetch downloads one release asset into dir and returns its path. Optional
// assets (the signature pair) return "" on a 404 rather than failing: a
// release published without them is the checksum-only case, said out loud by
// the caller.
func (s *releaseSource) fetch(ctx context.Context, tag, name, dir string, optional bool) (string, error) {
	url := s.base + "/releases/download/" + tag + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing left to read
	if resp.StatusCode == http.StatusNotFound && optional {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", url, resp.Status)
	}

	path := filepath.Join(dir, name)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304; a path this process built
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, io.LimitReader(resp.Body, maxArchiveBytes))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("download %s: %w", name, err)
	}
	return path, nil
}

// checksumFor finds the sha256 hex for one asset in a checksums.txt, the
// `sha256sum` output format release.yml writes.
func checksumFor(checksums []byte, asset string) (string, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s: do not run this archive", asset)
}

// verifyChecksum compares a file against its published sha256.
func verifyChecksum(path, wantHex string) error {
	f, err := os.Open(path) // #nosec G304: a path this process built
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantHex {
		return fmt.Errorf("checksum mismatch for %s (got %s, want %s); do not run this archive",
			filepath.Base(path), got, wantHex)
	}
	return nil
}

// verifySignature checks the cosign keyless signature over checksums.txt,
// with exactly the install script's posture: required to *pass* when it can
// run, never required to be runnable. cosign absent and signature absent are
// each a note the caller prints; a signature that fails to verify is fatal.
func verifySignature(ctx context.Context, base, checksums, sig, pem string) (note string, err error) {
	cosign, lookErr := exec.LookPath("cosign")
	if lookErr != nil {
		return "cosign not found; checksum verified but signature not checked", nil
	}
	if sig == "" || pem == "" {
		return "no signature published for this release; checksum only", nil
	}
	identity := base + "/" // the release workflow of this repository, any ref
	cmd := exec.CommandContext(ctx, cosign, "verify-blob",
		"--certificate", pem,
		"--signature", sig,
		"--certificate-identity-regexp", identity,
		"--certificate-oidc-issuer", oidcIssuer,
		checksums) // #nosec G204: fixed argv over files this process wrote
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		return "", fmt.Errorf("signature verification failed; do not run this archive:\n%s",
			strings.TrimSpace(string(out)))
	}
	return "signature verified", nil
}

// extractBinary pulls the single `kanea` file out of a release archive.
// Anything else in the archive is ignored; a `kanea` entry that is not a
// plain file, or an archive without one, is refused.
func extractBinary(archive, dest string) error {
	f, err := os.Open(archive) // #nosec G304; a path this process built
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(archive), err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s holds no kanea binary", filepath.Base(archive))
		}
		if err != nil {
			return err
		}
		if filepath.Clean(hdr.Name) != "kanea" {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("the kanea entry in %s is not a regular file", filepath.Base(archive))
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) // #nosec G302,G304; a binary, at a path this process built
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(tr, maxArchiveBytes)) // #nosec G110; capped
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	}
}

// installOver replaces the running binary's own path with the file at src:
// a rename(2) within the same directory, so the swap is atomic and a process
// already executing the old image keeps its inode.
func installOver(src, target string) error {
	staged := target + ".next"
	if err := os.Rename(src, staged); err != nil {
		// src is in a temp dir that may be another filesystem; fall back to a
		// copy into the target's directory so the final rename stays atomic.
		if err := copyFile(src, staged); err != nil {
			return fmt.Errorf("stage the new binary beside %s: %w (are you root?)", target, err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Remove(staged) //nolint:errcheck // cleanup path
		return fmt.Errorf("install the new binary: %w", err)
	}
	return nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src) // #nosec G304: a path this process built
	if err != nil {
		return err
	}
	defer in.Close()                                                         //nolint:errcheck // read-only
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) // #nosec G302,G304; a binary, at a path this process built
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dest) //nolint:errcheck // cleanup path
	}
	return err
}

// runningBinaryPath resolves this process's own binary: the path the new
// release is installed over. Unlike init.go's executablePath it has no
// fallback: installing over a guessed path is how the wrong file gets
// replaced as root.
func runningBinaryPath() (string, error) {
	target, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(target)
}

// selfUpdate downloads and verifies the release asset for tag and installs
// it over target. It returns notes the caller should print: the signature
// posture is a fact the operator must see either way.
func (s *releaseSource) selfUpdate(ctx context.Context, tag, asset, target string) (notes []string, err error) {
	work, err := os.MkdirTemp("", "kanea-upgrade-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work) //nolint:errcheck // best-effort cleanup

	archive, err := s.fetch(ctx, tag, asset, work, false)
	if err != nil {
		return nil, err
	}
	checksums, err := s.fetch(ctx, tag, "checksums.txt", work, false)
	if err != nil {
		return nil, err
	}
	sums, err := os.ReadFile(checksums) // #nosec G304: a path this process built
	if err != nil {
		return nil, err
	}
	want, err := checksumFor(sums, asset)
	if err != nil {
		return nil, err
	}
	if err := verifyChecksum(archive, want); err != nil {
		return nil, err
	}

	sig, err := s.fetch(ctx, tag, "checksums.txt.sig", work, true)
	if err != nil {
		return nil, err
	}
	pem, err := s.fetch(ctx, tag, "checksums.txt.pem", work, true)
	if err != nil {
		return nil, err
	}
	note, err := verifySignature(ctx, s.base, checksums, sig, pem)
	if err != nil {
		return nil, err
	}
	notes = append(notes, note)

	staged := filepath.Join(work, "kanea")
	if err := extractBinary(archive, staged); err != nil {
		return nil, err
	}
	if err := installOver(staged, target); err != nil {
		return nil, err
	}
	notes = append(notes, fmt.Sprintf("installed %s at %s", tag, target))
	return notes, nil
}
