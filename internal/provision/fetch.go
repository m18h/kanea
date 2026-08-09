package provision

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// HTTPSource fetches artefacts from the URLs the manifest pins.
type HTTPSource struct {
	client *http.Client
}

// maxRedirects bounds the redirect chain. GitHub serves release downloads as a
// redirect to objects.githubusercontent.com, so redirects cannot simply be
// refused — but each hop is re-checked for HTTPS, because a chain that ends in
// plaintext is a chain that leaks which version of which runtime this node is
// about to install.
const maxRedirects = 10

// fetchTimeout bounds a single artefact. Generous: a containerd tarball on a
// slow link is minutes, and an installer that gives up on a bad connection is
// an installer that half-installs a node.
const fetchTimeout = 15 * time.Minute

// NewHTTPSource returns a Source that downloads from upstream.
func NewHTTPSource() *HTTPSource {
	return &HTTPSource{
		client: &http.Client{
			Timeout: fetchTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				if req.URL.Scheme != "https" {
					return fmt.Errorf("refusing a redirect to %s://%s — artefact downloads stay on https",
						req.URL.Scheme, req.URL.Host)
				}
				return nil
			},
		},
	}
}

// Describe names where artefacts come from, for logs and errors.
func (s *HTTPSource) Describe() string { return "upstream" }

// Offline is always false: this Source is the network.
func (s *HTTPSource) Offline() bool { return false }

// Open downloads a component's artefact.
func (s *HTTPSource) Open(ctx context.Context, c *Component, arch string) (io.ReadCloser, error) {
	if c.Kind == KindImage {
		// Images do not come through a Source: they are pulled by digest
		// through containerd, which has the content store and the unpacking.
		// Saying so beats a confusing empty URL.
		return nil, fmt.Errorf("component %q is an image; pull it by digest instead", c.Name)
	}
	url := c.ArtefactURL(arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "kanea-install")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close() //nolint:errcheck // cleanup path
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// Stage writes a component's artefact to a temporary file, verified.
//
// The order is the whole point: bytes land at a temporary path, the hash is
// checked, and only then does anything else look at the file. A partially
// written or mismatched `containerd` must never exist at a path something
// might execute, and "verify after install" is not a smaller version of that
// rule — it is the absence of it.
//
// The caller closes and removes the returned file.
func Stage(ctx context.Context, src Source, c *Component, arch, tmpDir string) (*os.File, error) {
	want, err := c.Hash(arch)
	if err != nil {
		return nil, err
	}

	body, err := src.Open(ctx, c, arch)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }() //nolint:errcheck // cleanup path
	tmp, err := os.CreateTemp(tmpDir, "kanea-"+c.Name+"-*.part")
	if err != nil {
		return nil, fmt.Errorf("staging file for %s: %w", c.Name, err)
	}
	cleanup := func() {
		_ = tmp.Close()           //nolint:errcheck // cleanup path
		_ = os.Remove(tmp.Name()) //nolint:errcheck // cleanup path
	}

	verified := NewVerifiedReader(body, want)
	if _, err := io.Copy(tmp, verified); err != nil {
		cleanup()
		if errors.Is(err, ErrHashMismatch) {
			return nil, fmt.Errorf("%s from %s: %w", c.Display(), src.Describe(), err)
		}
		return nil, fmt.Errorf("download %s from %s: %w", c.Display(), src.Describe(), err)
	}
	// io.Copy stops at EOF, which is where the reader verifies — but a body
	// that ends without EOF (a Source backed by an exact-length reader) would
	// slip through, so it is asked again. Verify is idempotent.
	if err := verified.Verify(); err != nil {
		cleanup()
		return nil, fmt.Errorf("%s from %s: %w", c.Display(), src.Describe(), err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, fmt.Errorf("rewind the staged %s: %w", c.Name, err)
	}
	return tmp, nil
}

// writeFileAtomic writes r to path with mode, via a temporary file in the same
// directory and a rename.
//
// Same directory, so the rename is within one filesystem and therefore atomic;
// across one it is a copy that can be interrupted, which is the failure this
// exists to prevent. The mode is set before the rename for the same reason: a
// brief window where a root binary is world-writable is still a window.
func writeFileAtomic(path string, r io.Reader, mode os.FileMode) error {
	dir := filepath.Dir(path)
	// #nosec G301 — 0755 is required, not lax. These directories hold the
	// component executables, and `buildkitd` runs as the unprivileged
	// kanea-buildkit user (§5.2.11) which has to traverse them to exec
	// buildctl and rootlesskit. 0750 would break the one component whose
	// whole point is that it is not root.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("staging file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() //nolint:errcheck // no-op once the rename succeeds

	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close() //nolint:errcheck // cleanup path
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close() //nolint:errcheck // cleanup path
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	// Synced before the rename: an installer that survives the power cut it
	// caused is worth the milliseconds, and a zero-length containerd after a
	// crash looks like a corrupt download nobody can explain.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() //nolint:errcheck // cleanup path
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
