package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/m18h/kanea/internal/jobspec"
)

// dirReader resolves a `file` block's `source` against the directory of the
// spec that declared it (jobspec R35).
//
// This is the CLI's implementation of jobspec.SourceReader, and it is the only
// one backed by a filesystem. The daemon supplies none, so `source` is refused
// there by name: `POST /v1/spec/render` parses an in-memory string inside
// kanead as root, and a parser that opened files itself would make that route
// an arbitrary file read for any signed-in user.
type dirReader struct{}

// ReadSpecFile reads rel relative to specPath's directory.
//
// The lexical checks (absolute, `..`, clean) already ran at parse. This is the
// assertion at the point of use, and it is a different assertion: a lexical
// check cannot see a symlink, which is the K-01 hole in the build context's
// original containment check. Every component is checked, not just the leaf.
func (dirReader) ReadSpecFile(specPath, rel string) ([]byte, error) {
	base, err := filepath.Abs(filepath.Dir(specPath))
	if err != nil {
		return nil, fmt.Errorf("resolve spec directory: %w", err)
	}
	target := filepath.Join(base, rel)
	if err := withinSpecDir(base, target); err != nil {
		return nil, err
	}

	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	// Regular files only. A symlink here would be the containment check's
	// blind spot, and a directory or a fifo is not content.
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}

	// #nosec G304: target is contained under the spec's own directory by the
	// check above, component by component including symlinks.
	f, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only, cleanup path

	// Never ReadFile a file of unknown size: the cap is the point, and reading
	// first and checking after is how a 4 GiB file becomes an OOM.
	body, err := io.ReadAll(io.LimitReader(f, int64(jobspec.MaxFileBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	if len(body) > jobspec.MaxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes (PRD §21)", rel, jobspec.MaxFileBytes)
	}
	return body, nil
}

// withinSpecDir refuses a target that leaves base, following symlinks
// component by component.
//
// The lexical Rel check alone was the K-01 hole in the build context: a
// symlinked component resolves elsewhere while the spelling stays inside. So
// every prefix is Lstat-ed, and any symlink among them is refused outright
// rather than resolved and re-checked, which is the same call withinDir makes.
func withinSpecDir(base, target string) error {
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside the spec's directory", target)
	}
	walked := base
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		walked = filepath.Join(walked, part)
		info, err := os.Lstat(walked)
		if err != nil {
			// A missing component is the caller's problem to report with its
			// own message; it is not a containment failure.
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s passes through a symlink (%s), which is refused", target, walked)
		}
	}
	return nil
}
