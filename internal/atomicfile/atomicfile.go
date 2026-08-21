// Package atomicfile writes a file in place, atomically, and only when its
// content changed.
//
// It exists because two subsystems need the same twenty-five lines and a second
// copy would drift: internal/network writes each project's resolv.conf, and
// internal/reconciler writes spec-declared config files (PRD §6.2 R35). The
// drift that copying invites is a half-written file bind-mounted into a
// container, which is not a class of bug worth risking to avoid a package.
//
// (The `ownershipRefusedBy` duplication precedent deliberately does not apply:
// that covers a two-entry map whose second copy is obvious at a glance.)
package atomicfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// WriteIfChanged writes body to path with mode, and reports whether it wrote.
//
// Two properties matter to both callers. **Unchanged content writes nothing**,
// so a steady-state reconcile pass touches no disk at all. And the write is a
// temp file in the same directory followed by rename(2), so a reader never sees
// half a file - which is also what makes it safe while a container has the old
// inode bind-mounted: the bind pins what it opened, and a new container binds
// the new inode.
func WriteIfChanged(path string, body []byte, mode os.FileMode) (bool, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("dir %s: %w", dir, err)
	}

	// #nosec G304: path comes from configuration, not from a request, and is
	// the same file this function is about to write.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return false, nil
	}

	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, body, mode); err != nil {
		return false, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		if rmErr := os.Remove(tmp); rmErr != nil && !os.IsNotExist(rmErr) {
			return false, fmt.Errorf("install %s: %w (and temp file left behind: %w)", path, err, rmErr)
		}
		return false, fmt.Errorf("install %s: %w", path, err)
	}
	return true, nil
}
