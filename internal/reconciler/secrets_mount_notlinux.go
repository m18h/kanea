//go:build !linux

package reconciler

import (
	"fmt"
	"os"
)

// ensureSecretsTmpfs is the off-Linux answer: a plain directory. There is no
// tmpfs mount primitive there, and kanead does not run there either; this
// exists so the package builds and its tests run. The 0700 directory is the
// whole posture here.
func ensureSecretsTmpfs(dir string) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("secrets dir: %w", err)
	}
	return false, nil
}

// ensureFilesTmpfs is the same for spec-declared files (R35).
func ensureFilesTmpfs(dir string) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("files dir: %w", err)
	}
	return false, nil
}

// warnFilesTmpfsFallback never fires here, for warnSecretsTmpfsFallback's
// reason: the whole platform is already the fallback.
func (r *Reconciler) warnFilesTmpfsFallback(string) {}

// warnSecretsTmpfsFallback never fires here: the whole platform is already
// the fallback, and nothing new is being said.
func (r *Reconciler) warnSecretsTmpfsFallback(string) {}
