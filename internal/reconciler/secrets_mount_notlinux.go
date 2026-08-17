//go:build !linux

package reconciler

import (
	"fmt"
	"os"
)

// ensureSecretsTmpfs is the development-node answer: a plain directory. There
// is no tmpfs mount primitive off Linux, and a workstation running netns mode
// trades the structural guarantee for convenience; the 0700 directory is the
// whole posture here.
func ensureSecretsTmpfs(dir string) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("secrets dir: %w", err)
	}
	return false, nil
}

// warnSecretsTmpfsFallback never fires here: the whole platform is already
// the fallback, and nothing new is being said.
func (r *Reconciler) warnSecretsTmpfsFallback(string) {}
