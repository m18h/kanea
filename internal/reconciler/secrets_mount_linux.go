//go:build linux

package reconciler

import (
	"fmt"
	"os"
	"syscall"
)

// ensureSecretsTmpfs mounts the tmpfs the env-secret files live on (PRD §6.2
// R3), once, lazily: a node whose services reference no secrets never carries
// the mount. Already a mount point is success - a kanead restart reuses what
// the last one mounted, and stacking a fresh tmpfs over live binds would hide
// the files running allocs still read.
//
// 4 MiB, because the whole directory is secrets and they are small; a bound
// is what makes a mistake (a megabyte private key, a thousand allocs) a
// visible error rather than silent RAM growth inside the §5.2.11 reserve.
func ensureSecretsTmpfs(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secrets dir: %w", err)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	if stat.Type == 0x01021994 { // TMPFS_MAGIC
		return nil
	}
	// #nosec G204: a fixed directory, a fixed filesystem, no input.
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=4M,mode=0700"); err != nil {
		return fmt.Errorf("mount tmpfs at %s: %w", dir, err)
	}
	return nil
}
