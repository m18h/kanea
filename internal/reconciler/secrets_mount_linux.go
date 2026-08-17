//go:build linux

package reconciler

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
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
//
// EPERM is the one soft failure, reported to the caller: kanead runs as root
// in production, so a mount that fails with EPERM is a dev or test run without
// CAP_SYS_ADMIN, and the answer there is the same plain 0700 directory the
// non-linux build uses. Anything else (ENOSPC, a kernel that lost tmpfs) fails
// the alloc, because proceeding would write secrets to disk.
//
// The bool reports "fell back to a plain directory". The caller warns through
// its own logger.
func ensureSecretsTmpfs(dir string) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("secrets dir: %w", err)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return false, fmt.Errorf("statfs %s: %w", dir, err)
	}
	if stat.Type == 0x01021994 { // TMPFS_MAGIC
		return false, nil
	}
	// #nosec G204: a fixed directory, a fixed filesystem, no input.
	err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=4M,mode=0700")
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, unix.EPERM):
		return true, nil
	default:
		return false, fmt.Errorf("mount tmpfs at %s (R3 keeps secrets in RAM, so this must work): %w", dir, err)
	}
}

// secretsTmpfsFallbackWarned makes the fallback a once-only log line: dev is
// the only place it fires, and it fires on every environment-secret create
// there.
var secretsTmpfsFallbackWarned atomic.Bool

// warnSecretsTmpfsFallback says the soft failure out loud, once.
func (r *Reconciler) warnSecretsTmpfsFallback(dir string) {
	if secretsTmpfsFallbackWarned.Swap(true) {
		return
	}
	r.log.Warn("secrets directory is not tmpfs (no CAP_SYS_ADMIN; dev or test "+
		"mode): env-secret values would hit the directory on disk", "dir", dir)
}
