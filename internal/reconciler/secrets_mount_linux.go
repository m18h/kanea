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
	return ensureTmpfs(dir, "size=4M,mode=0700", "secrets")
}

// ensureFilesTmpfs is the same, for the tree spec-declared files carrying a
// secret are materialised into (R35).
//
// A separate mount rather than a bigger secrets one, deliberately: the secrets
// tmpfs is shared by every alloc on the node and sized for credentials, so a
// config file filling it would surface as secrets_failed on a service in
// another project that declares no files at all.
func ensureFilesTmpfs(dir string) (bool, error) {
	// 16 MiB: the per-service content budget (§21) times enough allocs to be
	// generous, and a ceiling rather than a reservation, so the footprint pays
	// only for what is written. Bigger than the secrets tmpfs because config
	// files legitimately are, and separate from it so that being wrong about
	// this number cannot fail credential delivery.
	return ensureTmpfs(dir, "size=16M,mode=0700", "files")
}

func ensureTmpfs(dir, opts, what string) (bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("%s dir: %w", what, err)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return false, fmt.Errorf("statfs %s: %w", dir, err)
	}
	if stat.Type == 0x01021994 { // TMPFS_MAGIC
		return false, nil
	}
	// #nosec G204: a fixed directory, a fixed filesystem, no input.
	err := syscall.Mount("tmpfs", dir, "tmpfs", 0, opts)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, unix.EPERM):
		return true, nil
	default:
		return false, fmt.Errorf("mount tmpfs at %s (%s must stay in RAM, so this must work): %w",
			dir, what, err)
	}
}

// secretsTmpfsFallbackWarned makes the fallback a once-only log line: dev is
// the only place it fires, and it fires on every environment-secret create
// there.
var secretsTmpfsFallbackWarned atomic.Bool

// filesTmpfsFallbackWarned is the files tree's own once-flag: the two trees
// fall back independently, and one warning standing for both would hide it.
var filesTmpfsFallbackWarned atomic.Bool

// warnFilesTmpfsFallback says the soft failure out loud, once.
func (r *Reconciler) warnFilesTmpfsFallback(dir string) {
	if filesTmpfsFallbackWarned.Swap(true) {
		return
	}
	r.log.Warn("files directory is not tmpfs (no CAP_SYS_ADMIN; dev or test mode): "+
		"a config file interpolating a secret would hit the directory on disk", "dir", dir)
}

// warnSecretsTmpfsFallback says the soft failure out loud, once.
func (r *Reconciler) warnSecretsTmpfsFallback(dir string) {
	if secretsTmpfsFallbackWarned.Swap(true) {
		return
	}
	r.log.Warn("secrets directory is not tmpfs (no CAP_SYS_ADMIN; dev or test "+
		"mode): env-secret values would hit the directory on disk", "dir", dir)
}
