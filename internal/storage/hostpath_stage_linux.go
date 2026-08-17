//go:build linux

package storage

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// stagingSupported reports the build's answer: the race K-20 closes exists
// where runc does, which is linux.
const stagingSupported = true

// pinHost opens the resolved directory through openat2 and re-verifies the
// allowlist against the OBJECT, not the spelling: RESOLVE_NO_SYMLINKS makes a
// symlink swap lose the race to the open, and the fd's own path (read back
// through /proc/self/fd) is what gets prefix-checked, because the string
// EvalSymlinks returned is not necessarily the thing being mounted.
//
// The caller closes the fd.
func pinHost(resolved string, allowed []string) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, resolved, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("pin %s: %w", resolved, err)
	}
	fdPath, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("read the pinned path for %s: %w", resolved, err)
	}
	for _, prefix := range allowed {
		if withinPrefix(fdPath, prefix) {
			return fd, nil
		}
	}
	_ = unix.Close(fd)
	return -1, fmt.Errorf("%w: %q (pinned as %q) is not under any allowed prefix",
		ErrHostPathNotAllowed, resolved, fdPath)
}

// pinAndBind mounts the object the policy actually checked (K-20).
//
// Resolve's EvalSymlinks→Stat→prefix-check answers about a path; runc's bind
// mount happens seconds later, and a workload with an rw volume under an
// allowed prefix can atomic-rename a checked directory to a symlink in the
// gap. The bind's source is /proc/self/fd/N, which the kernel resolves to the
// open file description - the pinned inode - in this process, not to a path
// an attacker can still rename; and the staging target lives under a
// root-owned directory, so runc's later walk of the source path it is handed
// crosses nothing a workload can influence.
//
// The fd is closed before returning: the bind mount holds the reference.
func pinAndBind(resolved, staging string, allowed []string) error {
	fd, err := pinHost(resolved, allowed)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	if err := os.MkdirAll(staging, 0o750); err != nil {
		return fmt.Errorf("staging directory %s: %w", staging, err)
	}
	if err := unix.Mount("/proc/self/fd/"+strconv.Itoa(fd), staging, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("stage the pinned directory at %s: %w", staging, err)
	}
	return nil
}

// unstagePath removes one staging bind mount and its directory. Absent and
// unmounted both count as done: teardown runs on paths where part of it
// already happened.
func unstagePath(mounted func(string) (bool, error), path string) error {
	on, err := mounted(path)
	if err != nil {
		return fmt.Errorf("check staging mount %s: %w", path, err)
	}
	if on {
		if err := unix.Unmount(path, 0); err != nil {
			return fmt.Errorf("unmount staging %s: %w", path, err)
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove staging %s: %w", path, err)
	}
	return nil
}
