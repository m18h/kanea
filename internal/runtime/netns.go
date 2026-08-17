package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// NetnsDir is where iproute2 keeps named network namespaces. A netns here
// outlives the process that made it, which is the whole point: the network is
// wired up before the workload starts and survives a task restart.
const NetnsDir = "/run/netns"

// NetnsPath returns the persistent netns path for an alloc.
func NetnsPath(allocID string) string {
	return filepath.Join(NetnsDir, allocID)
}

// CreateNetns makes a persistent, named network namespace for an alloc and
// brings its loopback up.
//
// The ordering matters: create the netns, attach the datapath (which writes
// the alloc's identity and plumbs its veth, §5.2.5), and only then start the
// task. Attaching the network after the task starts leaves a window in which
// the workload runs with no connectivity, and under the datapath, with no
// identity, so its traffic is dropped.
//
// It is idempotent: an existing netns is reused rather than recreated, so a
// retrying reconciler does not tear the network out from under a running alloc.
func CreateNetns(allocID string) (string, error) {
	if allocID == "" {
		return "", fmt.Errorf("%w: empty alloc id", ErrInvalidSpec)
	}
	path := NetnsPath(allocID)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	if out, err := runIP("netns", "add", allocID); err != nil {
		return "", fmt.Errorf("create netns %s: %w (%s)", allocID, err, out)
	}
	// CNI plugins do not bring lo up; a workload that talks to itself needs it.
	if out, err := runIP("netns", "exec", allocID, "ip", "link", "set", "lo", "up"); err != nil {
		// Roll back rather than hand back a half-built namespace. A rollback
		// failure is reported alongside the original cause, not swallowed.
		lo := fmt.Errorf("bring lo up in netns %s: %w (%s)", allocID, err, out)
		if rbOut, rbErr := runIP("netns", "delete", allocID); rbErr != nil {
			return "", errors.Join(lo, fmt.Errorf("rollback delete netns %s: %w (%s)", allocID, rbErr, rbOut))
		}
		return "", lo
	}
	return path, nil
}

// DeleteNetns removes an alloc's network namespace. Call it only after CNI DEL
// and after the task is gone: CNI DEL needs the namespace to still exist in
// order to clean up (M0 spike ②).
//
// Missing is success: teardown is idempotent.
func DeleteNetns(allocID string) error {
	if allocID == "" {
		return nil
	}
	if _, err := os.Stat(NetnsPath(allocID)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if out, err := runIP("netns", "delete", allocID); err != nil {
		return fmt.Errorf("delete netns %s: %w (%s)", allocID, err, out)
	}
	return nil
}

// NetnsExists reports whether the alloc's namespace is present: the check a
// reconciler uses to detect drift (someone deleted it by hand).
func NetnsExists(allocID string) bool {
	_, err := os.Stat(NetnsPath(allocID))
	return err == nil
}

// runIP shells out to iproute2. There is no stable Go API for creating a
// *persistent* named netns (it requires a bind mount into /run/netns held by a
// live process), and `ip netns` is the canonical implementation. Arguments are
// always passed as an array, never a shell string (PRD §14, A03).
func runIP(args ...string) (string, error) {
	cmd := exec.Command("ip", args...) // #nosec G204: fixed argv, no shell
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(bytes.TrimSpace(out))), err
}
