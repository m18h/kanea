package runtime

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Reading the OOM fact out of the alloc's cgroup (PRD v1.68, §17).
//
// containerd's exit status carries a number and nothing else, so an OOM kill
// and any other SIGKILL are the same 137: including the one `kanea stop`
// produces on a service that ignored its SIGTERM. The kernel does record the
// difference, in the alloc's own cgroup v2 `memory.events`, and that counter is
// the only honest source: a classifier that read 137 as "out of memory" would
// call every forced stop a memory problem.
//
// Everything here is best-effort by design. A cgroup that cannot be read is
// *not* evidence of anything, and the caller treats it as such: §9.2's "no
// data is never zero", applied to a cause rather than a metric.

// DefaultCgroupRoot is where cgroup v2 is mounted on a systemd node. It matches
// the datapath's own constant; both are describing the same mount.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// memoryUnlimited is what `memory.max` holds when no limit is set, which,
// since v1.58, is the default for a service that declares no `resources` block.
const memoryUnlimited = "max"

// oomState is what the cgroup can tell us about how an alloc ended.
type oomState struct {
	// Killed reports that the kernel OOM-killed a process in this cgroup.
	Killed bool
	// MemoryLimit is the alloc's own `memory.max` in bytes, or 0 when it
	// declared none. The distinction decides which OOM story is true: a
	// declared limit was exceeded, or the workload parent's collective ceiling
	// was hit (§5.2.11), and those want opposite fixes.
	MemoryLimit uint64
	// Known reports that the cgroup was actually readable. False means the
	// alloc's cgroup is gone or unreadable, so nothing above may be trusted.
	Known bool
}

// readOOMState reads the alloc's cgroup. It never returns an error: every
// failure means "the cgroup could not answer", which is the same answer as far
// as a caller is concerned, and an error return would invite a classifier to
// treat an unreadable cgroup as a distinct kind of exit. It is not one.
func readOOMState(cgroupRoot, allocID string) oomState {
	if cgroupRoot == "" {
		cgroupRoot = DefaultCgroupRoot
	}
	// filepath.Join cleans the result, and the id it is composed from is a
	// containerd container id, which containerd itself constrains to
	// alphanumerics and `._-`, so it holds no separator to traverse with. Ours
	// are narrower still (AllocID over two DNS-1123 labels, constraint #5).
	dir := filepath.Join(cgroupRoot, CgroupPath(WorkloadSlice, allocID))

	events, err := os.ReadFile(filepath.Join(dir, "memory.events")) // #nosec G304; a path composed from a containerd id, joined and cleaned
	if err != nil {
		return oomState{}
	}
	out := oomState{Known: true, Killed: cgroupCounter(string(events), "oom_kill") > 0}

	// Only meaningful once we know a kill happened, and a missing memory.max
	// beside a present memory.events reads the same as an unset limit.
	if limit, err := os.ReadFile(filepath.Join(dir, "memory.max")); err == nil { // #nosec G304: same path, same provenance
		out.MemoryLimit = parseMemoryMax(string(limit))
	}
	return out
}

// cgroupCounter pulls one "<key> <value>" line out of a cgroup flat-keyed file.
// An absent key is zero: `memory.events` gained fields over kernel versions, and
// a kernel that does not report one is not reporting a kill.
func cgroupCounter(content, key string) uint64 {
	for _, line := range strings.Split(content, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || name != key {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// parseMemoryMax reads `memory.max`, where the literal "max" means unbounded.
// Zero means "no limit declared", which is what unbounded is in the record too
// (R11, v1.58): one representation, so the two cannot drift.
func parseMemoryMax(content string) uint64 {
	content = strings.TrimSpace(content)
	if content == "" || content == memoryUnlimited {
		return 0
	}
	n, err := strconv.ParseUint(content, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
