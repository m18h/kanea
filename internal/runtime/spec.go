package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// MinAllocIDLength is the shortest usable alloc id. Cilium derives a temporary
// interface name from the first 5 characters of "<container-id>:<ifname>", so a
// shorter id puts a ':' in an interface name and CNI ADD fails with a bare
// EINVAL (M0 spike ①). Catching it here turns that into a clear error.
const MinAllocIDLength = 5

// DefaultPidsLimit contains fork bombs when the caller does not set one.
// PRD §5.2.11 requires a pids cap on every alloc, not just a memory cap.
const DefaultPidsLimit int64 = 256

// cpuPeriod is the standard CFS period; quota is derived from millicores.
const cpuPeriod uint64 = 100_000

// Validate rejects specs this driver will not run. It is strict on purpose:
// the alternative to a clear error here is a container that runs unlimited or
// unhardened, which is exactly what AGENTS.md constraints #6 and #11 forbid.
func (s AllocSpec) Validate() error {
	switch {
	case s.ID == "":
		return fmt.Errorf("%w: empty alloc id", ErrInvalidSpec)
	case len(s.ID) < MinAllocIDLength:
		return fmt.Errorf("%w: alloc id %q is %d characters; at least %d are required so the CNI "+
			"plugin can derive a valid interface name", ErrInvalidSpec, s.ID, len(s.ID), MinAllocIDLength)
	case s.Project == "":
		return fmt.Errorf("%w: alloc %s has no project", ErrInvalidSpec, s.ID)
	case s.Image == "":
		return fmt.Errorf("%w: alloc %s has no image", ErrInvalidSpec, s.ID)
	case s.Resources.CPUMillis <= 0:
		return fmt.Errorf("%w: alloc %s has no CPU limit; no alloc may run unlimited (PRD §6.2 R11)",
			ErrInvalidSpec, s.ID)
	case s.Resources.MemoryBytes <= 0:
		return fmt.Errorf("%w: alloc %s has no memory limit; no alloc may run unlimited (PRD §6.2 R11)",
			ErrInvalidSpec, s.ID)
	}
	for _, m := range s.Mounts {
		if !filepath.IsAbs(m.Source) || !filepath.IsAbs(m.Destination) {
			return fmt.Errorf("%w: alloc %s mount %s -> %s: both paths must be absolute",
				ErrInvalidSpec, s.ID, m.Source, m.Destination)
		}
	}
	for _, d := range s.Devices {
		if !filepath.IsAbs(d.Path) {
			return fmt.Errorf("%w: alloc %s device %q: the path must be absolute",
				ErrInvalidSpec, s.ID, d.Path)
		}
		// A device with no permissions is a node the container can see and
		// cannot open — almost certainly a caller that forgot the field rather
		// than an operator who meant it.
		if d.Perms == "" {
			return fmt.Errorf("%w: alloc %s device %q has no cgroup permissions",
				ErrInvalidSpec, s.ID, d.Path)
		}
	}
	return nil
}

// specOpts builds the OCI spec options for an alloc, in the order they must be
// applied. The image config comes first so later options override it.
func specOpts(spec AllocSpec) []oci.SpecOpts {
	opts := []oci.SpecOpts{}
	if len(spec.Command) > 0 {
		opts = append(opts, oci.WithProcessArgs(spec.Command...))
	}
	if len(spec.Env) > 0 {
		opts = append(opts, oci.WithEnv(envSlice(spec.Env)))
	}
	opts = append(opts, withHardening(spec))
	opts = append(opts, withResources(spec))
	if spec.NetnsPath != "" {
		// Join the netns CNI already wired up. Created before the task starts,
		// removed after it dies (M0 spike ②).
		opts = append(opts, oci.WithLinuxNamespace(specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: spec.NetnsPath,
		}))
	}
	if len(spec.Mounts) > 0 {
		opts = append(opts, oci.WithMounts(ociMounts(spec.Mounts)))
	}
	// Devices last, and after withResources: containerd's default spec carries a
	// deny-all device cgroup rule that withResources preserves, and an allow
	// rule only means anything if it is appended after that deny (PRD §6.2 R17).
	for _, device := range spec.Devices {
		opts = append(opts, oci.WithLinuxDevice(device.Path, device.Perms))
	}
	return opts
}

// withHardening applies the PRD §14 (A05) workload defaults. These are not
// configurable: v1 has no `privileged` escape hatch in the job spec, so there
// is no path by which a workload can ask for more.
func withHardening(spec AllocSpec) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Process == nil {
			s.Process = &specs.Process{}
		}
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}

		// Drop ALL capabilities, then grant back exactly what the spec asked
		// for (PRD §6.2 R13). jobspec has already refused anything outside the
		// permitted set, so this grants a bounded, reviewed list.
		//
		// Bounding, effective and permitted — never inheritable or ambient: a
		// granted capability must not survive into a child that re-execs, which
		// is how a capability turns into a persistent foothold.
		granted := append([]string(nil), spec.Capabilities...)
		s.Process.Capabilities = &specs.LinuxCapabilities{
			Bounding:    granted,
			Effective:   granted,
			Permitted:   granted,
			Inheritable: []string{},
			Ambient:     []string{},
		}
		// No setuid escalation, even if the image ships setuid binaries.
		s.Process.NoNewPrivileges = true

		if spec.ReadOnlyRootfs {
			s.Root = &specs.Root{Path: rootPath(s), Readonly: true}
		}

		// Per-alloc PID and IPC namespaces: one alloc must not see or signal
		// another's processes, nor share its shared memory. The cgroup namespace
		// matters twice over — it hides the host's cgroup tree, and it puts the
		// alloc's own cgroup at /sys/fs/cgroup, which is where a workload (and
		// any runtime that reads its own limits) expects to find it.
		s.Linux.Namespaces = ensureNamespaces(s.Linux.Namespaces,
			specs.PIDNamespace, specs.IPCNamespace, specs.UTSNamespace,
			specs.MountNamespace, specs.CgroupNamespace)

		// A UTS namespace with the host's hostname in it is the worst of both
		// worlds: the alloc is isolated but every log line, every `hostname`
		// call and every client library that self-identifies claims to be the
		// node. The alloc id is what `kanea ps` and `kanea logs` use, so it is
		// the name that lets someone correlate what they see inside a container
		// with what they see outside it.
		s.Hostname = spec.ID

		// Standard kernel-surface reduction: these are the paths a container
		// must not read or write even with no capabilities.
		s.Linux.MaskedPaths = maskedPaths()
		s.Linux.ReadonlyPaths = readonlyPaths()

		// containerd's default spec leaves /sys/fs/cgroup unmounted, so a
		// workload cannot read its own limits — and container-aware runtimes
		// (JVM, Node, Go's GOMEMLIMIT tooling) size themselves from exactly
		// that. Mount it read-only: with the cgroup namespace above, the alloc
		// sees its own cgroup at the root and cannot rewrite its limits.
		s.Mounts = ensureCgroupMount(s.Mounts)
		return nil
	}
}

// withResources applies the mandatory limits and the cgroup placement. Swap is
// pinned to the memory limit, i.e. zero swap headroom: PRD §5.2.11 makes the
// reserve RAM, not swap, so an alloc must not escape its ceiling via swap.
func withResources(spec AllocSpec) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}

		mem := spec.Resources.MemoryBytes
		s.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &mem, Swap: &mem}

		quota := int64(spec.Resources.CPUMillis) * int64(cpuPeriod) / 1000
		period := cpuPeriod
		s.Linux.Resources.CPU = &specs.LinuxCPU{Quota: &quota, Period: &period}

		pids := spec.Resources.PidsLimit
		if pids <= 0 {
			pids = DefaultPidsLimit
		}
		s.Linux.Resources.Pids = &specs.LinuxPids{Limit: &pids}

		if spec.CgroupPath != "" {
			s.Linux.CgroupsPath = spec.CgroupPath
		}
		return nil
	}
}

// ensureNamespaces adds any of the given namespace types that are missing,
// preserving existing entries (which may carry a path, as the netns does).
func ensureNamespaces(have []specs.LinuxNamespace, want ...specs.LinuxNamespaceType) []specs.LinuxNamespace {
	present := make(map[specs.LinuxNamespaceType]bool, len(have))
	for _, ns := range have {
		present[ns.Type] = true
	}
	for _, t := range want {
		if !present[t] {
			have = append(have, specs.LinuxNamespace{Type: t})
		}
	}
	return have
}

// ensureCgroupMount adds a read-only cgroup mount unless one is already there.
func ensureCgroupMount(mounts []specs.Mount) []specs.Mount {
	for _, m := range mounts {
		if m.Destination == "/sys/fs/cgroup" {
			return mounts
		}
	}
	return append(mounts, specs.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroup",
		Source:      "cgroup",
		Options:     []string{"nosuid", "noexec", "nodev", "relatime", "ro"},
	})
}

func rootPath(s *oci.Spec) string {
	if s.Root != nil && s.Root.Path != "" {
		return s.Root.Path
	}
	return "rootfs"
}

// maskedPaths hides kernel interfaces that leak host state or allow tampering.
func maskedPaths() []string {
	return []string{
		"/proc/acpi",
		"/proc/asound",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

// readonlyPaths keeps /proc control files visible but immutable.
func readonlyPaths() []string {
	return []string{
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}

// envSlice renders the env map as KEY=VALUE, sorted so a spec change produces a
// stable diff in `kanea plan` rather than map-order churn.
func envSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func ociMounts(mounts []Mount) []specs.Mount {
	out := make([]specs.Mount, 0, len(mounts))
	for _, m := range mounts {
		options := []string{"rbind"}
		if m.ReadOnly {
			options = append(options, "ro")
		} else {
			options = append(options, "rw")
		}
		// Caller-supplied options come last so they cannot be silently dropped,
		// and are appended rather than replacing: rbind is not negotiable — a
		// host path may carry submounts, and a plain bind would hide them.
		options = append(options, m.Options...)
		out = append(out, specs.Mount{
			Type:        "bind",
			Source:      m.Source,
			Destination: m.Destination,
			Options:     options,
		})
	}
	return out
}

// CgroupPath composes the per-alloc cgroup path under the workload parent
// (PRD §5.2.11). Every alloc lives under one parent so the collective ceiling
// applies even if a per-alloc limit is somehow missed.
func CgroupPath(parent, allocID string) string {
	if parent == "" {
		parent = WorkloadSlice
	}
	return "/" + strings.Trim(parent, "/") + "/" + allocID
}

// WorkloadSlice is the single parent cgroup for every managed alloc.
const WorkloadSlice = "kanea-workloads.slice"

// Namespace is the containerd namespace for a project: one namespace per
// project gives free isolation of images and containers (PRD §5.2.4).
func Namespace(project string) string {
	return "kanea-" + project
}
