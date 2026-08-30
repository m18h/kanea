package main

// The Kanea workload hardening set, copied from internal/runtime/spec.go and
// internal/runtime/seccomp.go (the wasm spike's check-C discipline: a spike
// never imports the platform, it copies the opts verbatim so a rejection
// names the opt the shipping code would have to branch on).
//
// seccomp_default.json is a byte copy of internal/runtime/seccomp_default.json
// at the time of the spike; the resolution below is defaultSeccomp verbatim,
// minus the sync.Once (a spike runs once).

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	goruntime "runtime"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// compatBaseline is reconciler.BaselineCapabilities as of PRD v1.103: the
// seven uid-switching grants, CAP_NET_BIND_SERVICE gone (the alloc netns
// carries ip_unprivileged_port_start=0 instead — which is exactly what
// check E interrogates under a userns).
var compatBaseline = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
}

//go:embed seccomp_default.json
var seccompDefaultJSON []byte

// withKaneaHardening mirrors internal/runtime's withHardening + withResources
// for a service-shaped alloc: the capability set applied to bounding /
// effective / permitted (never inheritable or ambient), no-new-privileges,
// the masked and readonly paths, PID/IPC/UTS/mount/cgroup namespaces, the
// read-only cgroup mount, the resolved seccomp profile, and a 64 MiB / 64
// pids resource box.
func withKaneaHardening(id string, caps []string, netnsPath string, mounts []specs.Mount) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Process == nil {
			s.Process = &specs.Process{}
		}
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}

		granted := append([]string(nil), caps...)
		s.Process.Capabilities = &specs.LinuxCapabilities{
			Bounding:    granted,
			Effective:   granted,
			Permitted:   granted,
			Inheritable: []string{},
			Ambient:     []string{},
		}
		s.Process.NoNewPrivileges = true

		s.Linux.Namespaces = ensureNamespaces(s.Linux.Namespaces,
			specs.PIDNamespace, specs.IPCNamespace, specs.UTSNamespace,
			specs.MountNamespace, specs.CgroupNamespace)
		if netnsPath != "" {
			s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{
				Type: specs.NetworkNamespace,
				Path: netnsPath,
			})
		}
		s.Hostname = id

		s.Linux.MaskedPaths = []string{
			"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
			"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
			"/proc/sched_debug", "/proc/scsi", "/sys/firmware",
			"/sys/devices/virtual/powercap",
		}
		s.Linux.ReadonlyPaths = []string{
			"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
		}

		profile, err := resolveSeccomp(granted)
		if err != nil {
			return err
		}
		s.Linux.Seccomp = profile

		mem := int64(64 << 20)
		pids := int64(64)
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}
		s.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &mem, Swap: &mem}
		s.Linux.Resources.Pids = &specs.LinuxPids{Limit: &pids}

		s.Mounts = ensureCgroupMount(s.Mounts)
		s.Mounts = append(s.Mounts, mounts...)
		return nil
	}
}

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

// ---- seccomp resolution, copied from internal/runtime/seccomp.go ----

type seccompFile struct {
	DefaultAction   specs.LinuxSeccompAction `json:"defaultAction"`
	DefaultErrnoRet *uint                    `json:"defaultErrnoRet,omitempty"`
	Architectures   []specs.Arch             `json:"architectures"`
	Syscalls        []seccompRule            `json:"syscalls"`
}

type seccompRule struct {
	Names    []string                 `json:"names"`
	Action   specs.LinuxSeccompAction `json:"action"`
	ErrnoRet *uint                    `json:"errnoRet,omitempty"`
	Args     []specs.LinuxSeccompArg  `json:"args,omitempty"`
	Includes *seccompFilter           `json:"includes,omitempty"`
	Excludes *seccompFilter           `json:"excludes,omitempty"`
}

type seccompFilter struct {
	Arches []string `json:"arches,omitempty"`
	Caps   []string `json:"caps,omitempty"`
}

func resolveSeccomp(caps []string) (*specs.LinuxSeccomp, error) {
	var f seccompFile
	if err := json.Unmarshal(seccompDefaultJSON, &f); err != nil {
		return nil, fmt.Errorf("embedded seccomp profile: %w", err)
	}

	var arch specs.Arch
	switch goruntime.GOARCH {
	case "amd64":
		arch = specs.ArchX86_64
	case "arm64":
		arch = specs.ArchAARCH64
	default:
		return nil, fmt.Errorf("no seccomp arch mapping for %s", goruntime.GOARCH)
	}
	arches := map[specs.Arch]bool{arch: true}
	switch arch {
	case specs.ArchX86_64:
		arches[specs.ArchX86], arches[specs.ArchX32] = true, true
	case specs.ArchAARCH64:
		arches[specs.ArchARM] = true
	}
	granted := make(map[string]bool, len(caps))
	for _, c := range caps {
		granted[c] = true
	}

	archOverlap := func(list []string) bool {
		for _, a := range list {
			if arches[specs.Arch(a)] {
				return true
			}
		}
		return false
	}
	capsAll := func(list []string) bool {
		for _, c := range list {
			if !granted[c] {
				return false
			}
		}
		return true
	}
	capsAny := func(list []string) bool {
		for _, c := range list {
			if granted[c] {
				return true
			}
		}
		return false
	}

	out := &specs.LinuxSeccomp{
		DefaultAction:   f.DefaultAction,
		DefaultErrnoRet: f.DefaultErrnoRet,
		Architectures:   f.Architectures,
	}
	for _, rule := range f.Syscalls {
		if inc := rule.Includes; inc != nil {
			if len(inc.Arches) > 0 && !archOverlap(inc.Arches) {
				continue
			}
			if len(inc.Caps) > 0 && !capsAll(inc.Caps) {
				continue
			}
		}
		if exc := rule.Excludes; exc != nil {
			if len(exc.Arches) > 0 && archOverlap(exc.Arches) {
				continue
			}
			if len(exc.Caps) > 0 && capsAny(exc.Caps) {
				continue
			}
		}
		out.Syscalls = append(out.Syscalls, specs.LinuxSyscall{
			Names: rule.Names, Action: rule.Action, ErrnoRet: rule.ErrnoRet, Args: rule.Args,
		})
	}
	return out, nil
}
