package runtime

import (
	_ "embed"
	"encoding/json"
	"fmt"
	goruntime "runtime"
	"sync"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// seccomp_default.json is the workload syscall filter (PRD §14 A05): Docker's
// default profile (moby/moby v28.3.3, profiles/seccomp/default.json,
// Apache-2.0), converted for this platform: archMap becomes `architectures`
// (amd64 and arm64 plus their 32-bit compat personalities), the kernel-4.8
// minKernel gate becomes unconditional (the floor is 5.10), arch names become
// SCMP_ARCH_* constants, and the s390/riscv/ppc sections are dropped.
//
// It is vendored rather than fetched or generated: the syscall surface every
// workload runs under is exactly the kind of thing that should change only
// with a review (the components.json rule, applied to the filter).
//
//go:embed seccomp_default.json
var seccompDefaultJSON []byte

// The file keeps the docker-style shape, arch and capability gating included.
// Neither specs-go nor runc has such fields: the OCI consumers of a seccomp
// profile take a flat list, and handing them the raw profile would make the
// CAP_SYS_ADMIN section an *unconditional* allow of bpf, mount, umount and
// setns. Docker resolves the gates when it loads the profile; so do we, per
// alloc, below.
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

var parsedSeccomp = sync.OnceValues(func() (*seccompFile, error) {
	var f seccompFile
	if err := json.Unmarshal(seccompDefaultJSON, &f); err != nil {
		return nil, fmt.Errorf("runtime: embedded seccomp profile: %w", err)
	}
	if f.DefaultAction != specs.ActErrno {
		return nil, fmt.Errorf("runtime: embedded seccomp profile has default action %q, want %q",
			f.DefaultAction, specs.ActErrno)
	}
	return &f, nil
})

// nativeArch is the seccomp name of the node's own architecture. The profile
// is resolved on the node, so the build arch is the node arch.
func nativeArch() (specs.Arch, error) {
	switch goruntime.GOARCH {
	case "amd64":
		return specs.ArchX86_64, nil
	case "arm64":
		return specs.ArchAARCH64, nil
	}
	return "", fmt.Errorf("runtime: no seccomp arch mapping for %s", goruntime.GOARCH)
}

// defaultSeccomp resolves the vendored profile into the flat rule list runc
// consumes, for one alloc. A rule gated on an arch applies only when the node
// (or a 32-bit personality its kernel answers for) matches; a rule gated on a
// capability applies only when the alloc's *effective* set - the R13 baseline
// union the declared grants, which is what spec.Capabilities already carries -
// includes every gated capability. An excludes filter disqualifies on any
// overlap, the profile's own precedence.
func defaultSeccomp(caps []string) (*specs.LinuxSeccomp, error) {
	f, err := parsedSeccomp()
	if err != nil {
		return nil, err
	}
	arch, err := nativeArch()
	if err != nil {
		return nil, err
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
