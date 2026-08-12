package jobspec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// PermittedCapabilities is the closed set a service may request (R13).
//
// Every runc alloc starts from the baseline set (PRD §14 A05, v1.56 —
// reconciler.BaselineCapabilities), and the declared list adds to it; the
// CapabilityNone token starts from nothing instead. This set bounds what may
// be *declared*: what stock images legitimately need beyond the baseline —
// binding a raw socket, chrooting, dropping bounding-set entries. It is
// deliberately the conservative half of Docker's default set.
//
// Anything not listed here is refused at parse time. That is the point: v1 has
// no `privileged` escape hatch, and an allowlist that accepted CAP_SYS_ADMIN
// would be that hatch under another name.
var PermittedCapabilities = map[string]string{
	"CAP_AUDIT_WRITE":      "write audit records (login-style entrypoints)",
	"CAP_CHOWN":            "chown files, e.g. a data directory at first start",
	"CAP_DAC_OVERRIDE":     "bypass file permission checks",
	"CAP_FOWNER":           "operate on files owned by another uid",
	"CAP_FSETID":           "keep setuid/setgid bits when modifying a file",
	"CAP_KILL":             "signal processes it does not own",
	"CAP_MKNOD":            "create device nodes",
	"CAP_NET_BIND_SERVICE": "bind ports below 1024",
	"CAP_NET_RAW":          "raw and packet sockets (ping, traceroute)",
	"CAP_SETFCAP":          "set file capabilities",
	"CAP_SETGID":           "change group id, e.g. dropping to a service account",
	"CAP_SETPCAP":          "drop capabilities from its own bounding set",
	"CAP_SETUID":           "change user id, e.g. dropping to a service account",
	"CAP_SYS_CHROOT":       "chroot",
}

// forbiddenCapabilities are refused with a specific explanation rather than the
// generic "unknown capability", because these are the ones people actually
// reach for — and each is effectively root on the host.
var forbiddenCapabilities = map[string]string{
	"CAP_SYS_ADMIN":       "it is equivalent to root: mount, namespace and cgroup control",
	"CAP_SYS_MODULE":      "it can load kernel modules",
	"CAP_SYS_RAWIO":       "it grants raw I/O port and memory access",
	"CAP_SYS_PTRACE":      "it can inspect and modify any process, escaping the container",
	"CAP_SYS_BOOT":        "it can reboot the host",
	"CAP_SYS_TIME":        "it can change the host clock, which breaks TLS and audit ordering",
	"CAP_DAC_READ_SEARCH": "it can read any file on the host by inode",
	"CAP_BPF":             "it can load eBPF programs, which is host-level control",
	"CAP_PERFMON":         "it exposes host-wide performance and memory data",
	"CAP_MAC_ADMIN":       "it can change mandatory access control policy",
	"CAP_MAC_OVERRIDE":    "it bypasses mandatory access control",
	"CAP_SYS_NICE":        "it can starve other workloads by re-prioritising itself",
	"CAP_SYS_RESOURCE":    "it can raise its own resource limits past the alloc's",
	"CAP_NET_ADMIN":       "it can reconfigure networking, including Kanea's own datapath",
}

// CapabilityNone is the canonical spelling of the opt-out token: a service
// declaring it starts from nothing rather than from the baseline set. The
// constant is duplicated in the reconciler (reconciler.CapabilityNone), the
// ownershipRefusedBy precedent: a dependency from reconciler to jobspec would
// point the wrong way, and the contract is one lowercase word.
const CapabilityNone = "none"

var capabilityNoneUpper = strings.ToUpper(CapabilityNone)

// validateCapabilities enforces R13.
func validateCapabilities(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if svc.Task == nil {
		return diags
	}

	seen := make(map[string]bool, len(svc.Task.Capabilities))
	for _, capability := range svc.Task.Capabilities {
		name := strings.ToUpper(strings.TrimSpace(capability))

		// "none" opts out of the baseline: start from nothing, then grant
		// only what the rest of the list names (R13, v1.56). Checked before
		// the CAP_ prefix rule — it is a token, not a capability — but still
		// through the duplicate map.
		if name == capabilityNoneUpper {
			if seen[CapabilityNone] {
				diags = append(diags, capDiag(svc, fmt.Sprintf("%q is listed twice", CapabilityNone)))
				continue
			}
			seen[CapabilityNone] = true
			continue
		}

		switch {
		case name == "":
			diags = append(diags, capDiag(svc, "an empty capability name"))
			continue

		case !strings.HasPrefix(name, "CAP_"):
			diags = append(diags, capDiag(svc, fmt.Sprintf(
				"capability %q must be written with its CAP_ prefix, e.g. %q",
				capability, "CAP_"+name)))
			continue

		case seen[name]:
			diags = append(diags, capDiag(svc, fmt.Sprintf("capability %q is listed twice", name)))
			continue
		}
		seen[name] = true

		if reason, forbidden := forbiddenCapabilities[name]; forbidden {
			diags = append(diags, capDiag(svc, fmt.Sprintf(
				"capability %s cannot be granted: %s. v1 has no privileged escape hatch, "+
					"and this allowlist is not one", name, reason)))
			continue
		}
		if _, ok := PermittedCapabilities[name]; !ok {
			diags = append(diags, capDiag(svc, fmt.Sprintf(
				"unknown or unsupported capability %s. Permitted: %s",
				name, strings.Join(sortedPermitted(), ", "))))
		}
	}
	return diags
}

// validateCommand enforces R12: an argument array, never a shell string.
//
// Only the program (element 0) must be non-empty. Later arguments may be empty
// strings, because some programs use that meaningfully — `redis-server --save
// ""` is the documented way to disable snapshots, and rejecting it would make
// the field unusable for exactly the images that need it.
func validateCommand(svc *Service) hcl.Diagnostics {
	if svc.Task == nil || len(svc.Task.Command) == 0 {
		return nil
	}
	if strings.TrimSpace(svc.Task.Command[0]) == "" {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid command",
			Detail: fmt.Sprintf("Service %q: the first element of command is the program to run "+
				"and cannot be empty. command is an argument array — "+
				"[\"nginx\", \"-g\", \"daemon off;\"] — never a shell string.", svc.Name),
			Subject: svc.Task.DefRange.Ptr(),
		}}
	}
	return nil
}

func capDiag(svc *Service, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Invalid capability",
		Detail:   fmt.Sprintf("Service %q: %s.", svc.Name, detail),
		Subject:  svc.Task.DefRange.Ptr(),
	}
}

// NormalizeCapabilities upper-cases and de-duplicates a validated list, so
// every consumer sees canonical names. The one exception is the "none" token,
// canonicalized to lowercase — it is a spec-level word, not a capability, and
// the case difference is what keeps it visually distinct from the CAP_ names
// it stands beside. Sorting puts it after them, which is fine: position never
// carries meaning (this function sorts, and spec-source regenerates from the
// stored form).
func NormalizeCapabilities(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, c := range in {
		name := strings.ToUpper(strings.TrimSpace(c))
		if name == capabilityNoneUpper {
			name = CapabilityNone
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func sortedPermitted() []string {
	out := make([]string, 0, len(PermittedCapabilities))
	for name := range PermittedCapabilities {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
