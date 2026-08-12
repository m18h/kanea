package reconciler

import (
	"sort"
	"strings"
)

// CapabilityNone is the R13 token that opts a service out of the baseline:
// "start from nothing". It is stored in Desired.Capabilities exactly as
// declared (jobspec canonicalizes it to this lowercase form), because
// declaring it changes what runs and must therefore change the spec hash.
// It never reaches an AllocSpec — effectiveCapabilities strips it, and the
// runtime driver refuses any non-CAP_ token as a second line of defence,
// since runc fails the whole task on an unknown capability name.
const CapabilityNone = "none"

// BaselineCapabilities is what a runc alloc gets when its spec declares
// nothing (PRD §6.2 R13, v1.56): the grants the PUID-pattern image class
// needs to fix a root-owned volume, drop to its configured user, signal the
// children its root init supervises (confined by the per-alloc PID
// namespace), and bind a port below the netns's 1024 floor.
//
// CAP_NET_RAW is deliberately absent and must stay absent: the datapath's
// identity is the IP (PRD §5.2.5), and a raw socket is a source-forging
// primitive against a SYN-gated, stateless policy layer. That is where
// Docker's default set stops being a precedent.
var BaselineCapabilities = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_NET_BIND_SERVICE",
	"CAP_SETGID",
	"CAP_SETUID",
}

// effectiveCapabilities projects a service's declared capability list into
// the set its allocs actually run with.
//
// This is projection-time on purpose, and the placement is load-bearing (the
// R23 lesson): Desired.Capabilities is SpecHash material, so writing the
// baseline into the record would re-hash — and roll — every capability-less
// service on the node the moment kanead was upgraded. Applied here, an
// existing alloc keeps the set it was created with until its next roll, and
// the baseline arrives with the next deploy.
//
// A non-default runtime passes through verbatim: R25 gives a function's spec
// no way to declare capabilities, so its list is empty and stays empty — and
// a hand-crafted record that somehow carries one is preserved for the
// generate layer to refuse by name rather than silently swallowed here.
func effectiveCapabilities(d Desired) []string {
	if d.Runtime != "" {
		return d.Capabilities
	}

	declared := make([]string, 0, len(d.Capabilities))
	fromNothing := false
	for _, c := range d.Capabilities {
		if c == CapabilityNone {
			fromNothing = true
			continue
		}
		declared = append(declared, c)
	}
	if fromNothing {
		return declared
	}

	merged := make(map[string]bool, len(BaselineCapabilities)+len(declared))
	for _, c := range BaselineCapabilities {
		merged[c] = true
	}
	for _, c := range declared {
		merged[c] = true
	}
	out := make([]string, 0, len(merged))
	for c := range merged {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// describeCapabilities names a declared list for a plan line. The empty
// default reads as what it means rather than as a blank.
func describeCapabilities(caps []string) string {
	if len(caps) == 0 {
		return "baseline (default)"
	}
	return "[" + strings.Join(caps, ", ") + "]"
}
