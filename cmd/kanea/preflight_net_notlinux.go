//go:build !linux

package main

import goruntime "runtime"

// networkEgressChecks off Linux mirrors checkBPF's stance: the host already
// failed checkPlatform, and this exists so `doctor` on a development machine
// reports the checks exist rather than hiding them.
func networkEgressChecks(preflightOptions) []checkResult {
	return []checkResult{warn("egress", "not checked on "+goruntime.GOOS, "")}
}
