//go:build !linux

package main

import goruntime "runtime"

// checkBPF is a warning off Linux: statfs magics are a Linux concept, and a
// non-linux host already failed checkPlatform — this runs only so `doctor` on
// a development machine reports the check exists rather than hiding it.
func checkBPF() checkResult {
	return warn("bpf", "not checked on "+goruntime.GOOS, "")
}
