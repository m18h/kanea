//go:build !linux

package scaling

// openI915Sampler is Linux-only, because perf_event_open is a Linux syscall and
// the i915 PMU is a Linux driver's.
//
// A dev build on another platform reports no Intel utilisation, which is the
// same absence a Linux node without an Intel GPU reports - the posture the rest
// of this file's neighbours already take (NodeReader answers nothing off Linux
// rather than inventing a procfs).
func openI915Sampler(string) EngineBusyReader { return nil }
