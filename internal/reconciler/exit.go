package reconciler

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/m18h/kanea/internal/runtime"
)

// Classifying a termination (PRD v1.68, §17).
//
// This is deliberately a pure function over what the driver observed, for the
// same reason Observe is pure over World: the interesting cases are a kernel
// away and would otherwise only be reachable on a node with a workload actually
// being OOM-killed.

// signalExitBase is the shell convention containerd's exit statuses follow: a
// process killed by signal N reports 128+N.
const signalExitBase = 128

// signalNames covers the signals a container realistically dies from. Anything
// outside it is reported by number — an unnamed signal is still a signal, and
// guessing a name for a number we do not know would be worse than the number.
var signalNames = map[uint32]string{
	1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 6: "SIGABRT",
	8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 15: "SIGTERM",
	24: "SIGXCPU", 25: "SIGXFSZ", 31: "SIGSYS",
}

// classifyExit turns an observed stop into a reason and a one-line message.
//
// Order matters: OOM is checked first because an OOM kill *is* a SIGKILL, and
// classifying it as one would be true and useless. Everything else falls back
// to the most specific claim the evidence actually supports.
func classifyExit(status runtime.Status) (ExitReason, string) {
	switch {
	case status.OOMKnown && status.OOMKilled:
		return ExitOOMKilled, oomMessage(status)

	case status.ExitCode == 0:
		return ExitCompleted, "exited cleanly"

	case status.ExitCode > signalExitBase:
		signal := status.ExitCode - signalExitBase
		return ExitSignal, fmt.Sprintf("killed by %s (exit %d)",
			signalName(signal), status.ExitCode)

	default:
		return ExitError, fmt.Sprintf("exited with code %d", status.ExitCode)
	}
}

// oomMessage names the ceiling that was actually hit. The distinction is the
// whole point of carrying MemoryLimit: since v1.58 an omitted `resources` block
// means unbounded (R11), so the common OOM is now the *collective* ceiling
// (§5.2.11) — and "raise this service's limit" is the wrong advice for it.
func oomMessage(status runtime.Status) string {
	if status.MemoryLimit == 0 {
		return "out of memory under the node's workload ceiling — no limit declared"
	}
	return fmt.Sprintf("exceeded its %s memory limit", mebibytes(status.MemoryLimit))
}

func signalName(signal uint32) string {
	if name, ok := signalNames[signal]; ok {
		return name
	}
	return fmt.Sprintf("signal %d", signal)
}

// mebibytes renders a byte count the way R11 declares one, so the message reads
// back as the number an operator would type into `resources.memory`.
func mebibytes(n uint64) string {
	const mib = 1 << 20
	if n >= 1<<30 && n%(1<<30) == 0 {
		return fmt.Sprintf("%d GiB", n>>30)
	}
	return fmt.Sprintf("%d MiB", (n+mib-1)/mib)
}

// crashMessage renders a crash for the notification body. It falls back to the
// bare exit code for a record written before v1.68 carried a reason — those
// keep meaning exactly what they meant.
func crashMessage(record AllocRecord) string {
	if record.LastExitMessage == "" {
		return fmt.Sprintf("alloc %d exited with code %d", record.Index, record.LastExitCode)
	}
	if record.LastExitReason == ExitOOMKilled {
		return fmt.Sprintf("alloc %d OOM-killed: %s", record.Index, record.LastExitMessage)
	}
	return fmt.Sprintf("alloc %d %s", record.Index, record.LastExitMessage)
}

// applyPhase names where on the create path an alloc failed. It exists so the
// reason is structural rather than a match against an error string: the phases
// and the `return`s in create() are the same list, and a new step that forgets
// to name itself fails to compile into a reason rather than silently reporting
// the previous step's.
type applyPhase struct {
	reason ExitReason
	what   string
}

var (
	phaseImage       = applyPhase{ExitImageFailed, "image"}
	phaseVolume      = applyPhase{ExitVolumeFailed, "volumes"}
	phasePassthrough = applyPhase{ExitPassthroughFailed, "grants"}
	phaseNetwork     = applyPhase{ExitNetworkFailed, "network"}
	phaseCreate      = applyPhase{ExitCreateFailed, "create"}
	phaseStart       = applyPhase{ExitStartFailed, "start"}
)

// applyError carries the phase alongside the cause, so the reconcile loop can
// record *why* an alloc never started without re-parsing the error text.
type applyError struct {
	phase applyPhase
	err   error
}

func (e *applyError) Error() string { return e.phase.what + ": " + e.err.Error() }
func (e *applyError) Unwrap() error { return e.err }

// failedAt wraps a create-path failure with its phase.
func failedAt(phase applyPhase, err error) error {
	return &applyError{phase: phase, err: err}
}

// startFailure classifies an apply error for the record. A failure that is not
// on the create path (a stop, a scale-in) has no phase and no reason: those are
// retried without ever having been an alloc's own problem.
func startFailure(err error) (ExitReason, string, bool) {
	var applyErr *applyError
	if !errors.As(err, &applyErr) {
		return "", "", false
	}
	return applyErr.phase.reason, truncateMessage(applyErr.err.Error()), true
}

// maxExitMessage bounds what reaches the record. The text can carry a registry
// or containerd error, which is attacker-influencable in length if not in
// content (an image reference comes from a spec), and this field is replicated
// and rendered in a table.
const maxExitMessage = 300

func truncateMessage(s string) string {
	if len(s) <= maxExitMessage {
		return s
	}
	// The ellipsis is three bytes, and the budget is in bytes. Cut back to a
	// rune boundary as well: a message sliced mid-rune renders as a
	// replacement character, which looks like corruption rather than a cut.
	cut := maxExitMessage - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
