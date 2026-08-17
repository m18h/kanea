package reconciler

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/m18h/kanea/internal/runtime"
)

func TestClassifyExit(t *testing.T) {
	tests := []struct {
		name        string
		status      runtime.Status
		wantReason  ExitReason
		wantMessage string
	}{
		{
			name: "OOM against a declared limit names the number",
			status: runtime.Status{
				ExitCode: 137, OOMKnown: true, OOMKilled: true, MemoryLimit: 268435456,
			},
			wantReason:  ExitOOMKilled,
			wantMessage: "exceeded its 256 MiB memory limit",
		},
		{
			// R11/v1.58 made unbounded the default, so this is now the common
			// OOM, and "raise the service's limit" is the wrong advice for it.
			name: "OOM with no declared limit names the node ceiling",
			status: runtime.Status{
				ExitCode: 137, OOMKnown: true, OOMKilled: true, MemoryLimit: 0,
			},
			wantReason:  ExitOOMKilled,
			wantMessage: "out of memory under the node's workload ceiling (no limit declared)",
		},
		{
			name:        "an ordinary failure is an error",
			status:      runtime.Status{ExitCode: 1},
			wantReason:  ExitError,
			wantMessage: "exited with code 1",
		},
		{
			name:        "a segfault names the signal",
			status:      runtime.Status{ExitCode: 139, OOMKnown: true},
			wantReason:  ExitSignal,
			wantMessage: "killed by SIGSEGV (exit 139)",
		},
		{
			name:        "an unnamed signal is reported by number",
			status:      runtime.Status{ExitCode: 128 + 42, OOMKnown: true},
			wantReason:  ExitSignal,
			wantMessage: "killed by signal 42 (exit 170)",
		},
		{
			name:        "a clean exit is completed",
			status:      runtime.Status{ExitCode: 0},
			wantReason:  ExitCompleted,
			wantMessage: "exited cleanly",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, message := classifyExit(tc.status)
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if message != tc.wantMessage {
				t.Errorf("message = %q, want %q", message, tc.wantMessage)
			}
		})
	}
}

// The single most important negative case. `kanea stop` on a service that
// ignores SIGTERM produces exit 137 (exactly what an OOM kill produces) so a
// classifier that pattern-matched the code would report every forced stop as a
// memory problem, and an operator would go resize a service that is fine.
func TestAKillIsNotAnOOMWithoutTheCounter(t *testing.T) {
	killed := runtime.Status{ExitCode: 137, OOMKnown: true, OOMKilled: false}

	reason, message := classifyExit(killed)
	if reason != ExitSignal {
		t.Fatalf("reason = %q, want %q", reason, ExitSignal)
	}
	if !strings.Contains(message, "SIGKILL") {
		t.Errorf("message = %q, want it to name SIGKILL", message)
	}
}

// An unreadable cgroup is not evidence either way, and must land on the same
// honest answer rather than on a guess in either direction (§9.2's rule).
func TestAnUnknownCgroupNeverClaimsAnOOM(t *testing.T) {
	unknown := runtime.Status{ExitCode: 137, OOMKnown: false, OOMKilled: true}

	if reason, _ := classifyExit(unknown); reason != ExitSignal {
		t.Errorf("reason = %q, want %q: OOMKilled is meaningless while OOMKnown is false",
			reason, ExitSignal)
	}
}

func TestStartFailureCarriesItsPhase(t *testing.T) {
	tests := []struct {
		phase      applyPhase
		wantReason ExitReason
	}{
		{phaseImage, ExitImageFailed},
		{phaseVolume, ExitVolumeFailed},
		{phasePassthrough, ExitPassthroughFailed},
		{phaseSecrets, ExitSecretsFailed},
		{phaseNetwork, ExitNetworkFailed},
		{phaseCreate, ExitCreateFailed},
		{phaseStart, ExitStartFailed},
	}

	for _, tc := range tests {
		t.Run(string(tc.wantReason), func(t *testing.T) {
			err := failedAt(tc.phase, errors.New("boom"))

			reason, message, ok := startFailure(err)
			if !ok {
				t.Fatal("startFailure did not recognise its own error")
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if message != "boom" {
				t.Errorf("message = %q, want the cause without the phase prefix", message)
			}
		})
	}
}

// A failure off the create path: a teardown, a removal, an unknown action;
// is not the alloc's own problem and must not be written onto its record.
func TestAnUnphasedErrorIsNotAStartFailure(t *testing.T) {
	if _, _, ok := startFailure(errors.New("teardown failed")); ok {
		t.Error("startFailure claimed a plain error")
	}
	if _, _, ok := startFailure(nil); ok {
		t.Error("startFailure claimed a nil error")
	}
}

// The wrapped error stays inspectable: failedAt annotates, it does not replace.
func TestFailedAtPreservesTheCause(t *testing.T) {
	cause := errors.New("no such image")
	err := failedAt(phaseImage, cause)

	if !errors.Is(err, cause) {
		t.Error("errors.Is lost the cause")
	}
	if !strings.Contains(err.Error(), "image") {
		t.Errorf("Error() = %q, want the phase named", err.Error())
	}
}

func TestALongMessageIsBounded(t *testing.T) {
	// Multi-byte, so a naive byte slice would cut a rune in half and the
	// message would render as a replacement character: corruption, where a
	// truncation was meant.
	for _, filler := range []string{"x", "é", "→"} {
		err := failedAt(phaseImage, errors.New(strings.Repeat(filler, 5000)))

		_, message, ok := startFailure(err)
		if !ok {
			t.Fatal("startFailure did not recognise its own error")
		}
		if len(message) > maxExitMessage {
			t.Errorf("%q: message is %d bytes, want at most %d",
				filler, len(message), maxExitMessage)
		}
		if !utf8.ValidString(message) {
			t.Errorf("%q: message was cut mid-rune: %q", filler, message)
		}
	}
}

func TestCrashMessageNamesTheCause(t *testing.T) {
	oom := AllocRecord{
		Index: 2, LastExitCode: 137,
		LastExitReason: ExitOOMKilled, LastExitMessage: "exceeded its 256 MiB memory limit",
	}
	if got, want := crashMessage(oom),
		"alloc 2 OOM-killed: exceeded its 256 MiB memory limit"; got != want {
		t.Errorf("crashMessage = %q, want %q", got, want)
	}

	// A record written before v1.68 has a code and no reason, and still reads
	// exactly as it always did.
	old := AllocRecord{Index: 0, LastExitCode: 1}
	if got, want := crashMessage(old), "alloc 0 exited with code 1"; got != want {
		t.Errorf("crashMessage = %q, want %q", got, want)
	}
}

func TestMebibytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{64 << 20, "64 MiB"},
		{256 << 20, "256 MiB"},
		{2 << 30, "2 GiB"},
		{1536 << 20, "1536 MiB"}, // not a whole GiB: stay in the declared unit
	}
	for _, tc := range tests {
		if got := mebibytes(tc.in); got != tc.want {
			t.Errorf("mebibytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The R23 rule, applied to v1.68's fields: AllocRecord is CDC-replicated, so a
// record written before these fields existed has to serialise byte-identically
// or upgrading kanead ships a change for every alloc on the node.
func TestARecordWithNoExitReasonCarriesNoExitReasonKeys(t *testing.T) {
	record := AllocRecord{
		ID: "shop-web-0", Project: "shop", Service: "web", Index: 0,
		State: AllocRunning, CreatedAt: time.Unix(0, 0).UTC(),
	}

	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"last_exit_reason", "last_exit_message"} {
		if strings.Contains(string(encoded), key) {
			t.Errorf("%s appears in a record that has none: %s", key, encoded)
		}
	}
}
