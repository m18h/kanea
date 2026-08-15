package reconciler_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
)

// oomKill makes a running alloc look like the kernel killed it for memory: the
// same exit 137 a forced stop produces, plus the cgroup evidence that is the
// only thing separating the two.
func (f *fakeDriver) oomKill(id string, at time.Time, limit uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allocs[id] = runtime.Status{
		ID: id, State: runtime.StateStopped, ExitCode: 137, ExitedAt: at,
		OOMKnown: true, OOMKilled: true, MemoryLimit: limit,
	}
}

func TestAnOOMKillIsRecordedAsOne(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	h.driver.oomKill(id, h.now, 256<<20)
	h.reconcile(t)

	rec := h.allocRecord(t, 0)
	if rec.LastExitReason != reconciler.ExitOOMKilled {
		t.Errorf("reason = %q, want %q", rec.LastExitReason, reconciler.ExitOOMKilled)
	}
	if !strings.Contains(rec.LastExitMessage, "256 MiB") {
		t.Errorf("message = %q, want the declared limit named", rec.LastExitMessage)
	}
	// The pre-v1.68 fields keep meaning what they meant.
	if rec.LastExitCode != 137 {
		t.Errorf("last exit code = %d, want 137", rec.LastExitCode)
	}
}

// The same exit code, without the cgroup evidence, must not be reported as a
// memory problem — this is `kanea stop` against a service that ignored its
// SIGTERM, and telling the operator to resize it would be wrong.
func TestAPlainKillIsNotRecordedAsAnOOM(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	h.driver.crash(reconciler.AllocID("shop", "web", 0), 137, h.now)
	h.reconcile(t)

	rec := h.allocRecord(t, 0)
	if rec.LastExitReason != reconciler.ExitSignal {
		t.Errorf("reason = %q, want %q", rec.LastExitReason, reconciler.ExitSignal)
	}
	if strings.Contains(strings.ToLower(rec.LastExitMessage), "memory") {
		t.Errorf("message = %q, want no memory claim", rec.LastExitMessage)
	}
}

// An alloc that never started explains itself rather than sitting at `pending`
// with the cause in a daemon log (PRD v1.68).
func TestAnAllocThatCannotStartRecordsWhy(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	h.setDesired(t, d)
	h.driver.failWith["image:"+d.Image] = errors.New("pull access denied")

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("failed = %d, want 1", res.Failed)
	}

	rec := h.allocRecord(t, 0)
	if rec.LastExitReason != reconciler.ExitImageFailed {
		t.Errorf("reason = %q, want %q", rec.LastExitReason, reconciler.ExitImageFailed)
	}
	if !strings.Contains(rec.LastExitMessage, "pull access denied") {
		t.Errorf("message = %q, want the cause", rec.LastExitMessage)
	}
	// Recording a reason must not invent a state the planner would act on.
	if rec.State != reconciler.AllocPending {
		t.Errorf("state = %q, want pending", rec.State)
	}
}

// The retry is unchanged by all this: the reason is recorded, and the next pass
// tries again exactly as it did before. R29's restart budget is for a workload
// that ran and crashed — spending it on a registry outage would fail a service
// permanently for something on the node's side of the line.
func TestAStartFailureDoesNotSpendTheRestartBudget(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 2}
	h.setDesired(t, d)
	h.driver.failWith["image:"+d.Image] = errors.New("pull access denied")

	for range 5 {
		if _, err := h.r.Reconcile(context.Background()); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	rec := h.allocRecord(t, 0)
	if rec.Restarts != 0 {
		t.Errorf("restarts = %d, want 0 — a start failure is not a crash", rec.Restarts)
	}
	if rec.State == reconciler.AllocFailed {
		t.Error("state = failed: a start failure must stay retryable")
	}

	// And it still recovers on its own once the cause goes away.
	delete(h.driver.failWith, "image:"+d.Image)
	if _, err := h.r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := h.driver.state(reconciler.AllocID("shop", "web", 0)); got != runtime.StateRunning {
		t.Errorf("state = %q, want running", got)
	}
}

// A create that fails fails again every pass. Rewriting an identical record
// each time would turn one typo into a steady stream of Store writes, CDC
// changes and S3 uploads — the v1.44 "an unchanged value is never rewritten"
// rule, which this path has to follow because it runs on a timer.
func TestARepeatedStartFailureIsWrittenOnce(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	h.setDesired(t, d)
	h.driver.failWith["image:"+d.Image] = errors.New("pull access denied")

	if _, err := h.r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	first := h.allocRecord(t, 0)

	h.now = h.now.Add(time.Minute)
	for range 3 {
		if _, err := h.r.Reconcile(context.Background()); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	if got := h.allocRecord(t, 0); !got.UpdatedAt.Equal(first.UpdatedAt) {
		t.Errorf("UpdatedAt moved from %v to %v: the record was rewritten with nothing new to say",
			first.UpdatedAt, got.UpdatedAt)
	}
}

// The explanation must not outlive the problem: once the alloc starts, the
// "image not found" that was true a moment ago is not.
func TestAStartFailureReasonIsClearedOnceTheAllocRuns(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	h.setDesired(t, d)
	h.driver.failWith["image:"+d.Image] = errors.New("pull access denied")

	if _, err := h.r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if rec := h.allocRecord(t, 0); rec.LastExitReason != reconciler.ExitImageFailed {
		t.Fatalf("reason = %q, want the failure recorded first", rec.LastExitReason)
	}

	delete(h.driver.failWith, "image:"+d.Image)
	h.reconcile(t)

	rec := h.allocRecord(t, 0)
	if rec.LastExitReason != "" {
		t.Errorf("reason = %q, want it cleared once the alloc is running", rec.LastExitReason)
	}
	if rec.LastExitMessage != "" {
		t.Errorf("message = %q, want it cleared", rec.LastExitMessage)
	}
}

// A crash reason, unlike a start failure, travels with the exit it explains: an
// alloc that came back after an OOM should still say what happened to it.
func TestACrashReasonSurvivesTheRestart(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 3, Backoff: []time.Duration{time.Second}}
	h.setDesired(t, d)
	h.reconcile(t)

	h.driver.oomKill(reconciler.AllocID("shop", "web", 0), h.now, 64<<20)
	h.reconcile(t)

	h.now = h.now.Add(2 * time.Second)
	h.reconcile(t)

	rec := h.allocRecord(t, 0)
	if rec.State != reconciler.AllocRunning {
		t.Fatalf("state = %q, want running", rec.State)
	}
	if rec.LastExitReason != reconciler.ExitOOMKilled {
		t.Errorf("reason = %q, want the OOM still recorded after the restart",
			rec.LastExitReason)
	}
}
