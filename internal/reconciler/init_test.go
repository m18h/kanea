package reconciler_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/store"
)

// withInit returns desired(count) carrying an init sequence.
func withInit(count int, names ...string) reconciler.Desired {
	d := desired(count)
	for _, n := range names {
		d.Init = append(d.Init, reconciler.InitContainer{
			Name:  n,
			Image: "registry.example.com/shop/" + n + ":1",
		})
	}
	return d
}

// initID is the container id of one step of shop/web-<index>.
func initID(index, ordinal int, name string) string {
	return runtime.InitID(reconciler.AllocID("shop", "web", index), ordinal, name)
}

// initStatus builds the world entry for one step.
func initStatus(index, ordinal int, name string, state runtime.State, code uint32) reconciler.InitStatus {
	id := initID(index, ordinal, name)
	return reconciler.InitStatus{
		Status: runtime.Status{
			ID: id, State: state, ExitCode: code, Role: runtime.RoleInit,
		},
		Project: "shop",
		AllocID: reconciler.AllocID("shop", "web", index),
	}
}

// initWorld builds a world for one alloc part-way through its sequence.
func initWorld(d reconciler.Desired, rec reconciler.AllocRecord, steps ...reconciler.InitStatus) reconciler.World {
	w := reconciler.World{
		Desired:    []reconciler.Desired{d},
		Records:    map[string]reconciler.AllocRecord{rec.ID: rec},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}
	for _, s := range steps {
		w.InitActual[s.ID] = s
	}
	return w
}

// initRecord is an alloc sitting on one step of its sequence.
func initRecord(index, ordinal int, name string, started time.Time) reconciler.AllocRecord {
	rec := record(index, reconciler.AllocInit)
	rec.InitStep, rec.InitName, rec.InitStartedAt = ordinal, name, started
	return rec
}

// --- upgrade safety -------------------------------------------------------
//
// These are the tests that stop an upgrade rolling a fleet. They are first
// because they are the ones whose failure costs somebody a night.

// TestAServiceWithoutInitSerializesUnchanged pins the R23 rule on both new
// fields. A Desired that declares neither must marshal exactly as it did
// before v1.84, or every SpecHash on every node changes and upgrading kanead
// replaces every container on it.
func TestAServiceWithoutInitSerializesUnchanged(t *testing.T) {
	body, err := json.Marshal(desired(1))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"init"`, `"pull_policy"`} {
		if strings.Contains(string(body), key) {
			t.Errorf("a service declaring no init containers serialized %s;\n"+
				"the field needs omitempty, or upgrading kanead re-hashes and rolls "+
				"every alloc on the node (the R23 lesson)\n%s", key, body)
		}
	}
}

// TestAPreV1RecordCarriesNoInitKeys is the same rule for AllocRecord, which is
// CDC-replicated and is the API's wire format directly.
func TestAPreV1RecordCarriesNoInitKeys(t *testing.T) {
	body, err := json.Marshal(record(0, reconciler.AllocRunning))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"init_step"`, `"init_name"`, `"init_started_at"`} {
		if strings.Contains(string(body), key) {
			t.Errorf("an alloc record that never ran an init sequence serialized %s;\n"+
				"every one of these needs omitempty/omitzero\n%s", key, body)
		}
	}
}

// TestPullPolicyIsNotSpecHashMaterial: where an image may be fetched from is
// not baked into a container, so flipping it must not roll a service. Same
// call as Expose, Publish, trigger config and R31's budget.
func TestPullPolicyIsNotSpecHashMaterial(t *testing.T) {
	base := withInit(1, "migrate")
	before := reconciler.SpecHash(base)

	changed := base
	changed.PullPolicy = runtime.PullNever
	changed.Init = []reconciler.InitContainer{{
		Name:       base.Init[0].Name,
		Image:      base.Init[0].Image,
		PullPolicy: runtime.PullNever,
		Timeout:    5 * time.Minute,
	}}
	if got := reconciler.SpecHash(changed); got != before {
		t.Errorf("changing pull_policy and timeout rolled the alloc:\n"+
			"  before %s\n  after  %s\n"+
			"neither is container state; hashableInit must strip both", before, got)
	}
}

// TestChangingAnInitContainerRollsTheAlloc is the other half: everything about
// a step that *is* baked into a container has to be in the material, or a
// changed migration would never be run.
func TestChangingAnInitContainerRollsTheAlloc(t *testing.T) {
	base := withInit(1, "migrate")
	before := reconciler.SpecHash(base)

	cases := map[string]func(*reconciler.InitContainer){
		"image":   func(i *reconciler.InitContainer) { i.Image = "other:2" },
		"command": func(i *reconciler.InitContainer) { i.Command = []string{"/bin/migrate", "down"} },
		"env":     func(i *reconciler.InitContainer) { i.Env = map[string]string{"A": "b"} },
		"user":    func(i *reconciler.InitContainer) { i.User = &runtime.User{UID: 999, GID: 999} },
		"caps":    func(i *reconciler.InitContainer) { i.Capabilities = []string{"CAP_CHOWN"} },
		"cpu":     func(i *reconciler.InitContainer) { i.Resources.CPUMillis = 500 },
		"name":    func(i *reconciler.InitContainer) { i.Name = "renamed" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.Init = []reconciler.InitContainer{base.Init[0]}
			mutate(&changed.Init[0])
			if reconciler.SpecHash(changed) == before {
				t.Errorf("changing an init container's %s did not roll the alloc; "+
					"it is baked into a container and belongs in the SpecHash material", name)
			}
		})
	}
}

// TestAddingAnInitContainerRollsTheAlloc: adding a step to a service that had
// none is a new container, so it rolls.
func TestAddingAnInitContainerRollsTheAlloc(t *testing.T) {
	if reconciler.SpecHash(withInit(1, "migrate")) == reconciler.SpecHash(desired(1)) {
		t.Error("adding an init container did not change the spec hash")
	}
}

// --- the planner's transition table ---------------------------------------

func TestPlanStartsTheFirstInitContainer(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	got := reconciler.Plan(reconciler.World{
		Desired:    []reconciler.Desired{d},
		Records:    map[string]reconciler.AllocRecord{},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	})
	if len(got) != 1 || got[0].Kind != reconciler.ActionCreate {
		t.Fatalf("first pass should create the alloc, got %s", kinds(got))
	}
	if got[0].Init != nil {
		t.Errorf("a first create must carry no init marker, or it would skip the sequence")
	}
}

// TestPlanWaitsWhileAnInitContainerRuns is the property the whole design turns
// on: a running step costs no action and no Store write, so a five-minute
// migration does not stall the pass or churn the Store.
func TestPlanWaitsWhileAnInitContainerRuns(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	rec := initRecord(0, 0, "migrate", testNow.Add(-30*time.Second))
	w := initWorld(d, rec, initStatus(0, 0, "migrate", runtime.StateRunning, 0))

	got := reconciler.Plan(w)
	if len(got) != 1 || got[0].Kind != reconciler.ActionWait {
		t.Fatalf("a running init step should produce a wait, got %s", kinds(got))
	}
	if !strings.Contains(got[0].Reason, "migrate") {
		t.Errorf("the wait must name the step; got %q", got[0].Reason)
	}
	if changed := reconciler.Observe(w); len(changed) != 0 {
		t.Errorf("observing a running init step wrote %d record(s); "+
			"steady state must cost nothing (constraint #2)", len(changed))
	}
}

func TestPlanAdvancesToTheNextInitContainer(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	rec := initRecord(0, 0, "migrate", testNow.Add(-30*time.Second))
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateStopped, 0)))

	if len(got) != 1 || got[0].Kind != reconciler.ActionInitStep {
		t.Fatalf("a completed step should advance, got %s", kinds(got))
	}
	if got[0].Init == nil || got[0].Init.Ordinal != 1 || got[0].Init.Name != "seed" {
		t.Fatalf("expected step 1 (seed), got %+v", got[0].Init)
	}
	if got[0].Init.Op != reconciler.InitStart {
		t.Errorf("op = %q, want %q", got[0].Init.Op, reconciler.InitStart)
	}
}

// TestPlanCreatesTheTaskAfterTheLastInitContainer, and marks the create so it
// does not start the sequence over.
func TestPlanCreatesTheTaskAfterTheLastInitContainer(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	rec := initRecord(0, 1, "seed", testNow.Add(-time.Minute))
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateStopped, 0),
		initStatus(0, 1, "seed", runtime.StateStopped, 0)))

	if len(got) != 1 || got[0].Kind != reconciler.ActionCreate {
		t.Fatalf("a completed sequence should create the task, got %s", kinds(got))
	}
	if got[0].Init == nil || got[0].Init.Op != reconciler.InitDone {
		t.Fatalf("the create must be marked done, or create() restarts the sequence: %+v", got[0].Init)
	}
}

// TestPlanAdoptsARunningStepTheRecordDoesNotName is the crash window: kanead
// died between starting a step and persisting the record that names it.
// Reading the record would plan a create for a container that already exists,
// which fails ErrAlreadyExists on every pass forever.
func TestPlanAdoptsARunningStepTheRecordDoesNotName(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	rec := initRecord(0, 0, "migrate", testNow.Add(-time.Minute))
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateStopped, 0),
		initStatus(0, 1, "seed", runtime.StateRunning, 0)))

	if len(got) != 1 || got[0].Kind != reconciler.ActionInitStep {
		t.Fatalf("expected an init step action, got %s", kinds(got))
	}
	if got[0].Init.Op != reconciler.InitAdopt || got[0].Init.Name != "seed" {
		t.Fatalf("expected an adopt of seed, got %+v", got[0].Init)
	}
}

// TestASpecChangeAbandonsAHalfRunSequence: a deploy must not wait out the old
// spec's migrations before noticing it is a deploy.
func TestASpecChangeAbandonsAHalfRunSequence(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	rec := initRecord(0, 0, "migrate", testNow.Add(-time.Second))
	rec.SpecHash = "a-different-spec"
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateRunning, 0)))

	if len(got) != 1 || got[0].Kind != reconciler.ActionRestart {
		t.Fatalf("a stale alloc mid-init should restart, got %s", kinds(got))
	}
}

// --- the sweep ------------------------------------------------------------

// TestInitContainersAreNotOrphans is the regression that matters most. An init
// container has no alloc record, so a planner that saw one in Actual would
// destroy a running migration on the pass after it started.
func TestInitContainersAreNotOrphans(t *testing.T) {
	d := withInit(1, "migrate")
	rec := initRecord(0, 0, "migrate", testNow.Add(-time.Second))
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateRunning, 0)))

	for _, a := range got {
		if a.Kind == reconciler.ActionRemove || a.Kind == reconciler.ActionRemoveInit {
			t.Fatalf("a running init container was planned for removal: %s %s (%s)",
				a.Kind, a.AllocID, a.Reason)
		}
	}
}

// TestCompletedStepsSurviveUntilTheTaskStarts: they are the evidence that they
// ran, and reaping them before the task is created would make the next pass
// start the sequence over.
func TestCompletedStepsSurviveUntilTheTaskStarts(t *testing.T) {
	d := withInit(1, "migrate", "seed")
	rec := initRecord(0, 1, "seed", testNow.Add(-time.Second))
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateStopped, 0),
		initStatus(0, 1, "seed", runtime.StateRunning, 0)))

	for _, a := range got {
		if a.Kind == reconciler.ActionRemoveInit {
			t.Fatalf("a completed step was reaped mid-sequence: %s (%s)", a.AllocID, a.Reason)
		}
	}
}

// TestLeftoverInitContainersAreReaped covers the four cases the sweep exists
// for, driven by what is on the node rather than by the spec's list.
func TestLeftoverInitContainersAreReaped(t *testing.T) {
	t.Run("the alloc is running", func(t *testing.T) {
		d := withInit(1, "migrate")
		rec := record(0, reconciler.AllocRunning)
		rec.SpecHash = reconciler.SpecHash(d)
		w := initWorld(d, rec, initStatus(0, 0, "migrate", runtime.StateStopped, 0))
		w.Actual[rec.ID] = running(rec.ID)

		if !plannedRemoveInit(reconciler.Plan(w), initID(0, 0, "migrate")) {
			t.Error("a finished sequence's containers must be reaped once the task is up")
		}
	})

	t.Run("the step was renamed away", func(t *testing.T) {
		d := withInit(1, "migrate")
		rec := initRecord(0, 0, "migrate", testNow)
		// A container from a step this spec no longer declares.
		stale := initStatus(0, 0, "seed", runtime.StateStopped, 0)
		w := initWorld(d, rec,
			initStatus(0, 0, "migrate", runtime.StateRunning, 0), stale)

		if !plannedRemoveInit(reconciler.Plan(w), stale.ID) {
			t.Error("a container for an undeclared step must be reaped")
		}
	})

	t.Run("the alloc has no record", func(t *testing.T) {
		d := withInit(1, "migrate")
		w := reconciler.World{
			Desired: []reconciler.Desired{d},
			Records: map[string]reconciler.AllocRecord{},
			Actual:  map[string]runtime.Status{},
			InitActual: map[string]reconciler.InitStatus{
				initID(0, 0, "migrate"): initStatus(0, 0, "migrate", runtime.StateStopped, 0),
			},
			Now: testNow,
		}
		if !plannedRemoveInit(reconciler.Plan(w), initID(0, 0, "migrate")) {
			t.Error("a container whose alloc has no record must be reaped")
		}
	})
}

func plannedRemoveInit(actions []reconciler.Action, id string) bool {
	for _, a := range actions {
		if a.Kind == reconciler.ActionRemoveInit && a.AllocID == id {
			return true
		}
	}
	return false
}

// --- the failure taxonomy -------------------------------------------------

// TestAFailedInitContainerSpendsTheRestartBudget. It ran and failed, so unlike
// a create-path failure it is a crash: R29's escalating backoff applies and a
// broken migration stops hammering the database after `attempts`.
func TestAFailedInitContainerSpendsTheRestartBudget(t *testing.T) {
	d := withInit(1, "migrate")
	rec := initRecord(0, 0, "migrate", testNow.Add(-time.Second))
	w := initWorld(d, rec, initStatus(0, 0, "migrate", runtime.StateStopped, 2))

	changed := reconciler.Observe(w)
	got, ok := changed[rec.ID]
	if !ok {
		t.Fatal("a non-zero init exit produced no record change")
	}
	if got.State != reconciler.AllocBackoff {
		t.Errorf("state = %q, want %q", got.State, reconciler.AllocBackoff)
	}
	if got.LastExitReason != reconciler.ExitInitFailed {
		t.Errorf("reason = %q, want %q", got.LastExitReason, reconciler.ExitInitFailed)
	}
	if got.LastExitCode != 2 {
		t.Errorf("exit code = %d, want 2", got.LastExitCode)
	}
	if !strings.Contains(got.LastExitMessage, "migrate") {
		t.Errorf("the message must name the step; got %q", got.LastExitMessage)
	}
	if got.NextRestartAt.IsZero() {
		t.Error("no backoff was armed; the budget was not spent")
	}
}

// TestAnExhaustedInitBudgetFailsTheAlloc: after `attempts`, stop.
func TestAnExhaustedInitBudgetFailsTheAlloc(t *testing.T) {
	d := withInit(1, "migrate")
	rec := initRecord(0, 0, "migrate", testNow.Add(-time.Second))
	rec.Restarts = d.Restart.Attempts
	if rec.Restarts == 0 {
		rec.Restarts = 5 // the platform default
	}
	changed := reconciler.Observe(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateStopped, 1)))

	if got := changed[rec.ID].State; got != reconciler.AllocFailed {
		t.Errorf("state = %q, want %q after the budget is spent", got, reconciler.AllocFailed)
	}
}

// TestARestartAfterAnInitFailureCountsAgainstTheBudget is the defect this test
// is named for: an alloc that failed during init has no main container, so the
// !isActual path would emit ActionCreate - and create() increments Restarts
// only for ActionRestart, so the budget would never be spent and a broken
// migration would retry forever.
func TestARestartAfterAnInitFailureCountsAgainstTheBudget(t *testing.T) {
	d := withInit(1, "migrate")
	rec := record(0, reconciler.AllocBackoff)
	rec.SpecHash = reconciler.SpecHash(d)
	rec.LastExitReason = reconciler.ExitInitFailed
	rec.InitName, rec.Restarts = "migrate", 1
	rec.NextRestartAt = testNow.Add(-time.Second) // elapsed

	w := initWorld(d, rec)
	got := reconciler.Plan(w)
	if len(got) != 1 {
		t.Fatalf("expected one action, got %s", kinds(got))
	}
	if got[0].Kind != reconciler.ActionRestart {
		t.Fatalf("kind = %q, want %q: an ActionCreate here never increments Restarts, "+
			"so a failing migration would retry without bound",
			got[0].Kind, reconciler.ActionRestart)
	}
}

// TestAnInitTimeoutIsAKillNotAGap. A hang is the workload failing, and if
// anything a stronger signal than a non-zero exit.
func TestAnInitTimeoutIsAKillNotAGap(t *testing.T) {
	d := withInit(1, "migrate")
	d.Init[0].Timeout = time.Minute
	rec := initRecord(0, 0, "migrate", testNow.Add(-2*time.Minute))

	changed := reconciler.Observe(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateRunning, 0)))
	got, ok := changed[rec.ID]
	if !ok {
		t.Fatal("a step past its timeout produced no record change")
	}
	if got.LastExitReason != reconciler.ExitInitTimeout {
		t.Errorf("reason = %q, want %q", got.LastExitReason, reconciler.ExitInitTimeout)
	}
	// A timeout has no exit code we chose: absent is honest, zero would read
	// as a clean exit.
	if got.LastExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (absent): we killed it, so there is no code",
			got.LastExitCode)
	}
	if !strings.Contains(got.LastExitMessage, "timeout") {
		t.Errorf("the message must say it timed out; got %q", got.LastExitMessage)
	}
}

// TestAnUndeclaredTimeoutNeverFires: absent means no timeout (R11's rule), not
// zero. A step with no bound may run as long as it takes.
func TestAnUndeclaredTimeoutNeverFires(t *testing.T) {
	d := withInit(1, "migrate") // no Timeout
	rec := initRecord(0, 0, "migrate", testNow.Add(-72*time.Hour))

	if changed := reconciler.Observe(initWorld(d, rec,
		initStatus(0, 0, "migrate", runtime.StateRunning, 0))); len(changed) != 0 {
		t.Errorf("a step with no declared timeout was timed out after 72h; "+
			"absent is no timeout, never zero (R11): %+v", changed)
	}
}

// --- crash recovery -------------------------------------------------------

// TestAResumedSequenceDoesNotRerunFinishedSteps. kanead restarts while step 2
// of 3 is running: the next pass must wait, not start over. This is why
// completed containers are kept as evidence.
func TestAResumedSequenceDoesNotRerunFinishedSteps(t *testing.T) {
	d := withInit(1, "one", "two", "three")
	rec := initRecord(0, 1, "two", testNow.Add(-10*time.Second))
	got := reconciler.Plan(initWorld(d, rec,
		initStatus(0, 0, "one", runtime.StateStopped, 0),
		initStatus(0, 1, "two", runtime.StateRunning, 0)))

	if len(got) != 1 || got[0].Kind != reconciler.ActionWait {
		t.Fatalf("a resumed sequence should wait on the live step, got %s", kinds(got))
	}
	if !strings.Contains(got[0].Reason, "two") {
		t.Errorf("the wait should name the live step; got %q", got[0].Reason)
	}
}

// TestARunningTaskClearsTheInitBookkeeping is the other crash window: kanead
// died between starting the task and writing the record.
func TestARunningTaskClearsTheInitBookkeeping(t *testing.T) {
	d := withInit(1, "migrate")
	rec := initRecord(0, 0, "migrate", testNow.Add(-time.Minute))
	rec.SpecHash = reconciler.SpecHash(d)
	w := initWorld(d, rec, initStatus(0, 0, "migrate", runtime.StateStopped, 0))
	w.Actual[rec.ID] = running(rec.ID)

	got, ok := reconciler.Observe(w)[rec.ID]
	if !ok {
		t.Fatal("a running task beside an init record produced no change")
	}
	if got.State != reconciler.AllocRunning {
		t.Errorf("state = %q, want %q", got.State, reconciler.AllocRunning)
	}
	if got.InitName != "" || !got.InitStartedAt.IsZero() {
		t.Errorf("a running alloc still points at a step: %q started %s",
			got.InitName, got.InitStartedAt)
	}
}

// --- container identity ---------------------------------------------------

// TestAnInitIDCanNeverBeAnAllocID is the collision argument. With a dash
// separator, an init block named "1" on alloc "shop-web-0" would yield
// "shop-web-0-init-0-1", a well-formed alloc id for project "shop", service
// "web-0-init-0", index 1 - and World.Actual is keyed by id.
func TestAnInitIDCanNeverBeAnAllocID(t *testing.T) {
	id := runtime.InitID(reconciler.AllocID("shop", "web", 0), 0, "1")
	if !strings.Contains(id, ".") {
		t.Fatalf("init id %q contains no dot; alloc ids and init ids would share a namespace", id)
	}
	allocID, ok := runtime.AllocIDOf(id)
	if !ok || allocID != "shop-web-0" {
		t.Errorf("AllocIDOf(%q) = %q, %v; want shop-web-0, true", id, allocID, ok)
	}
	if _, ok := runtime.AllocIDOf("shop-web-0"); ok {
		t.Error("an ordinary alloc id was read as an init container id")
	}
}

// TestTheFirstInitFailureAlreadyCountsAgainstTheBudget is the same defect one
// attempt earlier, and the one a `Restarts > 0` guard would let through.
//
// Observe records an init failure and arms the backoff but never increments
// Restarts - create does, and only for ActionRestart. So the *first* retry has
// to be an ActionRestart too, or the counter never leaves zero and a broken
// migration retries forever at the shortest backoff.
func TestTheFirstInitFailureAlreadyCountsAgainstTheBudget(t *testing.T) {
	d := withInit(1, "migrate")
	rec := record(0, reconciler.AllocBackoff)
	rec.SpecHash = reconciler.SpecHash(d)
	rec.LastExitReason = reconciler.ExitInitFailed
	rec.InitName = "migrate"
	rec.Restarts = 0                              // never retried
	rec.NextRestartAt = testNow.Add(-time.Second) // the delay has elapsed

	got := reconciler.Plan(initWorld(d, rec))
	if len(got) != 1 || got[0].Kind != reconciler.ActionRestart {
		t.Fatalf("kind = %s, want %s on the first retry after an init failure",
			kinds(got), reconciler.ActionRestart)
	}
	if !strings.Contains(got[0].Reason, "attempt 1") {
		t.Errorf("the reason should name the attempt; got %q", got[0].Reason)
	}
}

// TestAnInitBackoffIsHonoured: the delay Observe armed must actually be waited
// out, or the escalating schedule is decoration.
func TestAnInitBackoffIsHonoured(t *testing.T) {
	d := withInit(1, "migrate")
	rec := record(0, reconciler.AllocBackoff)
	rec.SpecHash = reconciler.SpecHash(d)
	rec.LastExitReason = reconciler.ExitInitFailed
	rec.InitName = "migrate"
	rec.NextRestartAt = testNow.Add(30 * time.Second) // not yet

	if got := reconciler.Plan(initWorld(d, rec)); len(got) != 0 {
		t.Fatalf("an alloc still in its init backoff was acted on: %s", kinds(got))
	}
}

// --- the loop, end to end ------------------------------------------------
//
// The two tests below drive the real Reconcile loop rather than the planner
// alone, because the defect this feature is most exposed to lives *between*
// them: Observe arms a backoff without incrementing Restarts, and the write
// that spends the budget is create()'s - which a service with init containers
// never reaches, since the sequence starts and the pass returns. A pure
// planner test cannot see that, and did not.

// allocOf reads one alloc record straight out of the Store.
func allocOf(t *testing.T, h *harness, index int) reconciler.AllocRecord {
	t.Helper()
	rec, _, err := store.GetValue[reconciler.AllocRecord](context.Background(), h.store,
		store.KindAlloc, reconciler.AllocKey("shop", "web", index))
	if err != nil {
		t.Fatalf("load alloc record: %v", err)
	}
	return rec
}

func TestAnInitSequenceRunsToCompletionOnePassAtATime(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	d.Init = []reconciler.InitContainer{
		{Name: "one", Image: "busybox:1"},
		{Name: "two", Image: "busybox:2"},
	}
	h.setDesired(t, d)
	allocID := reconciler.AllocID("shop", "web", 0)

	// Pass 1: shared setup, then step one starts. The task does not exist.
	h.reconcile(t)
	if rec := allocOf(t, h, 0); rec.State != reconciler.AllocInit || rec.InitName != "one" {
		t.Fatalf("after pass 1: state %q step %q, want init/one", rec.State, rec.InitName)
	}
	if _, exists := h.driver.allocs[allocID]; exists {
		t.Fatal("the task was created before the sequence finished")
	}

	// Pass 2: step one is still running, so the pass asks the driver for
	// nothing. (ActionWait itself counts as "applied" - it always has, for
	// dependency waits - so the claim worth asserting is that no container
	// work happened, not that no action was emitted.)
	before := len(h.driver.calls)
	h.reconcile(t)
	for _, call := range h.driver.calls[before:] {
		if strings.HasPrefix(call, "create:") || strings.HasPrefix(call, "start:") {
			t.Errorf("a running step provoked %q; the pass must wait, not act", call)
		}
	}

	// Pass 3: step one exited zero, step two starts.
	h.driver.exit(runtime.InitID(allocID, 0, "one"), 0)
	h.reconcile(t)
	if rec := allocOf(t, h, 0); rec.InitName != "two" {
		t.Fatalf("after step one completed: step %q, want two", rec.InitName)
	}

	// Pass 4: the sequence is done, so the task is finally created - and the
	// record stops pointing at a step.
	h.driver.exit(runtime.InitID(allocID, 1, "two"), 0)
	h.reconcile(t)
	rec := allocOf(t, h, 0)
	if rec.State != reconciler.AllocRunning {
		t.Fatalf("after the sequence: state %q, want running", rec.State)
	}
	if rec.InitName != "" || !rec.InitStartedAt.IsZero() {
		t.Errorf("a running alloc still points at step %q", rec.InitName)
	}
	if _, exists := h.driver.allocs[allocID]; !exists {
		t.Fatal("the task was never created")
	}

	// Pass 5: with the task up, the finished steps are swept - they were the
	// evidence, and they are not needed once the alloc is running.
	h.reconcile(t)
	for _, name := range []string{"one", "two"} {
		for ordinal := range 2 {
			if _, exists := h.driver.allocs[runtime.InitID(allocID, ordinal, name)]; exists &&
				name == d.Init[ordinal].Name {
				t.Errorf("init container %q survived the task starting", name)
			}
		}
	}
}

// TestAFailingInitSequenceExhaustsTheRestartBudget is the one that matters. It
// walks the whole loop: fail, back off, retry, fail again - and asserts the
// counter actually moves and the alloc eventually stops being retried.
func TestAFailingInitSequenceExhaustsTheRestartBudget(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	d.Init = []reconciler.InitContainer{{Name: "migrate", Image: "migrate:1"}}
	d.Restart = reconciler.RestartPolicy{Attempts: 2, Backoff: []time.Duration{time.Second}}
	h.setDesired(t, d)
	allocID := reconciler.AllocID("shop", "web", 0)
	stepID := runtime.InitID(allocID, 0, "migrate")

	fail := func() {
		h.driver.exit(stepID, 1)
		h.reconcile(t)                      // Observe records the failure, arms the backoff
		h.now = h.now.Add(10 * time.Second) // let it elapse
		h.reconcile(t)                      // the retry
	}

	h.reconcile(t) // pass 1: step starts
	if rec := allocOf(t, h, 0); rec.Restarts != 0 {
		t.Fatalf("Restarts = %d before any failure, want 0", rec.Restarts)
	}

	fail()
	rec := allocOf(t, h, 0)
	if rec.LastExitReason != reconciler.ExitInitFailed {
		t.Fatalf("reason = %q, want %q", rec.LastExitReason, reconciler.ExitInitFailed)
	}
	if rec.Restarts != 1 {
		t.Fatalf("Restarts = %d after one failure and one retry, want 1.\n"+
			"A counter stuck at zero means a broken migration retries forever: "+
			"Observe arms the backoff but never increments, and create()'s own "+
			"record write is never reached when a sequence starts", rec.Restarts)
	}

	fail()
	if rec := allocOf(t, h, 0); rec.Restarts != 2 {
		t.Fatalf("Restarts = %d after two failures, want 2", rec.Restarts)
	}

	// Budget spent: the alloc is failed and left alone.
	h.driver.exit(stepID, 1)
	h.reconcile(t)
	if rec := allocOf(t, h, 0); rec.State != reconciler.AllocFailed {
		t.Fatalf("state = %q after the budget is spent, want failed", rec.State)
	}
	h.now = h.now.Add(time.Hour)
	if res := h.reconcile(t); res.Applied != 0 {
		t.Errorf("a failed alloc was acted on %d time(s); it must be left alone "+
			"until a new spec hash arrives (R29)", res.Applied)
	}
}

// --- once per service (v1.92) ---------------------------------------------
//
// The sequence belongs to the service, not to each alloc. Creation is not
// budget-gated - only ActionReplace is - so before this a first deploy of
// `count = 3` created three allocs in one pass and ran three migrations at
// once, against the same database.

// actionFor returns the single action planned for one alloc, or fails.
func actionFor(t *testing.T, actions []reconciler.Action, index int) reconciler.Action {
	t.Helper()
	id := reconciler.AllocID("shop", "web", index)
	var found []reconciler.Action
	for _, a := range actions {
		if a.AllocID == id {
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		t.Fatalf("actions for alloc %d = %v, want exactly one (all: %s)", index, found, kinds(actions))
	}
	return found[0]
}

// The headline: one sequence, on alloc 0, and nobody else starts one.
func TestInitRunsOnTheLeaderAloneOnAFirstDeploy(t *testing.T) {
	d := withInit(3, "migrate")
	w := reconciler.World{
		Desired:    []reconciler.Desired{d},
		Records:    map[string]reconciler.AllocRecord{},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}

	actions := reconciler.Plan(w)
	if got := actionFor(t, actions, 0); got.Kind != reconciler.ActionCreate {
		t.Errorf("alloc 0 = %s, want create: the leader runs the sequence", got.Kind)
	}
	for _, index := range []int{1, 2} {
		got := actionFor(t, actions, index)
		if got.Kind != reconciler.ActionWait {
			t.Errorf("alloc %d = %s (%s), want wait: only the leader runs init",
				index, got.Kind, got.Reason)
		}
		if !strings.Contains(got.Reason, "shop-web-0") {
			t.Errorf("alloc %d waits without naming the leader: %q", index, got.Reason)
		}
	}
}

// A follower waits while the leader is mid-sequence, and the reason says which
// step: a service that has not started needs to be able to say why on `ps`.
func TestFollowersWaitNamingTheLiveStep(t *testing.T) {
	d := withInit(2, "migrate", "seed")
	w := initWorld(d, initRecord(0, 1, "seed", testNow.Add(-30*time.Second)),
		initStatus(0, 0, "migrate", runtime.StateStopped, 0),
		initStatus(0, 1, "seed", runtime.StateRunning, 0))

	got := actionFor(t, reconciler.Plan(w), 1)
	if got.Kind != reconciler.ActionWait {
		t.Fatalf("alloc 1 = %s, want wait", got.Kind)
	}
	if !strings.Contains(got.Reason, "seed") {
		t.Errorf("wait reason does not name the live step: %q", got.Reason)
	}
}

// Once the leader is past its sequence, the followers are created - and with
// no init of their own, which is what create() checks the index for.
func TestFollowersAreCreatedOnceTheLeaderIsPastInit(t *testing.T) {
	d := withInit(3, "migrate")
	leader := record(0, reconciler.AllocRunning)
	leader.SpecHash = reconciler.SpecHash(d)

	w := reconciler.World{
		Desired: []reconciler.Desired{d},
		Records: map[string]reconciler.AllocRecord{leader.ID: leader},
		Actual: map[string]runtime.Status{
			leader.ID: running(leader.ID),
		},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}

	for _, index := range []int{1, 2} {
		if got := actionFor(t, reconciler.Plan(w), index); got.Kind != reconciler.ActionCreate {
			t.Errorf("alloc %d = %s (%s), want create", index, got.Kind, got.Reason)
		}
	}
}

// The spec hash is half the test. On a deploy the leader re-runs the new
// spec's sequence, and a follower that only asked "is the leader past init"
// would build its new task against a migration that has not been applied yet.
func TestAFollowerWaitsForTheLeaderToRerunInitAfterADeploy(t *testing.T) {
	d := withInit(2, "migrate")
	leader := record(0, reconciler.AllocRunning)
	leader.SpecHash = "the-previous-spec"

	w := reconciler.World{
		Desired:    []reconciler.Desired{d},
		Records:    map[string]reconciler.AllocRecord{leader.ID: leader},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}

	got := actionFor(t, reconciler.Plan(w), 1)
	if got.Kind != reconciler.ActionWait {
		t.Fatalf("alloc 1 = %s (%s), want wait: the leader is on an older spec",
			got.Kind, got.Reason)
	}
}

// A leader that failed its migration stops the service, visibly. Failing the
// followers too would be a cascade - R10 refuses those for dependencies - and
// would spend their restart budgets on somebody else's failure; leaving them
// unexplained would be worse.
func TestAFailedLeaderStopsTheServiceAndSaysSo(t *testing.T) {
	d := withInit(2, "migrate")
	leader := record(0, reconciler.AllocFailed)
	leader.SpecHash = reconciler.SpecHash(d)
	leader.LastExitReason, leader.InitName = reconciler.ExitInitFailed, "migrate"

	w := reconciler.World{
		Desired:    []reconciler.Desired{d},
		Records:    map[string]reconciler.AllocRecord{leader.ID: leader},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}

	got := actionFor(t, reconciler.Plan(w), 1)
	if got.Kind != reconciler.ActionWait {
		t.Fatalf("alloc 1 = %s, want wait", got.Kind)
	}
	for _, want := range []string{"shop-web-0", "migrate", "failed"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason %q does not carry %q", got.Reason, want)
		}
	}
}

// A single-replica service is the common case and must behave exactly as it
// did: the leader is the only alloc, so nothing waits for anything.
func TestASingleAllocServiceIsUnchanged(t *testing.T) {
	d := withInit(1, "migrate")
	w := reconciler.World{
		Desired:    []reconciler.Desired{d},
		Records:    map[string]reconciler.AllocRecord{},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}

	if got := actionFor(t, reconciler.Plan(w), 0); got.Kind != reconciler.ActionCreate {
		t.Errorf("alloc 0 = %s, want create", got.Kind)
	}
}

// A service with no init blocks is gated by nothing: the follower path must be
// reachable only when there is a sequence to wait for.
func TestAServiceWithoutInitCreatesEveryAllocAtOnce(t *testing.T) {
	w := reconciler.World{
		Desired:    []reconciler.Desired{desired(3)},
		Records:    map[string]reconciler.AllocRecord{},
		Actual:     map[string]runtime.Status{},
		InitActual: map[string]reconciler.InitStatus{},
		Now:        testNow,
	}

	for index := range 3 {
		if got := actionFor(t, reconciler.Plan(w), index); got.Kind != reconciler.ActionCreate {
			t.Errorf("alloc %d = %s, want create", index, got.Kind)
		}
	}
}

// A follower holding an AllocInit record is a leftover from a node upgraded
// mid-sequence, back when init ran per alloc. It must not be planned into a
// sequence of its own; it takes the ordinary follower path.
func TestAFollowerLeftInAllocInitByAnUpgradeDoesNotResumeASequence(t *testing.T) {
	d := withInit(2, "migrate")
	leader := record(0, reconciler.AllocRunning)
	leader.SpecHash = reconciler.SpecHash(d)
	stale := initRecord(1, 0, "migrate", testNow.Add(-time.Minute))

	w := reconciler.World{
		Desired: []reconciler.Desired{d},
		Records: map[string]reconciler.AllocRecord{leader.ID: leader, stale.ID: stale},
		Actual:  map[string]runtime.Status{leader.ID: running(leader.ID)},
		InitActual: map[string]reconciler.InitStatus{
			initID(1, 0, "migrate"): initStatus(1, 0, "migrate", runtime.StateStopped, 0),
		},
		Now: testNow,
	}

	got := actionFor(t, reconciler.Plan(w), 1)
	if got.Kind == reconciler.ActionInitStep {
		t.Fatalf("a follower resumed a per-alloc sequence: %s", got.Reason)
	}
	if got.Kind != reconciler.ActionCreate {
		t.Errorf("alloc 1 = %s (%s), want create", got.Kind, got.Reason)
	}
}
