package reconciler_test

import (
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
)

// settled builds a record for an alloc that has been up long enough to count as
// available: stamped with the given spec, created well before now.
func settled(index int, hash string) reconciler.AllocRecord {
	rec := record(index, reconciler.AllocRunning)
	rec.SpecHash = hash
	rec.Healthy = true
	rec.CreatedAt = testNow.Add(-time.Hour)
	return rec
}

// world builds a World where every alloc of d is running and settled on hash.
func world(d reconciler.Desired, hash string) reconciler.World {
	w := reconciler.World{
		Desired: []reconciler.Desired{d},
		Records: map[string]reconciler.AllocRecord{},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	}
	for i := range d.Count {
		id := reconciler.AllocID(d.Project, d.Service, i)
		w.Records[id] = settled(i, hash)
		w.Actual[id] = running(id)
	}
	return w
}

func TestSpecHashIgnoresWhatDoesNotNeedANewContainer(t *testing.T) {
	base := desired(3)

	// Things that are applied to a running alloc, or to something other than
	// the alloc, must not roll it. A service that changes its replica bounds is
	// not a service that needs new containers.
	unchanged := base
	unchanged.Count = 9
	unchanged.Scaling = &reconciler.ScalingPolicy{Min: 1, Max: 20}
	unchanged.DependsOn = []string{"db"}
	unchanged.Restart = reconciler.RestartPolicy{Attempts: 99}
	unchanged.Update = reconciler.UpdatePolicy{MaxParallel: 4}
	if got, want := reconciler.SpecHash(unchanged), reconciler.SpecHash(base); got != want {
		t.Errorf("spec hash changed for a field that does not need a new container:\n got %s\nwant %s", got, want)
	}

	// Things that are baked in at creation must.
	for name, mutate := range map[string]func(*reconciler.Desired){
		"image":     func(d *reconciler.Desired) { d.Image = "nginx:1.28-alpine" },
		"env":       func(d *reconciler.Desired) { d.Env = map[string]string{"LOG_LEVEL": "debug"} },
		"resources": func(d *reconciler.Desired) { d.Resources.MemoryBytes = 512 << 20 },
		"command":   func(d *reconciler.Desired) { d.Command = []string{"/bin/sh", "-c", "sleep 1"} },
		"ports":     func(d *reconciler.Desired) { d.Ports = []reconciler.Port{{Name: "http", Container: 8080}} },
		"rootfs":    func(d *reconciler.Desired) { d.ReadOnlyRootfs = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if reconciler.SpecHash(changed) == reconciler.SpecHash(base) {
				t.Errorf("spec hash unchanged after %s changed; the deploy would never happen", name)
			}
		})
	}
}

func TestSpecHashIsStableAcrossEnvOrder(t *testing.T) {
	// Two maps built in different orders are the same environment. If the hash
	// disagreed, every reconcile pass would replace every alloc forever.
	a, b := desired(1), desired(1)
	a.Env = map[string]string{"A": "1", "B": "2", "C": "3"}
	b.Env = map[string]string{}
	for _, k := range []string{"C", "B", "A"} {
		b.Env[k] = map[string]string{"A": "1", "B": "2", "C": "3"}[k]
	}
	if reconciler.SpecHash(a) != reconciler.SpecHash(b) {
		t.Fatal("spec hash depends on map insertion order")
	}
}

func TestRunningAllocIsReplacedWhenTheSpecChanges(t *testing.T) {
	old := desired(1)
	w := world(old, reconciler.SpecHash(old))

	// The deploy: a new image against a service that is already running.
	next := old
	next.Image = "nginx:1.28-alpine"
	w.Desired = []reconciler.Desired{next}

	got := reconciler.Plan(w)
	if len(got) != 1 || got[0].Kind != reconciler.ActionReplace {
		t.Fatalf("a changed image did not replace the running alloc: %s", kinds(got))
	}
	if got[0].Reason != "spec changed" {
		t.Errorf("reason = %q, want %q", got[0].Reason, "spec changed")
	}
}

func TestSteadyStateStaysQuietWhenNothingChanged(t *testing.T) {
	d := desired(3)
	if got := reconciler.Plan(world(d, reconciler.SpecHash(d))); len(got) != 0 {
		t.Fatalf("a service that matches its spec produced work: %s", kinds(got))
	}
}

func TestRollingReplacesOneAtATime(t *testing.T) {
	old := desired(3)
	w := world(old, reconciler.SpecHash(old))

	next := old
	next.Image = "nginx:1.28-alpine"
	w.Desired = []reconciler.Desired{next}

	got := reconciler.Plan(w)
	if len(got) != 1 {
		t.Fatalf("default policy replaced %d allocs at once, want 1: %s", len(got), kinds(got))
	}
	// Lowest index first, so a deploy walks the service in a predictable order
	// rather than a map-iteration one.
	if got[0].AllocID != reconciler.AllocID("shop", "web", 0) {
		t.Errorf("replaced %s first, want index 0", got[0].AllocID)
	}
}

func TestRollingWaitsForTheReplacementToSettle(t *testing.T) {
	old := desired(3)
	next := old
	next.Image = "nginx:1.28-alpine"
	newHash := reconciler.SpecHash(next)

	w := world(old, reconciler.SpecHash(old))
	w.Desired = []reconciler.Desired{next}
	// Index 0 has just been replaced: new spec, created a moment ago.
	id := reconciler.AllocID("shop", "web", 0)
	fresh := settled(0, newHash)
	fresh.CreatedAt = testNow.Add(-time.Second)
	w.Records[id] = fresh

	if got := reconciler.Plan(w); len(got) != 0 {
		t.Fatalf("rolled on while the previous replacement was still settling: %s", kinds(got))
	}

	// Once it has been up for min_healthy, the roll continues.
	fresh.CreatedAt = testNow.Add(-reconciler.DefaultMinHealthy - time.Second)
	w.Records[id] = fresh
	got := reconciler.Plan(w)
	if len(got) != 1 || got[0].AllocID != reconciler.AllocID("shop", "web", 1) {
		t.Fatalf("the roll did not continue to index 1: %s", kinds(got))
	}
}

func TestRollingStopsWhenAnAllocIsDown(t *testing.T) {
	old := desired(3)
	next := old
	next.Image = "nginx:1.28-alpine"

	w := world(old, reconciler.SpecHash(old))
	w.Desired = []reconciler.Desired{next}
	// Index 2 is not running at all — a crash mid-deploy. The budget is
	// availability, so it is already spent and no healthy alloc is taken down
	// on top of it.
	delete(w.Actual, reconciler.AllocID("shop", "web", 2))

	for _, act := range reconciler.Plan(w) {
		if act.Kind == reconciler.ActionReplace {
			t.Fatalf("replaced a healthy alloc while %s was down: %s", "index 2", kinds([]reconciler.Action{act}))
		}
	}
}

func TestMaxParallelRaisesTheBudget(t *testing.T) {
	old := desired(4)
	old.Update = reconciler.UpdatePolicy{MaxParallel: 2}
	w := world(old, reconciler.SpecHash(old))

	next := old
	next.Image = "nginx:1.28-alpine"
	w.Desired = []reconciler.Desired{next}

	if got := reconciler.Plan(w); len(got) != 2 {
		t.Fatalf("max_parallel = 2 planned %d replacements: %s", len(got), kinds(got))
	}
}

func TestReplaceStrategyTakesThemAllAtOnce(t *testing.T) {
	old := desired(4)
	old.Update = reconciler.UpdatePolicy{Strategy: reconciler.StrategyReplace}
	w := world(old, reconciler.SpecHash(old))

	next := old
	next.Image = "nginx:1.28-alpine"
	w.Desired = []reconciler.Desired{next}

	if got := reconciler.Plan(w); len(got) != 4 {
		t.Fatalf("replace strategy planned %d of 4 replacements: %s", len(got), kinds(got))
	}
}

func TestUnstampedRecordsAreAdoptedNotRolled(t *testing.T) {
	// The upgrade case: records written before the spec hash existed. Rolling
	// them would replace every alloc on the node the first time the new kanead
	// reconciles, which is the worst possible moment for an outage.
	d := desired(3)
	w := world(d, "")

	if got := reconciler.Plan(w); len(got) != 0 {
		t.Fatalf("unstamped records were rolled on upgrade: %s", kinds(got))
	}

	// Observe adopts them, so the next real deploy is detected.
	changed := reconciler.Observe(w)
	if len(changed) != 3 {
		t.Fatalf("Observe adopted %d of 3 unstamped records", len(changed))
	}
	for id, rec := range changed {
		if rec.SpecHash != reconciler.SpecHash(d) {
			t.Errorf("%s adopted hash %q, want %q", id, rec.SpecHash, reconciler.SpecHash(d))
		}
	}
}

func TestFailedAllocIsRetriedWhenTheSpecChanges(t *testing.T) {
	// Deploying the fix is how a crash loop is resolved. An alloc that spent its
	// restart budget must not be immune to the correction.
	old := desired(1)
	id := reconciler.AllocID("shop", "web", 0)
	rec := record(0, reconciler.AllocFailed)
	rec.SpecHash = reconciler.SpecHash(old)
	rec.Restarts = 5

	next := old
	next.Image = "nginx:1.28-alpine"
	w := reconciler.World{
		Desired: []reconciler.Desired{next},
		Records: map[string]reconciler.AllocRecord{id: rec},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	}

	got := reconciler.Plan(w)
	if len(got) != 1 || got[0].Kind != reconciler.ActionCreate {
		t.Fatalf("a failed alloc was not retried against the new spec: %s", kinds(got))
	}
	if got[0].Reason != "spec changed" {
		t.Errorf("reason = %q, want %q", got[0].Reason, "spec changed")
	}

	// And it stays untouched while the spec is the one that failed.
	w.Desired = []reconciler.Desired{old}
	if got := reconciler.Plan(w); len(got) != 0 {
		t.Fatalf("a failed alloc was retried without a spec change: %s", kinds(got))
	}
}

func TestBackoffIsNotWaitedOutAfterADeploy(t *testing.T) {
	old := desired(1)
	id := reconciler.AllocID("shop", "web", 0)
	rec := record(0, reconciler.AllocBackoff)
	rec.SpecHash = reconciler.SpecHash(old)
	rec.NextRestartAt = testNow.Add(5 * time.Minute)

	next := old
	next.Image = "nginx:1.28-alpine"
	w := reconciler.World{
		Desired: []reconciler.Desired{next},
		Records: map[string]reconciler.AllocRecord{id: rec},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	}

	if got := reconciler.Plan(w); len(got) != 1 || got[0].Kind != reconciler.ActionCreate {
		t.Fatalf("the new spec waited out the old one's backoff: %s", kinds(got))
	}
}
