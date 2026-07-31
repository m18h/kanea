package reconciler_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
)

var testNow = time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

func desired(count int) reconciler.Desired {
	return reconciler.Desired{
		Project: "shop",
		Service: "web",
		Count:   count,
		Image:   "nginx:1.27-alpine",
		Resources: runtime.Resources{
			CPUMillis: 100, MemoryBytes: 256 << 20,
		},
	}
}

func running(id string) runtime.Status {
	return runtime.Status{ID: id, State: runtime.StateRunning, PID: 42}
}

// stopped models the exited alloc that every restart test exercises: index 0
// of shop/web.
func stopped(code uint32) runtime.Status {
	return runtime.Status{
		ID:       reconciler.AllocID("shop", "web", 0),
		State:    runtime.StateStopped,
		ExitCode: code,
		ExitedAt: testNow,
	}
}

func record(index int, state reconciler.AllocState) reconciler.AllocRecord {
	return reconciler.AllocRecord{
		ID:      reconciler.AllocID("shop", "web", index),
		Project: "shop", Service: "web", Index: index, State: state,
	}
}

// kinds summarises a plan for compact assertions.
func kinds(actions []reconciler.Action) string {
	parts := make([]string, 0, len(actions))
	for _, a := range actions {
		parts = append(parts, string(a.Kind)+":"+a.AllocID)
	}
	return strings.Join(parts, " ")
}

func TestPlanCreatesMissingAllocs(t *testing.T) {
	// First deploy: nothing exists, three allocs wanted.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(3)},
		Records: map[string]reconciler.AllocRecord{},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	})

	want := "create:shop-web-0 create:shop-web-1 create:shop-web-2"
	if kinds(got) != want {
		t.Errorf("plan = %q, want %q", kinds(got), want)
	}
}

func TestPlanSteadyStateDoesNothing(t *testing.T) {
	// The common case, and the one that must not churn: everything running.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(2)},
		Records: map[string]reconciler.AllocRecord{
			"shop-web-0": record(0, reconciler.AllocRunning),
			"shop-web-1": record(1, reconciler.AllocRunning),
		},
		Actual: map[string]runtime.Status{
			"shop-web-0": running("shop-web-0"),
			"shop-web-1": running("shop-web-1"),
		},
		Now: testNow,
	})
	if len(got) != 0 {
		t.Errorf("steady state produced actions: %q", kinds(got))
	}
}

func TestPlanStartsCreatedButUnstartedAlloc(t *testing.T) {
	// kanead died between Create and Start; the alloc exists but never ran.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocPending)},
		Actual: map[string]runtime.Status{
			"shop-web-0": {ID: "shop-web-0", State: runtime.StateCreated},
		},
		Now: testNow,
	})
	if kinds(got) != "start:shop-web-0" {
		t.Errorf("plan = %q, want start:shop-web-0", kinds(got))
	}
}

func TestPlanRestartsCrashedAlloc(t *testing.T) {
	rec := record(0, reconciler.AllocBackoff)
	rec.LastExitCode = 137

	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": rec},
		Actual:  map[string]runtime.Status{"shop-web-0": stopped(137)},
		Now:     testNow,
	})
	if kinds(got) != "restart:shop-web-0" {
		t.Fatalf("plan = %q, want restart:shop-web-0", kinds(got))
	}
	// The reason has to answer "why did my container restart".
	if !strings.Contains(got[0].Reason, "137") {
		t.Errorf("reason = %q, want it to mention the exit code", got[0].Reason)
	}
}

func TestPlanRespectsBackoffWindow(t *testing.T) {
	rec := record(0, reconciler.AllocBackoff)
	rec.NextRestartAt = testNow.Add(20 * time.Second)

	world := reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": rec},
		Actual:  map[string]runtime.Status{"shop-web-0": stopped(1)},
		Now:     testNow,
	}
	if got := reconciler.Plan(world); len(got) != 0 {
		t.Errorf("restarted during the backoff window: %q", kinds(got))
	}

	// Once the deadline passes, the restart proceeds.
	world.Now = testNow.Add(21 * time.Second)
	if got := reconciler.Plan(world); kinds(got) != "restart:shop-web-0" {
		t.Errorf("plan after backoff = %q, want restart:shop-web-0", kinds(got))
	}
}

func TestPlanRemovesAllocAfterRestartBudgetExhausted(t *testing.T) {
	// A crash loop must terminate: after the budget, the alloc is removed and
	// (by the executor) marked failed rather than restarted forever.
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 3}

	rec := record(0, reconciler.AllocBackoff)
	rec.Restarts = 3

	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{d},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": rec},
		Actual:  map[string]runtime.Status{"shop-web-0": stopped(1)},
		Now:     testNow,
	})
	if kinds(got) != "remove:shop-web-0" {
		t.Fatalf("plan = %q, want remove:shop-web-0", kinds(got))
	}
	if !strings.Contains(got[0].Reason, "exhausted") {
		t.Errorf("reason = %q, want it to say the budget is exhausted", got[0].Reason)
	}
}

func TestPlanLeavesFailedAllocsAlone(t *testing.T) {
	// Once failed, the reconciler stops trying: retrying forever would hide the
	// failure instead of surfacing it.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocFailed)},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	})
	if len(got) != 0 {
		t.Errorf("failed alloc produced actions: %q", kinds(got))
	}
}

func TestPlanScalesOut(t *testing.T) {
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(3)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocRunning)},
		Actual:  map[string]runtime.Status{"shop-web-0": running("shop-web-0")},
		Now:     testNow,
	})
	if kinds(got) != "create:shop-web-1 create:shop-web-2" {
		t.Errorf("plan = %q", kinds(got))
	}
}

func TestPlanScalesIn(t *testing.T) {
	// Scaling in removes the highest indexes, and says so.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{
			"shop-web-0": record(0, reconciler.AllocRunning),
			"shop-web-1": record(1, reconciler.AllocRunning),
			"shop-web-2": record(2, reconciler.AllocRunning),
		},
		Actual: map[string]runtime.Status{
			"shop-web-0": running("shop-web-0"),
			"shop-web-1": running("shop-web-1"),
			"shop-web-2": running("shop-web-2"),
		},
		Now: testNow,
	})
	if kinds(got) != "remove:shop-web-1 remove:shop-web-2" {
		t.Fatalf("plan = %q", kinds(got))
	}
	for _, a := range got {
		if !strings.Contains(a.Reason, "scaled in") {
			t.Errorf("reason = %q, want it to mention scaling in", a.Reason)
		}
	}
}

func TestPlanRemovesAllocsOfDeletedService(t *testing.T) {
	got := reconciler.Plan(reconciler.World{
		Desired: nil, // service deleted from the spec
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocRunning)},
		Actual:  map[string]runtime.Status{"shop-web-0": running("shop-web-0")},
		Now:     testNow,
	})
	if kinds(got) != "remove:shop-web-0" {
		t.Fatalf("plan = %q", kinds(got))
	}
	if !strings.Contains(got[0].Reason, "no longer declared") {
		t.Errorf("reason = %q", got[0].Reason)
	}
}

func TestPlanRemovesUnknownContainers(t *testing.T) {
	// Drift: a container in Kanea's namespace that no record claims. Someone
	// started it by hand, or a record was lost. Converge to "gone".
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocRunning)},
		Actual: map[string]runtime.Status{
			"shop-web-0": running("shop-web-0"),
			"mystery-1":  running("mystery-1"),
		},
		Now: testNow,
	})
	if kinds(got) != "remove:mystery-1" {
		t.Errorf("plan = %q, want remove:mystery-1", kinds(got))
	}
}

func TestPlanRecreatesAllocDeletedOutOfBand(t *testing.T) {
	// The drift case PRD §5.2.2 calls out: someone deleted the container.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocRunning)},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	})
	if kinds(got) != "create:shop-web-0" {
		t.Errorf("plan = %q, want create:shop-web-0", kinds(got))
	}
}

func TestPlanReplacesAllocInUnexpectedState(t *testing.T) {
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocRunning)},
		Actual: map[string]runtime.Status{
			"shop-web-0": {ID: "shop-web-0", State: runtime.StateUnknown},
		},
		Now: testNow,
	})
	if kinds(got) != "restart:shop-web-0" {
		t.Errorf("plan = %q", kinds(got))
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	// The loop runs every few seconds; a plan that varies between passes would
	// churn containers. Map iteration order must not leak into the output.
	world := reconciler.World{
		Desired: []reconciler.Desired{desired(4)},
		Records: map[string]reconciler.AllocRecord{
			"shop-web-0": record(0, reconciler.AllocRunning),
			"shop-web-9": record(9, reconciler.AllocRunning),
		},
		Actual: map[string]runtime.Status{
			"shop-web-0": running("shop-web-0"),
			"shop-web-9": running("shop-web-9"),
			"stray-7":    running("stray-7"),
		},
		Now: testNow,
	}
	first := kinds(reconciler.Plan(world))
	for range 20 {
		if got := kinds(reconciler.Plan(world)); got != first {
			t.Fatalf("plan is not deterministic:\n%q\n%q", first, got)
		}
	}
}

func TestPlanHandlesMultipleServices(t *testing.T) {
	api := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1, Image: "api:1",
		Resources: runtime.Resources{CPUMillis: 100, MemoryBytes: 128 << 20},
	}
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(1), api},
		Records: map[string]reconciler.AllocRecord{},
		Actual:  map[string]runtime.Status{},
		Now:     testNow,
	})
	if kinds(got) != "create:shop-api-0 create:shop-web-0" {
		t.Errorf("plan = %q", kinds(got))
	}
}

func TestPlanZeroCountRemovesEverything(t *testing.T) {
	// `kanea stop` scales to zero without deleting the service.
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{desired(0)},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": record(0, reconciler.AllocRunning)},
		Actual:  map[string]runtime.Status{"shop-web-0": running("shop-web-0")},
		Now:     testNow,
	})
	if kinds(got) != "remove:shop-web-0" {
		t.Errorf("plan = %q", kinds(got))
	}
}

func TestRestartPolicyDefaultsAndSchedule(t *testing.T) {
	var zero reconciler.RestartPolicy
	d := desired(1)
	d.Restart = zero

	// An exhausted default budget is 5 restarts.
	rec := record(0, reconciler.AllocBackoff)
	rec.Restarts = reconciler.DefaultRestartAttempts
	got := reconciler.Plan(reconciler.World{
		Desired: []reconciler.Desired{d},
		Records: map[string]reconciler.AllocRecord{"shop-web-0": rec},
		Actual:  map[string]runtime.Status{"shop-web-0": stopped(1)},
		Now:     testNow,
	})
	if kinds(got) != "remove:shop-web-0" {
		t.Errorf("default attempts not applied: %q", kinds(got))
	}
}

func TestAllocSpecFor(t *testing.T) {
	d := desired(2)
	d.Env = map[string]string{"A": "1"}
	spec := reconciler.AllocSpecFor(d, 1, "/var/log/kanea", "/var/lib/kanea/volumes")

	if spec.ID != "shop-web-1" {
		t.Errorf("id = %q", spec.ID)
	}
	if spec.CgroupPath != "/kanea-workloads.slice/shop-web-1" {
		t.Errorf("cgroup = %q; every alloc must sit under the workload parent", spec.CgroupPath)
	}
	if spec.NetnsPath != "/run/netns/shop-web-1" {
		t.Errorf("netns = %q", spec.NetnsPath)
	}
	if spec.LogPath != "/var/log/kanea/shop-web-1.log" {
		t.Errorf("log path = %q", spec.LogPath)
	}
	// The spec the driver receives must already satisfy its own validation.
	if err := spec.Validate(); err != nil {
		t.Errorf("generated spec is invalid: %v", err)
	}
}

func TestAllocSpecForResolvesVolumesPerAlloc(t *testing.T) {
	// PRD §8 per-alloc mode: each alloc gets its own directory, so two database
	// allocs can never write the same data dir.
	d := desired(2)
	d.Volumes = []reconciler.Volume{
		{Name: "data", Storage: "local-ssd", MountPath: "/var/lib/data"},
		{Name: "media", Storage: "local-ssd", MountPath: "/media", ReadOnly: true},
	}

	zero := reconciler.AllocSpecFor(d, 0, "", "/vol")
	one := reconciler.AllocSpecFor(d, 1, "", "/vol")

	if len(zero.Mounts) != 2 {
		t.Fatalf("mounts = %+v, want 2", zero.Mounts)
	}
	if zero.Mounts[0].Source != "/vol/shop/web/0/data" {
		t.Errorf("source = %q, want /vol/shop/web/0/data", zero.Mounts[0].Source)
	}
	if zero.Mounts[0].Destination != "/var/lib/data" {
		t.Errorf("destination = %q", zero.Mounts[0].Destination)
	}
	if !zero.Mounts[1].ReadOnly {
		t.Error("read-only volume mounted read-write")
	}
	if one.Mounts[0].Source == zero.Mounts[0].Source {
		t.Errorf("allocs share a volume directory: %q", one.Mounts[0].Source)
	}

	// The index is stable across restarts, so a restarted alloc finds its data.
	again := reconciler.AllocSpecFor(d, 0, "", "/vol")
	if again.Mounts[0].Source != zero.Mounts[0].Source {
		t.Errorf("volume path is not stable across rebuilds: %q vs %q",
			again.Mounts[0].Source, zero.Mounts[0].Source)
	}
}

func TestAllocIDAndKeyFormats(t *testing.T) {
	if got := reconciler.AllocID("shop", "web", 2); got != "shop-web-2" {
		t.Errorf("AllocID = %q", got)
	}
	if got := reconciler.AllocKey("shop", "web", 2); got != "shop/web/2" {
		t.Errorf("AllocKey = %q", got)
	}
	if got := reconciler.ServicePrefix("shop", "web"); got != "shop/web/" {
		t.Errorf("ServicePrefix = %q", got)
	}
	// Alloc ids are containerd container ids and netns names: they must clear
	// the CNI plugin's 5-character floor (M0 spike ①).
	if len(reconciler.AllocID("a", "b", 0)) < 5 {
		t.Error("shortest alloc id is below the CNI floor")
	}
}
