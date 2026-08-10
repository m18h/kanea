package reconciler_test

import (
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
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
	// A volume so that the ownership mutator below changes ownership and
	// nothing else. Adding a volume is its own change, and asserting on a
	// mutator that does both would pass without R24 being hashed at all.
	base.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}

	// Things that are applied to a running alloc, or to something other than
	// the alloc, must not roll it. A service that changes its replica bounds is
	// not a service that needs new containers.
	unchanged := base
	unchanged.Count = 9
	unchanged.Scaling = &reconciler.ScalingPolicy{Min: 1, Max: 20}
	unchanged.DependsOn = []string{"db"}
	unchanged.Restart = reconciler.RestartPolicy{Attempts: 99}
	unchanged.Update = reconciler.UpdatePolicy{MaxParallel: 4}
	// Trigger config is read live by the invokers, like Publish is by the
	// edge — editing a cron schedule must not roll the alloc (R26).
	unchanged.Function = &reconciler.FunctionMeta{
		HTTP:   true,
		Events: []reconciler.EventTrigger{{On: []string{"deploy.failed"}}},
		Crons:  []reconciler.CronTrigger{{Schedule: "0 3 * * *", Path: "/nightly"}},
	}
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
		// A device or socket is wired in when the container is created, so
		// granting or withdrawing one has to produce new containers.
		"devices": func(d *reconciler.Desired) {
			d.Devices = []reconciler.DeviceRequest{{Name: "dri", Grant: "gpu"}}
		},
		"sockets": func(d *reconciler.Desired) {
			d.Sockets = []reconciler.SocketRequest{
				{Name: "rt", Grant: "containerd", MountPath: "/var/run/docker.sock"},
			}
		},
		// The uid a process runs as is fixed when the container is created
		// (R23), and so is the ownership its volumes are mounted with (R24).
		"user": func(d *reconciler.Desired) {
			d.User = &runtime.User{UID: 999, GID: 999}
		},
		"volume owner": func(d *reconciler.Desired) {
			uid := uint32(999)
			d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data", UID: &uid}}
		},
		"volume mode": func(d *reconciler.Desired) {
			mode := uint32(0o700)
			d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data", Mode: &mode}}
		},
		// The runtime decides which shim runs the container (R25) — moving a
		// service between runc and wasmtime cannot happen in place.
		"runtime": func(d *reconciler.Desired) { d.Runtime = "io.containerd.wasmtime.v1" },
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

// A service that names no user and no volume ownership must hash to exactly
// what it hashed before R23/R24 existed.
//
// This is the upgrade-safety property, and it is not a detail. SpecHash decides
// whether an alloc is replaced, so a field that serialised as a zero value
// instead of being omitted would change the hash of every service on the node —
// and upgrading kanead would silently roll every container on it. The literal
// below is the pre-feature digest of this exact Desired; if a change here moves
// it, that is the question being asked, and the answer is almost always no.
func TestSpecHashIsUnchangedForASpecWithNoUserOrOwnership(t *testing.T) {
	d := desired(3)
	d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}

	// Verified against the pre-R23 material struct, whose JSON was:
	//   {"image":"nginx:1.27-alpine","resources":{...},"volumes":[{"Name":"data",
	//    "Storage":"","Resource":{...},"MountPath":"/data","ReadOnly":false}]}
	// The new fields are pointers with omitempty, so nil drops them from that
	// object entirely and the bytes are unchanged. v1.39's Runtime holds the
	// same line: an empty string with omitempty vanishes from the JSON, so a
	// pre-v1.39 record and a post-v1.39 runc service produce these same bytes.
	const beforeR23 = "df0877104f33e69e9cebc6f3d05a5975"
	if got := reconciler.SpecHash(d); got != beforeR23 {
		t.Errorf("spec hash = %s, want %s\n"+
			"A spec that declares no user and no volume ownership must hash as it did "+
			"before those fields existed. If it does not, upgrading kanead rolls every "+
			"alloc on the node.", got, beforeR23)
	}
}

// A runtime change rolls every alloc, so a plan that did not mention it would
// show a redeploy with no visible cause.
func TestDiffNamesARuntimeChange(t *testing.T) {
	have := desired(1)
	want := have
	want.Runtime = "io.containerd.wasmtime.v1"

	lines := reconciler.Diff([]reconciler.Desired{have}, []reconciler.Desired{want})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "runtime default -> io.containerd.wasmtime.v1") {
		t.Fatalf("plan lines %q do not name the runtime change", joined)
	}
}

// The two halves of an ownership pair are independent: setting only a gid must
// not read as "uid 0". chown(2) takes -1 for the half you are not changing, and
// the spec's nil means the same thing.
func TestVolumeOwnershipHalvesAreIndependent(t *testing.T) {
	uid, gid := uint32(999), uint32(999)
	onlyUID := desired(1)
	onlyUID.Volumes = []reconciler.Volume{{Name: "d", MountPath: "/d", UID: &uid}}
	onlyGID := desired(1)
	onlyGID.Volumes = []reconciler.Volume{{Name: "d", MountPath: "/d", GID: &gid}}

	if reconciler.SpecHash(onlyUID) == reconciler.SpecHash(onlyGID) {
		t.Error("a volume owned by uid 999 hashes the same as one owned by gid 999")
	}
	if !onlyUID.Volumes[0].Owned() || !onlyGID.Volumes[0].Owned() {
		t.Error("a volume with one half of an ownership pair does not report as owned")
	}
}

// A tcp port must hash to exactly what it hashed before v1.42's Protocol field
// existed — the same upgrade-safety property the R23 test above pins. The
// empty string with omitempty vanishes from the JSON, so a pre-v1.42 record
// and a post-v1.42 tcp port produce the same bytes; a udp port is a different
// spec and must not.
func TestSpecHashIsUnchangedForATCPPort(t *testing.T) {
	d := desired(1)
	d.Ports = []reconciler.Port{{Name: "http", Container: 8080}}

	const beforeV142 = "6bd5d8a584c64da2fded413bc03e3f03"
	if got := reconciler.SpecHash(d); got != beforeV142 {
		t.Errorf("spec hash = %s, want %s\n"+
			"A tcp port must hash as it did before Protocol existed, or upgrading "+
			"kanead rolls every service with a port on the node.", got, beforeV142)
	}

	udp := d
	udp.Ports = []reconciler.Port{{Name: "http", Container: 8080, Protocol: reconciler.PortProtocolUDP}}
	if reconciler.SpecHash(udp) == beforeV142 {
		t.Error("flipping a port to udp did not change the spec hash; the alloc would never roll")
	}
}
