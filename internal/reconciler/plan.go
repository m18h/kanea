package reconciler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/runtime"
)

// World is everything the planner needs to decide. It is a value, not an
// interface: the planner performs no I/O, so a test can construct any situation
// — including ones that are hard to produce against a live daemon.
type World struct {
	// Desired is the target state, one entry per service.
	Desired []Desired
	// Records is the durable alloc state, keyed by alloc id.
	Records map[string]AllocRecord
	// Actual is what the runtime reports, keyed by alloc id.
	Actual map[string]runtime.Status
	// Now is the reference time for backoff decisions.
	Now time.Time
}

// Plan computes the actions that close the gap between desired and actual.
//
// It is deterministic and total: the same World always yields the same actions,
// in a stable order, and every alloc in either desired or actual is accounted
// for. Determinism is what makes the loop safe to run every few seconds — a
// pass that has nothing to do returns nothing, rather than churning.
func Plan(w World) []Action {
	var actions []Action

	desiredByService := make(map[string]Desired, len(w.Desired))
	wanted := make(map[string]struct{}) // alloc ids that should exist

	// Which services are currently able to serve. Computed once: it is the same
	// answer for every alloc, and it is what gates dependents (R10).
	healthy := healthyServices(w)

	for _, d := range w.Desired {
		key := d.Project + "/" + d.Service
		desiredByService[key] = d

		// Once per service, not once per alloc: every alloc of a service is
		// created from the same desired state, so they all compare against the
		// same fingerprint.
		hash := SpecHash(d)
		// How many of this service's allocs may be disturbed right now. Computed
		// before any of them are planned, because the answer is a property of the
		// service as a whole — an alloc cannot decide on its own whether taking
		// itself down would leave the service short.
		budget := replaceBudget(w, d, hash)

		for i := range d.Count {
			id := AllocID(d.Project, d.Service, i)
			wanted[id] = struct{}{}
			planned := planAlloc(w, d, i, id, hash, healthy)
			for _, act := range planned {
				// The rolling gate. A replacement that does not fit in this
				// pass's budget is simply not emitted: the next pass will
				// reconsider it, by which time the ones that did go will have
				// settled. Nothing is queued and nothing is remembered, which is
				// what keeps the loop restartable at any instant (PRD §4.3).
				if act.Kind == ActionReplace {
					if budget <= 0 {
						continue
					}
					budget--
				}
				actions = append(actions, act)
			}
		}
	}

	// Anything running or recorded that is no longer wanted must go: a scale-in,
	// a deleted service, or a container someone started by hand. All three look
	// the same from here, and all three should converge to "gone".
	actions = append(actions, planOrphans(w, desiredByService, wanted)...)

	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].AllocID != actions[j].AllocID {
			return actions[i].AllocID < actions[j].AllocID
		}
		return actions[i].Kind < actions[j].Kind
	})
	return actions
}

// planAlloc decides about one alloc index of one service.
func planAlloc(w World, d Desired, index int, id, hash string, healthy map[string]bool) []Action {
	record, hasRecord := w.Records[id]
	status, isActual := w.Actual[id]

	base := Action{AllocID: id, Project: d.Project, Service: d.Service, Index: index}
	stale := hasRecord && drifted(record, hash)

	// Failed allocs are left alone: the restart budget is spent, and retrying
	// forever would hide the failure instead of surfacing it.
	//
	// Unless the spec changed. That is the whole workflow for fixing a crash
	// loop — see what failed, correct the image or the config, deploy — and a
	// planner that refused to touch a failed alloc would make the fix land only
	// after a manual delete.
	if hasRecord && record.State == AllocFailed && !stale {
		return nil
	}

	// Nothing exists yet: first deploy, or a scale-out.
	if !isActual {
		// A backoff is a wait for the same alloc to be worth trying again. A new
		// spec is not the same alloc: the operator changed something, quite
		// possibly the thing that was crashing, and making them wait out the
		// backoff of the image they just replaced helps nobody.
		if hasRecord && record.State == AllocBackoff && w.Now.Before(record.NextRestartAt) && !stale {
			return nil // still waiting out the backoff
		}
		// Dependencies gate creation, not restart: a dependent that is already
		// running keeps running when a dependency degrades (R10 is explicit
		// that there are no cascading stops). This is the point where an alloc
		// would come up and immediately fail to reach something it needs.
		if blocked := unmetDependencies(d, healthy); len(blocked) > 0 {
			act := base
			act.Kind = ActionWait
			act.Reason = "waiting for " + strings.Join(blocked, ", ") + " to become healthy"
			return []Action{act}
		}
		reason := "alloc missing"
		switch {
		case stale:
			reason = "spec changed"
		case hasRecord && record.Restarts > 0:
			reason = fmt.Sprintf("restarting after exit %d (attempt %d)",
				record.LastExitCode, record.Restarts+1)
		}
		act := base
		act.Kind = ActionCreate
		act.Reason = reason
		return []Action{act}
	}

	switch status.State {
	case runtime.StateRunning:
		if !stale {
			return nil // the steady state, and by far the common case
		}
		// The deploy. This is the only place a healthy alloc is deliberately
		// taken down, and it is gated by the update policy in Plan — reaching
		// here means the service can spare this one right now.
		act := base
		act.Kind = ActionReplace
		act.Reason = "spec changed"
		return []Action{act}

	case runtime.StateCreated:
		act := base
		act.Kind = ActionStart
		act.Reason = "alloc created but not started"
		return []Action{act}

	case runtime.StateStopped:
		if stale {
			// Already down, so it costs the service nothing and does not go
			// through the rolling budget — and it comes back on the new spec
			// rather than the one that stopped.
			act := base
			act.Kind = ActionRestart
			act.Reason = "spec changed"
			return []Action{act}
		}
		// A stopped alloc that should be running has crashed (or was killed
		// out of band). Restart it, subject to the policy.
		return planRestart(w, d, base, record, status)

	default:
		// Paused or unknown: containerd cannot tell us what this is, so replace
		// it rather than reason about it.
		act := base
		act.Kind = ActionRestart
		act.Reason = fmt.Sprintf("alloc in unexpected state %q", status.State)
		return []Action{act}
	}
}

// SpecHash fingerprints the parts of a desired service that are baked into a
// container when it is created.
//
// Only those parts. The desired state carries plenty that a running alloc does
// not embody — the replica count, the autoscaling policy, the health check the
// reconciler probes it with, the edge route, the network policy peers — and
// hashing those would turn "raise the maximum replica count" into a rolling
// restart of a service nobody asked to disturb. The rule is: if changing it
// requires a new container, it belongs here; if it can be applied to the
// running one, it does not.
func SpecHash(d Desired) string {
	// A named struct rather than the Desired itself, so that adding a field to
	// Desired does not silently start (or stop) triggering deploys. Whether a
	// new field rolls allocs is a decision, and it should have to be made here.
	material := struct {
		Image string `json:"image"`
		// PinnedImage is what actually runs, so it is what decides a deploy
		// (R19). Image is hashed too: editing the declared tag is a spec
		// change even when the digest behind it happens to be the same.
		//
		// The updater's other fields — RollbackImage, ImageCheckedAt,
		// ImageUpdatedAt — are deliberately absent, and so is RegistryAuthRef.
		// They are bookkeeping and pull-time inputs, not things baked into a
		// container: hashing them would roll every auto-updating service on
		// every poll, for no change to what is running.
		PinnedImage  string            `json:"pinned_image,omitempty"`
		Command      []string          `json:"command,omitempty"`
		Capabilities []string          `json:"capabilities,omitempty"`
		Env          map[string]string `json:"env,omitempty"`
		Resources      runtime.Resources `json:"resources"`
		Volumes        []Volume          `json:"volumes,omitempty"`
		Ports          []Port            `json:"ports,omitempty"`
		ReadOnlyRootfs bool              `json:"read_only_rootfs,omitempty"`
		// A device or a socket is wired into a container when it is created, so
		// changing one has to roll the allocs. The grant *names* are what is
		// hashed, which is also what makes the hash node-independent: the
		// resolved paths are unexported and never marshalled.
		Devices []DeviceRequest `json:"devices,omitempty"`
		Sockets []SocketRequest `json:"sockets,omitempty"`
		// Generation is not baked into anything. It is here so that an operator
		// asking for a restart produces a spec that differs, and therefore rolls
		// through exactly the machinery a real deploy does.
		Generation int `json:"generation,omitempty"`
	}{
		Image: d.Image, PinnedImage: d.PinnedImage,
		Command: d.Command, Capabilities: d.Capabilities,
		Env: d.Env, Resources: d.Resources, Volumes: d.Volumes,
		Ports: d.Ports, ReadOnlyRootfs: d.ReadOnlyRootfs,
		Devices: d.Devices, Sockets: d.Sockets,
		Generation: d.Generation,
	}

	// encoding/json sorts map keys, so the environment hashes the same however
	// it was built. That is the one part of this that is not obviously stable,
	// and it is the reason JSON is used rather than fmt.
	body, err := json.Marshal(material)
	if err != nil {
		// Unreachable for these types, and handled anyway: falling back to a
		// deterministic rendering keeps a marshal failure from producing a
		// different hash every pass, which would roll the service forever.
		body = []byte(fmt.Sprintf("%#v", material))
	}
	sum := sha256.Sum256(body)
	// Half the digest. This is a change detector, not a security boundary —
	// nobody chooses their own spec hash to collide with someone else's.
	return hex.EncodeToString(sum[:16])
}

// drifted reports whether an alloc is running something other than what is
// declared now.
func drifted(record AllocRecord, hash string) bool {
	// An unstamped record is adopted, not rolled. Records written before the
	// field existed have no hash, and treating "I do not know" as "it changed"
	// would make the first reconcile after an upgrade replace every alloc on the
	// node at once.
	return record.SpecHash != "" && record.SpecHash != hash
}

// replaceBudget is how many of a service's allocs may be replaced this pass.
//
// The unit is availability, not progress: the policy says how many allocs may
// be *down at once*, so anything already down — starting, unhealthy, or too
// recently replaced to be trusted — spends the budget before a deliberate
// replacement gets any. That is what makes a rolling deploy stop when it starts
// going wrong, instead of walking through every replica taking each one down.
func replaceBudget(w World, d Desired, hash string) int {
	if d.Count == 0 {
		return 0
	}
	limit := d.Update.maxParallel(d.Count)
	settled := d.Update.minHealthy()

	unavailable := 0
	for i := range d.Count {
		id := AllocID(d.Project, d.Service, i)
		status, running := w.Actual[id]
		if !running || status.State != runtime.StateRunning {
			unavailable++
			continue
		}
		record, hasRecord := w.Records[id]
		// A running alloc with no record was created this pass. It is up, but
		// nothing has confirmed it works yet, so it counts against the budget
		// for the same reason a fresh replacement does.
		if !hasRecord {
			unavailable++
			continue
		}
		if d.Check.configured() && !record.Healthy {
			unavailable++
			continue
		}
		// The settling clock runs on allocs this deploy has *already* replaced,
		// not on every young alloc. What min_healthy buys is confidence that the
		// new spec works before more of the service is committed to it; an alloc
		// still running the previous spec has nothing left to prove, and holding
		// a deploy back because the service happened to start a minute ago would
		// make "deploy right after a restart" mysteriously slow.
		//
		// CreatedAt is reset when an alloc is replaced, so this measures the life
		// of *this* container rather than of the alloc index it occupies.
		if settled > 0 && record.SpecHash == hash && w.Now.Sub(record.CreatedAt) < settled {
			unavailable++
			continue
		}
	}

	// A single-replica service has no spare capacity by definition, and the
	// subtraction would refuse to ever deploy it. Its one alloc is available, so
	// unavailable is zero and the budget is one — the deploy happens, with the
	// downtime that count = 1 has always implied.
	if budget := limit - unavailable; budget > 0 {
		return budget
	}
	return 0
}

// planRestart applies the restart policy to a stopped alloc.
func planRestart(w World, d Desired, base Action, record AllocRecord, status runtime.Status) []Action {
	if record.Restarts >= d.Restart.attempts() {
		// Budget exhausted. Emit a remove so the dead container does not linger
		// and confuse `ps`; the record is marked failed by the executor.
		act := base
		act.Kind = ActionRemove
		act.Reason = fmt.Sprintf("restart attempts exhausted (%d of %d) after exit %d",
			record.Restarts, d.Restart.attempts(), status.ExitCode)
		return []Action{act}
	}
	if !record.NextRestartAt.IsZero() && w.Now.Before(record.NextRestartAt) {
		return nil // backing off
	}

	act := base
	act.Kind = ActionRestart
	act.Reason = fmt.Sprintf("alloc exited with code %d (restart %d of %d)",
		status.ExitCode, record.Restarts+1, d.Restart.attempts())
	return []Action{act}
}

// planOrphans removes allocs that exist but are not wanted.
func planOrphans(w World, desiredByService map[string]Desired, wanted map[string]struct{}) []Action {
	var actions []Action
	seen := make(map[string]struct{}, len(w.Actual)+len(w.Records))

	consider := func(id, project, service string, index int) {
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		if _, keep := wanted[id]; keep {
			return
		}

		reason := "alloc no longer desired"
		if d, ok := desiredByService[project+"/"+service]; ok && index >= d.Count {
			reason = fmt.Sprintf("scaled in: index %d beyond count %d", index, d.Count)
		} else if !ok {
			reason = "service no longer declared"
		}
		actions = append(actions, Action{
			Kind: ActionRemove, AllocID: id, Project: project,
			Service: service, Index: index, Reason: reason,
		})
	}

	for id, status := range w.Actual {
		if rec, ok := w.Records[id]; ok {
			consider(id, rec.Project, rec.Service, rec.Index)
			continue
		}
		// No record: a container we do not know about. Its labels are the only
		// clue, and the driver already filters to Kanea's namespace.
		_ = status
		consider(id, "", "", -1)
	}
	for id, rec := range w.Records {
		consider(id, rec.Project, rec.Service, rec.Index)
	}
	return actions
}

// VolumeHostPath is where an alloc's copy of a volume lives on the host:
// <volumeDir>/<project>/<service>/<index>/<volume>.
//
// The alloc index is in the path on purpose. It is stable across restarts — a
// restarted alloc keeps index 0 — so data survives a crash, while two allocs of
// the same service never share a directory (PRD §8's per-alloc mode).
func VolumeHostPath(volumeDir, project, service string, index int, volume string) string {
	return filepath.Join(volumeDir, project, service, strconv.Itoa(index), volume)
}

// SharedVolumeHostPath is where a network-backed volume lives:
// <volumeDir>/<project>/<service>/shared/<volume>.
//
// No alloc index, unlike a local volume. An NFS export or an S3 bucket *is* the
// shared thing — mounting it once per alloc would establish N mounts of one
// bucket, N supervisors probing it, and N sets of credentials on disk, all to
// present the same bytes. One mount per service is what the storage actually is.
func SharedVolumeHostPath(volumeDir, project, service, volume string) string {
	return filepath.Join(volumeDir, project, service, "shared", volume)
}

// VolumePath returns where a volume lives for one alloc, which depends on
// whether it is backed by local disk or by network storage.
func VolumePath(volumeDir string, d Desired, index int, v Volume) string {
	// A host volume is mounted straight from the operator's directory: there is
	// nothing for Kanea to derive, and copying it under data_dir would give the
	// container a different filesystem than the one the operator named.
	if v.Resource.IsHost() {
		return v.HostPath()
	}
	if v.Resource.NeedsMount() {
		return SharedVolumeHostPath(volumeDir, d.Project, d.Service, v.Name)
	}
	return VolumeHostPath(volumeDir, d.Project, d.Service, index, v.Name)
}

// AllocSpecFor builds the runtime spec for one alloc of a service. Keeping it
// here (rather than in the executor) means a test can assert exactly what would
// be handed to containerd.
func AllocSpecFor(d Desired, index int, logDir, volumeDir string) runtime.AllocSpec {
	id := AllocID(d.Project, d.Service, index)
	spec := runtime.AllocSpec{
		ID:             id,
		Project:        d.Project,
		Service:        d.Service,
		Image:          d.RunImage(),
		Command:        d.Command,
		Capabilities:   d.Capabilities,
		Env:            d.Env,
		Resources:      d.Resources,
		ReadOnlyRootfs: d.ReadOnlyRootfs,
		CgroupPath:     runtime.CgroupPath(runtime.WorkloadSlice, id),
		NetnsPath:      runtime.NetnsPath(id),
	}
	if logDir != "" {
		spec.LogPath = filepath.Join(logDir, id+".log")
	}
	// resolv.conf is a bind mount like any other, and read-only: a workload
	// that could rewrite it would take itself off the internal zone.
	if d.ResolvConfPath != "" {
		spec.Mounts = append(spec.Mounts, runtime.Mount{
			Source: d.ResolvConfPath, Destination: "/etc/resolv.conf", ReadOnly: true,
		})
	}
	for _, v := range d.Volumes {
		spec.Mounts = append(spec.Mounts, runtime.Mount{
			Source:      VolumePath(volumeDir, d, index, v),
			Destination: v.MountPath,
			ReadOnly:    v.ReadOnly,
		})
	}
	// A granted socket is a bind like any other, with the options a socket
	// should never be without: nothing under it is executed, no setuid bit on
	// it means anything, and no device node beneath it is honoured.
	for _, s := range d.Sockets {
		if s.HostPath() == "" {
			continue // unresolved: ensurePassthrough has already failed the alloc
		}
		spec.Mounts = append(spec.Mounts, runtime.Mount{
			Source:      s.HostPath(),
			Destination: s.MountPath,
			ReadOnly:    s.ReadOnly,
			Options:     []string{"nosuid", "noexec", "nodev"},
		})
	}
	for _, dev := range d.Devices {
		spec.Devices = append(spec.Devices, dev.Devices()...)
	}
	return spec
}

// healthyServices reports, per "project/service", whether the service is
// currently able to serve.
//
// The bar is every desired alloc running *and* passing its check. Not "at least
// one": a dependent that starts against a half-scaled dependency will spread its
// own load across backends that are not all there yet, and the whole point of
// gating is to make the dependency ready before anything talks to it.
//
// A service with count 0 is vacuously healthy — it was deliberately scaled to
// nothing, and blocking its dependents forever would be a deadlock rather than
// a safeguard.
func healthyServices(w World) map[string]bool {
	out := make(map[string]bool, len(w.Desired))

	for _, d := range w.Desired {
		key := d.Project + "/" + d.Service
		if d.Count == 0 {
			out[key] = true
			continue
		}

		ready := true
		for i := range d.Count {
			id := AllocID(d.Project, d.Service, i)

			status, running := w.Actual[id]
			if !running || status.State != runtime.StateRunning {
				ready = false
				break
			}
			// A record is only consulted for its health verdict. An alloc that
			// is running but has no record yet was created this pass; with no
			// check declared that is healthy, and with one it is not yet known
			// to be, which the zero value already says.
			if d.Check.configured() && !w.Records[id].Healthy {
				ready = false
				break
			}
		}
		out[key] = ready
	}
	return out
}

// unmetDependencies lists the services a dependent is still waiting on.
//
// A dependency that is not in the desired set at all is *not* treated as unmet.
// jobspec already rejects a depends_on naming a service that does not exist
// (R10), so reaching this state means the dependency was removed out from under
// a running spec — and blocking forever on something that will never appear is
// worse than starting.
func unmetDependencies(d Desired, healthy map[string]bool) []string {
	var blocked []string
	for _, dep := range d.DependsOn {
		key := d.Project + "/" + dep
		ready, declared := healthy[key]
		if declared && !ready {
			blocked = append(blocked, dep)
		}
	}
	sort.Strings(blocked)
	return blocked
}

// Diff renders a create/change summary between what is declared now and what a
// spec would declare.
//
// It lives here rather than in the CLI because it is asked by more than the
// CLI: `kanea plan`, the MCP plan_spec tool, and anything else that wants to
// say what an apply would do. Two implementations of "what would change" drift,
// and they drift into a plan that does not match the apply that follows it.
//
// It compares only what a user declares, so an untouched service is not
// reported as a change because the daemon filled in a default.
func Diff(current, desired []Desired) []string {
	byKey := make(map[string]Desired, len(current))
	for _, svc := range current {
		byKey[svc.Project+"/"+svc.Service] = svc
	}

	var out []string
	for _, want := range desired {
		key := want.Project + "/" + want.Service
		have, exists := byKey[key]
		if !exists {
			out = append(out, fmt.Sprintf("+ create %s (count %d, image %s)", key, want.Count, want.Image))
			continue
		}
		var changes []string
		if have.Image != want.Image {
			changes = append(changes, fmt.Sprintf("image %s -> %s", have.Image, want.Image))
		}
		if have.Count != want.Count {
			changes = append(changes, fmt.Sprintf("count %d -> %d", have.Count, want.Count))
		}
		if have.Resources != want.Resources {
			changes = append(changes, fmt.Sprintf("resources %+v -> %+v", have.Resources, want.Resources))
		}
		if !sameEnv(have.Env, want.Env) {
			changes = append(changes, "env changed")
		}
		// Published ports are what people iterate on, and they do not change
		// the spec hash — so without this line `kanea plan` would print "No
		// changes" for the edit somebody just made and is about to apply.
		if !reflect.DeepEqual(have.Publish, want.Publish) {
			changes = append(changes, fmt.Sprintf("published ports %s -> %s",
				describePublish(have.Publish), describePublish(want.Publish)))
		}
		if len(changes) > 0 {
			out = append(out, fmt.Sprintf("~ update %s (%s)", key, strings.Join(changes, ", ")))
		}
	}
	sort.Strings(out)
	return out
}

// describePublish renders a service's node ports for a plan line.
func describePublish(ports []PublishedPort) string {
	if len(ports) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		mode := p.Mode
		if mode == "" {
			mode = "http"
		}
		parts = append(parts, fmt.Sprintf("%d/%s->%s", p.Host, mode, p.Port))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func sameEnv(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
