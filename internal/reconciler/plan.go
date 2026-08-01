package reconciler

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kanea-dev/kanea/internal/runtime"
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

		for i := range d.Count {
			id := AllocID(d.Project, d.Service, i)
			wanted[id] = struct{}{}
			actions = append(actions, planAlloc(w, d, i, id, healthy)...)
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
func planAlloc(w World, d Desired, index int, id string, healthy map[string]bool) []Action {
	record, hasRecord := w.Records[id]
	status, isActual := w.Actual[id]

	base := Action{AllocID: id, Project: d.Project, Service: d.Service, Index: index}

	// Failed allocs are left alone: the restart budget is spent, and retrying
	// forever would hide the failure instead of surfacing it.
	if hasRecord && record.State == AllocFailed {
		return nil
	}

	// Nothing exists yet: first deploy, or a scale-out.
	if !isActual {
		if hasRecord && record.State == AllocBackoff && w.Now.Before(record.NextRestartAt) {
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
		if hasRecord && record.Restarts > 0 {
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
		return nil // the steady state, and by far the common case

	case runtime.StateCreated:
		act := base
		act.Kind = ActionStart
		act.Reason = "alloc created but not started"
		return []Action{act}

	case runtime.StateStopped:
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
		Image:          d.Image,
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
