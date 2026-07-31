package reconciler

import (
	"fmt"
	"sort"
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

	for _, d := range w.Desired {
		key := d.Project + "/" + d.Service
		desiredByService[key] = d

		for i := range d.Count {
			id := AllocID(d.Project, d.Service, i)
			wanted[id] = struct{}{}
			actions = append(actions, planAlloc(w, d, i, id)...)
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
func planAlloc(w World, d Desired, index int, id string) []Action {
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

// AllocSpecFor builds the runtime spec for one alloc of a service. Keeping it
// here (rather than in the executor) means a test can assert exactly what would
// be handed to containerd.
func AllocSpecFor(d Desired, index int, logDir string) runtime.AllocSpec {
	id := AllocID(d.Project, d.Service, index)
	spec := runtime.AllocSpec{
		ID:             id,
		Project:        d.Project,
		Service:        d.Service,
		Image:          d.Image,
		Command:        d.Command,
		Env:            d.Env,
		Resources:      d.Resources,
		Mounts:         d.Mounts,
		ReadOnlyRootfs: d.ReadOnlyRootfs,
		CgroupPath:     runtime.CgroupPath(runtime.WorkloadSlice, id),
		NetnsPath:      runtime.NetnsPath(id),
	}
	if logDir != "" {
		spec.LogPath = logDir + "/" + id + ".log"
	}
	return spec
}
