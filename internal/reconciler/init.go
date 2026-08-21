package reconciler

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/m18h/kanea/internal/runtime"
)

// This file is the init-container state machine (PRD §6.2 R32).
//
// One property decides its whole shape: **the reconcile pass never waits.**
// create() runs inline on the loop's goroutine, so blocking on a five-minute
// migration would stall every other service on the node. Progress therefore
// advances one step per pass, through the Observe / Plan / apply split the loop
// already has, and the narrowed Driver interface gains no method - a Wait here
// would be the stall wearing an abstraction's clothes.
//
// The second property is subtler and is what the crash-recovery cases turn on:
// **the node is the truth and the record is a clock.** A completed init
// container is kept, stopped, as the evidence that its step ran, so the live
// step is derived from the containers that exist rather than read from the
// record; a lost record write therefore cannot re-run a finished migration.
// What the record carries that nothing can derive is InitStartedAt, because a
// timeout measured from the daemon's own start would silently reset on every
// kanead restart.

// InitOp is what an ActionInitStep does about one step.
type InitOp string

const (
	// InitStart creates and starts a step whose container does not exist.
	InitStart InitOp = "start"
	// InitDone marks an ActionCreate that follows a completed sequence, so
	// create() builds the task instead of starting the sequence over. It is on
	// the action rather than re-derived inside create() because create() is
	// reached from four kinds and only one of them has finished a sequence.
	InitDone InitOp = "done"
	// InitAdopt re-stamps the record's clock onto a step that is already
	// running. It exists for exactly one window: kanead dying between starting
	// a step and persisting the record that names it. Reading the record
	// instead would plan a create for a container that already exists, which
	// fails ErrAlreadyExists on every pass forever.
	InitAdopt InitOp = "adopt"
)

// InitAction is the init half of an Action, set only for ActionInitStep.
type InitAction struct {
	Ordinal int
	Name    string
	Op      InitOp
}

// isInitFailure reports whether a reason names a failed init step. Both are on
// the ran-and-failed side of §17's split, so both spend R29's restart budget.
func isInitFailure(r ExitReason) bool {
	return r == ExitInitFailed || r == ExitInitTimeout
}

// initVerb renders an init reason for a planner action's Reason string.
func initVerb(r ExitReason) string {
	if r == ExitInitTimeout {
		return "timed out"
	}
	return "failed"
}

// InitLeaderIndex is the alloc index that runs a service's init sequence.
//
// The sequence runs **once per service, not once per alloc** (PRD v1.92): a
// migration is work on shared state, and a spec that declares one has no way to
// say "three replicas, one migration" if every replica runs it. Since creation
// is not budget-gated - only ActionReplace is - a first deploy of `count = 3`
// used to create three allocs in one pass and run three sequences at once.
//
// Index 0 rather than "whichever alloc gets there first" for two reasons. The
// planner is deterministic and total, and a leader elected by a race is
// neither. And index 0 is the last alloc a scale-in removes, so the one alloc
// whose record proves the sequence ran is also the one that outlives every
// other.
const InitLeaderIndex = 0

// InitLeaderID is the alloc that runs the service's init sequence.
func InitLeaderID(d Desired) string {
	return AllocID(d.Project, d.Service, InitLeaderIndex)
}

// serviceInitDone reports whether a service's init sequence has completed for
// the given spec hash, and when it has not, why - because the answer gates
// every other alloc of the service and a silent wait is a service that never
// starts with nothing on screen to say so.
//
// The signal is the leader's **record**, not its init containers. Those are
// swept the moment its task is created (initContainersToReap keeps them only
// while the record is in AllocInit), so they are evidence *during* a sequence
// and gone afterwards; the record leaving AllocInit at a known spec hash is
// what survives. The hash is half of the test: on a deploy the leader re-runs
// the new spec's sequence, and a follower that only checked "not in init"
// would create its new task against a migration that has not been applied.
func serviceInitDone(w World, d Desired, hash string) (bool, string) {
	leader := InitLeaderID(d)
	record, ok := w.Records[leader]
	switch {
	case !ok:
		return false, fmt.Sprintf("waiting for %s to run the init sequence", leader)
	case record.SpecHash != "" && record.SpecHash != hash:
		return false, fmt.Sprintf("waiting for %s to re-run the init sequence for this spec", leader)
	case record.State == AllocInit:
		return false, fmt.Sprintf("waiting for %s init %q (%d of %d)",
			leader, record.InitName, record.InitStep+1, len(d.Init))
	case record.State == AllocFailed && isInitFailure(record.LastExitReason):
		// Named rather than propagated. Failing the followers too would be a
		// cascade, which R10 refuses for dependencies and which would spend
		// their restart budgets on somebody else's failure; leaving them
		// unexplained would be worse still.
		return false, fmt.Sprintf("%s failed its init %q; nothing else can start",
			leader, record.InitName)
	}
	return true, ""
}

// InitIDFor is the containerd id of one of an alloc's init steps.
func InitIDFor(allocID string, ordinal int, name string) string {
	return runtime.InitID(allocID, ordinal, name)
}

// InitStatus is one init container as the runtime reports it, plus the two
// things the id alone cannot answer.
//
// Project is carried rather than parsed back out of the alloc id: every driver
// call is namespaced, a removal aimed at the wrong namespace silently does
// nothing, and a project name may contain dashes so the id cannot be split on
// one. The loader knows the namespace it listed; it says so here.
type InitStatus struct {
	runtime.Status
	Project string
	AllocID string
}

// initStatus is what the world says about one declared step.
type initStatus struct {
	ordinal int
	step    InitContainer
	status  runtime.Status
	exists  bool
}

// initProgress walks a service's declared steps in order and reports the first
// one that is not finished, plus whether every step is done.
//
// "Finished" is stopped with exit code zero, and nothing else: a step that was
// created and never started, or that containerd cannot describe, is unfinished
// and gets acted on rather than skipped. Skipping one would run a task against
// a database whose migration may not have applied.
func initProgress(w World, d Desired, allocID string) (initStatus, bool) {
	for i := range d.Init {
		step := d.Init[i]
		found, ok := w.InitActual[InitIDFor(allocID, i, step.Name)]
		if ok && found.State == runtime.StateStopped && found.ExitCode == 0 {
			continue
		}
		return initStatus{ordinal: i, step: step, status: found.Status, exists: ok}, false
	}
	return initStatus{}, true
}

// planInit decides what to do about an alloc that is part-way through its init
// sequence. It is pure, like the rest of the planner.
//
// It handles progress only. The two terminal transitions - a step that exited
// non-zero, and one that outlived its timeout - belong to Observe, because they
// are observations that spend the restart budget through exactly the arithmetic
// a crash already goes through. By the time one of those has happened the alloc
// is no longer in AllocInit and this function is not reached.
func planInit(w World, d Desired, base Action, record AllocRecord) []Action {
	live, done := initProgress(w, d, base.AllocID)
	if done {
		// Every step finished. The task is created by the ordinary create
		// path, which finds its shared setup already in place.
		act := base
		act.Kind = ActionCreate
		act.Init = &InitAction{Op: InitDone}
		act.Reason = fmt.Sprintf("init containers completed (%d step(s))", len(d.Init))
		return []Action{act}
	}

	act := base
	act.Kind = ActionInitStep
	act.Init = &InitAction{Ordinal: live.ordinal, Name: live.step.Name, Op: InitStart}

	switch {
	case !live.exists:
		act.Reason = fmt.Sprintf("starting init %q (%d of %d)",
			live.step.Name, live.ordinal+1, len(d.Init))
		return []Action{act}

	case live.status.State == runtime.StateRunning:
		// The clock has to belong to the step it is timing. When it does not,
		// the record was written for an earlier step and this one is running
		// unwatched, so re-stamp rather than time it against somebody else's
		// start (see InitAdopt).
		if record.InitStep != live.ordinal || record.InitName != live.step.Name ||
			record.InitStartedAt.IsZero() {
			act.Init.Op = InitAdopt
			act.Reason = fmt.Sprintf("adopting running init %q (%d of %d)",
				live.step.Name, live.ordinal+1, len(d.Init))
			return []Action{act}
		}
		// Running, within its budget. The whole point of the design: no
		// action, no Store write, and the pass moves on to other services.
		wait := base
		wait.Kind = ActionWait
		wait.Reason = fmt.Sprintf("init %q (%d of %d) running for %s",
			live.step.Name, live.ordinal+1, len(d.Init),
			w.Now.Sub(record.InitStartedAt).Truncate(time.Second))
		return []Action{wait}

	default:
		// Created but never started, stopped non-zero (Observe has not caught
		// it yet this pass), or a state containerd cannot describe. Re-run the
		// step: teardown of the leftover happens in reapInit, which removes any
		// container the alloc is not currently expecting.
		act.Reason = fmt.Sprintf("re-running init %q (%d of %d) in state %q",
			live.step.Name, live.ordinal+1, len(d.Init), live.status.State)
		return []Action{act}
	}
}

// observeInit records the two terminal outcomes of a step: it ran and failed,
// or it outlived its timeout.
//
// Both spend R29's restart budget, and that is the deliberate half of §17's
// split. A step that could not be *pulled or created* never ran, so it keeps
// the create-path reasons and their per-pass, budget-free retry: a registry
// outage is on the node's side of the line and must not permanently fail a
// service. A step that ran and failed is a workload failing, which is what the
// budget is for; a broken migration has to stop hammering a database.
//
// A hang is treated the same way as a non-zero exit, and if anything is the
// stronger signal of the two.
func observeInit(w World, d Desired, record AllocRecord) (AllocRecord, bool) {
	live, done := initProgress(w, d, record.ID)
	if done || !live.exists {
		return record, false
	}

	var reason ExitReason
	var message string
	switch {
	case live.status.State == runtime.StateStopped && live.status.ExitCode != 0:
		reason = ExitInitFailed
		message = fmt.Sprintf("init %q (%d of %d) exited with code %d",
			live.step.Name, live.ordinal+1, len(d.Init), live.status.ExitCode)

	case live.status.State == runtime.StateRunning && live.step.Timeout > 0 &&
		record.InitStep == live.ordinal && record.InitName == live.step.Name &&
		!record.InitStartedAt.IsZero() &&
		w.Now.Sub(record.InitStartedAt) > live.step.Timeout:
		reason = ExitInitTimeout
		message = fmt.Sprintf("init %q (%d of %d) exceeded its %s timeout",
			live.step.Name, live.ordinal+1, len(d.Init), live.step.Timeout)

	default:
		return record, false
	}

	record.InitStep, record.InitName = live.ordinal, live.step.Name
	record.LastExitReason, record.LastExitMessage = reason, truncateMessage(message)
	record.LastExitAt = w.Now
	// Only a real exit gets a code. A timeout is killed by us on a later pass,
	// so there is no code we chose, and omitempty makes the absence honest
	// rather than a zero somebody reads as a clean exit.
	if reason == ExitInitFailed {
		record.LastExitCode = live.status.ExitCode
	} else {
		record.LastExitCode = 0
	}
	record.UpdatedAt = w.Now

	if record.Restarts >= d.Restart.attempts() {
		record.State = AllocFailed
	} else {
		record.State = AllocBackoff
		record.NextRestartAt = w.Now.Add(d.Restart.delayFor(record.Restarts + 1))
	}
	return record, true
}

// initContainersToReap lists the init containers that should not exist.
//
// It is driven by what is on the node under the alloc's own prefix rather than
// by the spec's list, which is what makes it correct in the four cases that
// matter: a step killed by its timeout, leftovers from a crashed kanead whose
// alloc has since failed or started, a step whose init block was renamed or
// deleted, and a sequence abandoned by a deploy. A sweep that iterated the
// current spec would miss every one of those, because in each of them the
// container's name is no longer in it.
//
// "Should not exist" is: the alloc has no record, or its record is not in
// AllocInit, or the container's ordinal is *past* the live step. Past, not
// other than: steps before the live one are the evidence that they completed
// and must survive until teardown.
func initContainersToReap(w World, desiredByService map[string]Desired) []Action {
	var actions []Action
	for id, status := range w.InitActual {
		record, hasRecord := w.Records[status.AllocID]
		keep := false
		if hasRecord && record.State == AllocInit {
			if d, isDesired := desiredByService[record.Project+"/"+record.Service]; isDesired {
				live, done := initProgress(w, d, status.AllocID)
				ordinal := initOrdinalOf(id, status.AllocID, d)
				// A step this spec no longer declares (ordinal < 0) is always a
				// reap. Otherwise keep everything up to and including the live
				// step, and keep the whole set once the sequence is complete:
				// those containers are the evidence that each step ran, and
				// removing them before the task is created would make the next
				// pass start the sequence over.
				keep = ordinal >= 0 && (done || ordinal <= live.ordinal)
			}
		}
		if keep {
			continue
		}
		reason := "init container is no longer expected"
		if hasRecord {
			reason = fmt.Sprintf("init container left over from a %s alloc", record.State)
		}
		actions = append(actions, Action{
			Kind: ActionRemoveInit, AllocID: id, Project: status.Project, Reason: reason,
		})
	}
	return actions
}

// initOrdinalOf finds a container id's ordinal among the declared steps, or
// -1 when the id names a step this spec no longer declares - a rename or a
// deletion, and in both cases a reap.
func initOrdinalOf(id, allocID string, d Desired) int {
	for i := range d.Init {
		if InitIDFor(allocID, i, d.Init[i].Name) == id {
			return i
		}
	}
	return -1
}

// initSpecFor derives one init container's AllocSpec from the alloc's own.
//
// It starts from the alloc's spec rather than building a fresh one, because
// what a step *shares* is the larger half and sharing it by construction is
// what keeps the two from drifting: the network namespace, the volume mounts,
// the secrets bind, the resolv.conf bind and the cgroup parent all come across
// untouched. What it replaces is the container's own identity: its id, image,
// command, env, user, capabilities, resources, log file and cgroup.
//
// Devices and granted sockets are dropped rather than inherited. R32 gives an
// init block no field for either, so passing the task's through would hand a
// step a grant nobody wrote down (runtime.AllocSpec.Validate refuses it too).
func initSpecFor(
	allocSpec runtime.AllocSpec, d Desired, ordinal int, step InitContainer,
	env map[string]string, fileMounts []runtime.Mount, logDir string,
) runtime.AllocSpec {
	spec := allocSpec
	spec.ID = InitIDFor(allocSpec.ID, ordinal, step.Name)
	spec.Init = &runtime.InitMeta{AllocID: allocSpec.ID, Ordinal: ordinal, Name: step.Name}
	spec.Image = step.Image
	spec.Command = step.Command
	spec.User = step.User
	spec.Resources = step.Resources
	// A step's pids cap is the alloc's: R11 keeps pids.max on every container
	// regardless of what else is declared, and a fork bomb in a migration is a
	// fork bomb.
	if spec.Resources.PidsLimit == 0 {
		spec.Resources.PidsLimit = allocSpec.Resources.PidsLimit
	}
	spec.Capabilities = effectiveInitCapabilities(d, step)
	// Never the task's rootfs policy: a step whose job is to write into a
	// volume is the common case, and read_only_rootfs is the task's decision
	// about the task.
	spec.ReadOnlyRootfs = false
	spec.Devices = nil
	spec.Mounts = dropGrantedSockets(allocSpec.Mounts, d)
	// A secret-bearing file is 0400 owned by *its reader* (R35), and this step's
	// user is deliberately independent of the task's (R32) - so the step binds
	// its own copy rather than the task's, which it could not read. Keyed by
	// destination, so a plain file (one shared world-readable inode) is left
	// exactly as the alloc has it.
	spec.Mounts = overrideMounts(spec.Mounts, fileMounts)

	spec.Env = step.Env
	if env != nil {
		spec.Env = env
	}
	if logDir != "" {
		spec.LogPath = filepath.Join(logDir, spec.ID+".log")
	}
	spec.CgroupPath = runtime.CgroupPath(runtime.WorkloadSlice, spec.ID)
	// The netns is the alloc's, deliberately and emphatically: it is what makes
	// ${service.db.host} resolve in a wait-for-database step (R32). Deriving one
	// from this container's id would give the step an empty namespace and an
	// address nothing routes to.
	if allocSpec.NetnsPath != "" {
		spec.NetnsPath = runtime.NetnsPath(allocSpec.ID)
	}
	return spec
}

// effectiveInitCapabilities projects a step's declared list exactly the way
// effectiveCapabilities projects the task's: the R13 baseline is applied here,
// at projection time, and never written into the record.
func effectiveInitCapabilities(d Desired, step InitContainer) []string {
	return effectiveCapabilities(Desired{
		Runtime:      d.Runtime,
		Capabilities: step.Capabilities,
	})
}

// dropGrantedSockets removes the mounts that came from R18 socket grants.
//
// A granted runtime socket is root on the node, and R32 gives an init block no
// way to ask for one; inheriting the task's would hand every step of every
// service with a socket grant the same authority, silently.
func dropGrantedSockets(mounts []runtime.Mount, d Desired) []runtime.Mount {
	if len(d.Sockets) == 0 {
		return mounts
	}
	granted := make(map[string]struct{}, len(d.Sockets))
	for _, s := range d.Sockets {
		granted[s.MountPath] = struct{}{}
	}
	out := make([]runtime.Mount, 0, len(mounts))
	for _, m := range mounts {
		if _, isGrant := granted[m.Destination]; isGrant {
			continue
		}
		out = append(out, m)
	}
	return out
}

// startInitStep creates and starts one step, then records that it did.
//
// The record write is the clock: it is what arms the step's timeout, and it is
// why an adopt exists for the window in which this function has started a
// container and not yet returned.
func (r *Reconciler) startInitStep(
	ctx context.Context, d Desired, action Action,
	allocSpec runtime.AllocSpec, sec allocSecrets, files allocFiles, ordinal int,
) error {
	step := d.Init[ordinal]
	spec := initSpecFor(allocSpec, d, ordinal, step,
		sec.InitEnv[step.Name], files.InitMounts[step.Name], r.logDir)

	if err := r.ensureInitImage(ctx, d, step); err != nil {
		return failedAt(phaseImage, err)
	}
	if err := r.driver.Create(ctx, spec); err != nil {
		// A step that already exists is the crash window, not a conflict: kanead
		// died between starting it and writing the record. Adopt it - the record
		// write below re-arms the clock - rather than failing the alloc forever
		// on a container that is doing exactly what was asked.
		if !errors.Is(err, runtime.ErrAlreadyExists) {
			return failedAt(phaseCreate, wrapInitError(step, ordinal, len(d.Init), err))
		}
	} else if err := r.driver.Start(ctx, d.Project, spec.ID); err != nil {
		return failedAt(phaseStart, wrapInitError(step, ordinal, len(d.Init), err))
	}

	return r.stampInitStep(ctx, d, action, ordinal, step.Name)
}

// stampInitStep writes which step is live and when it started. Nothing else on
// the record moves: this is bookkeeping, not a decision.
func (r *Reconciler) stampInitStep(
	ctx context.Context, d Desired, action Action, ordinal int, name string,
) error {
	now := r.now()
	record := AllocRecord{
		ID: action.AllocID, Project: d.Project, Service: d.Service, Index: action.Index,
		Image: d.Image, SpecHash: SpecHash(d), State: AllocInit,
		InitStep: ordinal, InitName: name, InitStartedAt: now,
		CreatedAt: now, UpdatedAt: now,
	}
	if existing, err := r.loadRecord(ctx, d.Project, d.Service, action.Index); err == nil {
		record.CreatedAt = existing.CreatedAt
		// The restart budget belongs to the spec hash that spent it (R29), so
		// it carries over exactly as create()'s does and for the same reason: a
		// service that exhausted its budget must be fixable by deploying a fix.
		if existing.SpecHash == "" || existing.SpecHash == record.SpecHash {
			record.Restarts = existing.Restarts
			// And it is *spent* here, for the same reason create() spends it:
			// this is the write that ends the retry, and create()'s own record
			// write is never reached on a service with init containers, because
			// the sequence starts and the pass returns. Without this the
			// counter never leaves zero and a broken migration retries at the
			// shortest backoff forever.
			//
			// Only on ActionRestart, and only ever on the step that begins a
			// sequence: an ActionInitStep advancing from step 1 to step 2 is
			// not a restart of anything.
			if action.Kind == ActionRestart {
				record.Restarts++
			}
			// The explanation travels with the exit it explains, exactly as
			// create() carries it: an alloc stuck in an init crash loop must
			// still answer "why" between attempts, or `kanea describe` goes
			// blank for the whole backoff and the operator is left with a
			// state and no cause. Gated on LastExitAt for create()'s reason
			// too: a *start* failure has no exit to carry, and this write is
			// the moment it stopped being true.
			if !existing.LastExitAt.IsZero() {
				record.LastExitCode = existing.LastExitCode
				record.LastExitAt = existing.LastExitAt
				record.LastExitReason = existing.LastExitReason
				record.LastExitMessage = existing.LastExitMessage
			}
		}
	}
	return r.persist(ctx, map[string]AllocRecord{record.ID: record})
}

// advanceInit executes one ActionInitStep.
//
// It re-runs the alloc's shared setup before starting a step, deliberately.
// Every part of it is idempotent (a netns that exists is adopted, a volume
// directory that exists is left alone, a grant re-resolves to the same node
// fact) and re-running it is what makes a sequence survive a kanead restart:
// the daemon that resumes a sequence may not be the one that started it.
func (r *Reconciler) advanceInit(ctx context.Context, desired Desired, action Action) error {
	if action.Init == nil {
		return fmt.Errorf("init step action for %s carries no step", action.AllocID)
	}
	if action.Init.Ordinal >= len(desired.Init) {
		// The spec changed under us between planning and applying. Do nothing:
		// the next pass sees the new hash and replaces the alloc.
		return nil
	}

	// An adopt touches no container at all, which is what makes it safe while
	// a step is running: re-running the setup below would rebuild the secrets
	// tree under a live reader.
	if action.Init.Op == InitAdopt {
		return r.stampInitStep(ctx, desired, action,
			action.Init.Ordinal, desired.Init[action.Init.Ordinal].Name)
	}

	spec, sec, files, err := r.prepareAlloc(ctx, &desired, action)
	if err != nil {
		return err
	}
	return r.startInitStep(ctx, desired, action, spec, sec, files, action.Init.Ordinal)
}

// ensureInitImage pulls one step's image under its own credential and policy.
func (r *Reconciler) ensureInitImage(ctx context.Context, d Desired, step InitContainer) error {
	var auth []byte
	if step.RegistryAuthRef != "" {
		if r.secrets == nil {
			return fmt.Errorf("init %q names a registry credential but no secret store is configured",
				step.Name)
		}
		resolved, err := r.secrets.Resolve(ctx, step.RegistryAuthRef)
		if err != nil {
			return fmt.Errorf("init %q registry credential %q: %w", step.Name, step.RegistryAuthRef, err)
		}
		auth = resolved
	}
	if _, err := r.driver.EnsureImage(ctx, runtime.ImageRef{
		Project: d.Project, Ref: step.Image, Auth: auth, Policy: r.effectivePullPolicy(step.PullPolicy),
	}); err != nil {
		return fmt.Errorf("init %q: %w", step.Name, err)
	}
	return nil
}

// wrapInitError names the step in an error that will become an exit message.
// The reason stays one of the create-path reasons (§17's split): nothing ran,
// so the restart budget is not spent, and which step it was belongs in the
// message rather than in the vocabulary.
func wrapInitError(step InitContainer, ordinal, total int, err error) error {
	return fmt.Errorf("init %q (%d of %d): %w", step.Name, ordinal+1, total, err)
}

// effectivePullPolicy resolves R33's "the node decides" on the node.
//
// An empty policy on a record is not a missing value: it is the record saying
// the node's default applies, which is why it is resolved here and not in
// toDesired (the Expose.TLSMode rule, v1.33).
func (r *Reconciler) effectivePullPolicy(declared string) string {
	if declared != "" {
		return declared
	}
	if r.pullPolicy != "" {
		return r.pullPolicy
	}
	return runtime.PullIfNotPresent
}

// overrideMounts replaces mounts whose destination one of the overrides claims.
//
// Replacement rather than append: two binds on one destination is one of them
// silently winning, and which one would depend on runc's ordering.
func overrideMounts(mounts, overrides []runtime.Mount) []runtime.Mount {
	if len(overrides) == 0 {
		return mounts
	}
	byDest := make(map[string]runtime.Mount, len(overrides))
	for _, m := range overrides {
		byDest[m.Destination] = m
	}
	out := make([]runtime.Mount, 0, len(mounts))
	for _, m := range mounts {
		if override, ok := byDest[m.Destination]; ok {
			out = append(out, override)
			continue
		}
		out = append(out, m)
	}
	return out
}
