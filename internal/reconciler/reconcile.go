package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/kanea-dev/kanea/internal/network"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/store"
)

// Store is the slice of the state store this package needs. Declaring it here
// rather than importing the full interface keeps the dependency honest and lets
// tests substitute a store without implementing CDC or compaction.
type Store interface {
	Get(ctx context.Context, kind store.Kind, key string) (store.Record, error)
	List(ctx context.Context, kind store.Kind, opts store.ListOptions) (store.Page, error)
	Apply(ctx context.Context, muts ...store.Mutation) (uint64, error)
}

// Driver is the slice of the runtime driver this package needs.
type Driver interface {
	EnsureImage(ctx context.Context, project, ref string) (string, error)
	Create(ctx context.Context, spec runtime.AllocSpec) error
	Start(ctx context.Context, project, id string) error
	List(ctx context.Context, project string) ([]runtime.Status, error)
	Stop(ctx context.Context, project, id string, grace time.Duration) error
	Remove(ctx context.Context, project, id string) error
}

// Network wires an alloc's namespace up and tears it down. M1 uses the plain
// netns implementation; M2 swaps in the Cilium CNI attach/detach behind the
// same seam (the ordering it must preserve is documented in runtime/netns.go).
type Network interface {
	Attach(ctx context.Context, spec runtime.AllocSpec) error
	Detach(ctx context.Context, spec runtime.AllocSpec) error
}

// NetworkInspector is an optional Network capability: reporting what the
// datapath currently holds, keyed by alloc id.
//
// Two things need this. Reclaiming orphans: an attachment can outlive
// everything that refers to it, because teardown detaches *after* the container
// is removed, so a kanead that dies in that window leaves a namespace and an
// endpoint with no container and no record — invisible to the planner, which
// reasons only about allocs it has heard of. And load balancing: backend
// addresses are read live rather than remembered, because they are reassigned
// whenever the agent restarts with a fresh kvstore (constraint #9).
//
// The implementation must return only attachments it owns. Reaping deletes.
type NetworkInspector interface {
	Attachments(ctx context.Context) (map[string]network.Attachment, error)
}

// PolicySyncer is an optional Network capability: making the datapath's network
// policies match the projects that currently exist.
//
// Policy is derived state — it follows from desired state and is rebuilt rather
// than remembered (constraint #9) — so it belongs in the convergence loop
// alongside everything else that has to agree with the Store.
type PolicySyncer interface {
	// SyncPolicies installs the default policy for each named project and
	// withdraws policies for projects that no longer exist.
	SyncPolicies(ctx context.Context, projects []network.ProjectPolicy) error
}

// LoadBalancer is an optional Network capability: programming stable service
// frontends backed by the allocs currently able to serve.
type LoadBalancer interface {
	// SyncServices makes the datapath's load balancing match this set exactly.
	SyncServices(ctx context.Context, services []network.Service) error
}

// Config configures a Reconciler.
type Config struct {
	Store  Store
	Driver Driver
	// Network is optional; nil means allocs run with a bare private netns.
	Network Network
	Logger  *slog.Logger
	// Interval is how often the loop runs without an external trigger.
	// Defaults to 10s — PRD §21 requires drift to heal within 30s.
	Interval time.Duration
	// StopGrace bounds SIGTERM before SIGKILL. Defaults to the driver's.
	StopGrace time.Duration
	// LogDir receives per-alloc log files.
	LogDir string
	// VolumeDir is the root of local volume storage (PRD §8: data_dir/volumes).
	VolumeDir string
	// ServiceCIDR is the pool service frontends are allocated from
	// (PRD §15.1). Empty means DefaultServiceCIDR.
	ServiceCIDR string
	// ResolvConfDir holds the generated per-project resolv.conf files.
	ResolvConfDir string
	// Nameserver is the address allocs are pointed at for DNS. Empty means
	// allocs keep whatever resolv.conf their image ships.
	Nameserver string
	// Now is injectable for tests.
	Now func() time.Time
}

// DefaultInterval keeps drift correction inside the §21 budget.
const DefaultInterval = 10 * time.Second

// Reconciler converges actual state to desired state.
type Reconciler struct {
	store   Store
	driver  Driver
	network Network
	log     *slog.Logger
	now     func() time.Time

	vips *vipAllocator

	interval      time.Duration
	stopGrace     time.Duration
	logDir        string
	volumeDir     string
	resolvConfDir string
	nameserver    string
}

// New builds a Reconciler.
func New(cfg Config) (*Reconciler, error) {
	if cfg.Store == nil {
		return nil, errors.New("reconciler: store is required")
	}
	if cfg.Driver == nil {
		return nil, errors.New("reconciler: driver is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	vips, err := newVIPAllocator(cfg.Store, cfg.ServiceCIDR)
	if err != nil {
		return nil, err
	}
	return &Reconciler{
		store:         cfg.Store,
		vips:          vips,
		driver:        cfg.Driver,
		network:       cfg.Network,
		log:           cfg.Logger,
		now:           cfg.Now,
		interval:      cfg.Interval,
		stopGrace:     cfg.StopGrace,
		logDir:        cfg.LogDir,
		volumeDir:     cfg.VolumeDir,
		resolvConfDir: cfg.ResolvConfDir,
		nameserver:    cfg.Nameserver,
	}, nil
}

// Result summarises one pass, for logs and tests.
type Result struct {
	Planned  int
	Applied  int
	Failed   int
	Observed int
	// Reaped counts orphaned network attachments reclaimed this pass.
	Reaped int
}

// Run drives the loop until the context is cancelled. Trigger is an optional
// channel that wakes the loop early — an apply, or a task exit, should not wait
// out the full interval.
func (r *Reconciler) Run(ctx context.Context, trigger <-chan struct{}) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		if _, err := r.Reconcile(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A failed pass is not fatal: the next one retries. Converging is
			// the loop's job, and transient containerd errors are expected.
			r.log.Error("reconcile pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-trigger:
		}
	}
}

// Reconcile runs one pass: observe reality, record what changed, plan, apply.
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	var result Result

	desired, err := r.loadDesired(ctx)
	if err != nil {
		return result, fmt.Errorf("load desired state: %w", err)
	}

	// Policy before allocs, and fail the pass if it does not land.
	//
	// An endpoint with no policy selecting it has no ingress enforcement at all
	// — it is reachable from every other workload on the node. So a project
	// whose isolation policy could not be written must not get new allocs:
	// convergence stalling is recoverable, a workload started unprotected is
	// not. Allocs already running are unaffected; the next pass retries.
	if err := r.syncPolicies(ctx, desired); err != nil {
		return result, fmt.Errorf("sync network policies: %w", err)
	}

	records, err := r.loadRecords(ctx)
	if err != nil {
		return result, fmt.Errorf("load alloc records: %w", err)
	}
	actual, err := r.loadActual(ctx, desired, records)
	if err != nil {
		return result, fmt.Errorf("load actual state: %w", err)
	}

	world := World{Desired: desired, Records: records, Actual: actual, Now: r.now()}

	// Observation is separate from planning on purpose: recording "this alloc
	// crashed at T with code N" is a fact, while deciding what to do about it
	// is policy. Keeping them apart is what lets the planner stay pure.
	changed := Observe(world)
	if len(changed) > 0 {
		if err := r.persist(ctx, changed); err != nil {
			return result, fmt.Errorf("persist observations: %w", err)
		}
		for id, rec := range changed {
			records[id] = rec
		}
		world.Records = records
		result.Observed = len(changed)
	}

	actions := Plan(world)
	result.Planned = len(actions)

	for _, action := range actions {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := r.apply(ctx, world, action); err != nil {
			// One alloc's failure must not stall the others: log it, count it,
			// and let the next pass retry.
			result.Failed++
			r.log.Error("action failed",
				"action", action.Kind, "alloc", action.AllocID, "reason", action.Reason, "error", err)
			continue
		}
		result.Applied++
		r.log.Info("action applied",
			"action", action.Kind, "alloc", action.AllocID, "reason", action.Reason)
	}

	// Everything below reasons about the world *after* the actions, so refresh
	// the view when there were any. Without this a service deployed in this
	// pass would have no backends until the next one — a full interval of a
	// frontend that exists and answers nothing.
	//
	// Skipped when nothing was applied, which is the overwhelmingly common case:
	// a steady-state pass should not cost an extra round trip per project.
	if result.Applied > 0 {
		if actual, err := r.loadActual(ctx, desired, records); err != nil {
			r.log.Warn("cannot re-read alloc state after applying actions", "error", err)
		} else {
			world.Actual = actual
		}
	}

	// Datapath state is read once, after the actions: the allocs just created
	// are attached by now, and the allocs just removed are not.
	attachments := r.attachments(ctx)

	// Sweep before publishing backends, so an orphan cannot be advertised as
	// somewhere to send traffic even for one settle window.
	result.Reaped = r.reapNetwork(ctx, world, attachments)
	if err := r.syncServices(ctx, world, attachments); err != nil {
		// Unlike policy, this is not fail-closed: stale load balancing points at
		// allocs that were healthy a few seconds ago, which is a degraded
		// service rather than an unprotected one. Failing the pass here would
		// stop crash recovery over a routing update.
		r.log.Error("sync service load balancing", "error", err)
	}
	return result, nil
}

// attachments reads what the datapath holds, or nil if the driver cannot say.
func (r *Reconciler) attachments(ctx context.Context) map[string]network.Attachment {
	inspector, ok := r.network.(NetworkInspector)
	if !ok {
		return nil
	}
	found, err := inspector.Attachments(ctx)
	if err != nil {
		// Not worth failing a pass over: every other part of convergence still
		// works, and the next pass retries. A nil map disables both the sweep
		// and the LB update, which is the safe reading of "I cannot see".
		r.log.Warn("cannot read network attachments", "error", err)
		return nil
	}
	return found
}

// syncServices publishes each service's frontend and its live backends.
func (r *Reconciler) syncServices(ctx context.Context, w World, attachments map[string]network.Attachment) error {
	lb, ok := r.network.(LoadBalancer)
	if !ok {
		return nil
	}
	if attachments == nil {
		return nil // no view of the datapath; leave the last known good state alone
	}

	// Only services that will actually get a frontend hold an address. A worker
	// with no ports would otherwise consume one for its whole life and shift
	// every later assignment along, which makes the pool harder to read and the
	// numbering harder to explain.
	refs := make([]serviceRef, 0, len(w.Desired))
	for _, d := range w.Desired {
		if len(d.Ports) == 0 {
			continue
		}
		refs = append(refs, serviceRef{Project: d.Project, Service: d.Service})
	}
	vips, err := r.vips.Sync(ctx, refs)
	if err != nil {
		return err
	}

	services := make([]network.Service, 0, len(w.Desired))
	for _, d := range w.Desired {
		if len(d.Ports) == 0 {
			continue // nothing to load balance
		}
		ports := make([]network.ServicePort, 0, len(d.Ports))
		for _, p := range d.Ports {
			ports = append(ports, network.ServicePort{
				Name: p.Name, Port: p.Container, TargetPort: p.Container,
			})
		}
		services = append(services, network.Service{
			Project:  d.Project,
			Service:  d.Service,
			VIP:      vips[d.Project+"/"+d.Service],
			Ports:    ports,
			Backends: backendsFor(w, d, attachments),
		})
	}
	return lb.SyncServices(ctx, services)
}

// backendsFor picks the allocs of one service that should receive traffic.
//
// "Desired" is not the test — "serving right now" is. An alloc that is created
// but not started, waiting out a restart backoff, or has exhausted its budget
// may still hold an attachment, and routing real requests into it is a black
// hole.
//
// The two conditions are what the runtime reports and what the datapath
// reports, deliberately not what the Store remembers. An alloc's record is
// written at the end of the pass that changed it, so a just-restarted alloc
// still reads `backoff` while containerd already reports it running — trusting
// the record would drop a healthy backend for a full interval. Observed state
// is the truth about whether traffic can be served; the record is the truth
// about why, which is a different question.
//
// A ready endpoint is required as well: one that has not resolved its identity
// carries reserved:init and has its traffic denied in both directions, so
// advertising it would route requests straight into a drop.
func backendsFor(w World, d Desired, attachments map[string]network.Attachment) []network.Backend {
	backends := make([]network.Backend, 0, d.Count)
	for i := range d.Count {
		id := AllocID(d.Project, d.Service, i)

		if status, ok := w.Actual[id]; !ok || status.State != runtime.StateRunning {
			continue
		}
		att, ok := attachments[id]
		if !ok || !att.Ready || att.IPv4 == "" {
			continue
		}
		backends = append(backends, network.Backend{AllocID: id, IPv4: att.IPv4})
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].AllocID < backends[j].AllocID })
	return backends
}

// resolvConfFor renders the project's resolv.conf, or reports why it cannot.
func (r *Reconciler) resolvConfFor(project string) (string, error) {
	if r.resolvConfDir == "" || r.nameserver == "" {
		return "", errNoInternalDNS
	}
	return network.WriteResolvConf(r.resolvConfDir, project, r.nameserver)
}

// errNoInternalDNS marks a node with no embedded resolver configured — the
// netns development mode, or an operator who turned DNS off.
var errNoInternalDNS = errors.New("no internal resolver is configured")

// syncPolicies makes network policy match the set of projects in desired state.
func (r *Reconciler) syncPolicies(ctx context.Context, desired []Desired) error {
	syncer, ok := r.network.(PolicySyncer)
	if !ok {
		return nil
	}
	// One entry per project, carrying only the services that asked for extra
	// ingress. Sorted so an unchanged spec produces an identical call — the
	// writer skips unchanged files, and that only works if the input is stable.
	byProject := map[string]*network.ProjectPolicy{}
	for _, d := range desired {
		policy, ok := byProject[d.Project]
		if !ok {
			policy = &network.ProjectPolicy{Project: d.Project}
			byProject[d.Project] = policy
		}
		if len(d.AllowFrom) == 0 {
			continue
		}
		peers := make([]network.ServiceRef, 0, len(d.AllowFrom))
		for _, p := range d.AllowFrom {
			peers = append(peers, network.ServiceRef{Project: p.Project, Service: p.Service})
		}
		policy.Services = append(policy.Services, network.ServicePolicy{
			Service: d.Service, AllowFrom: peers,
		})
	}

	out := make([]network.ProjectPolicy, 0, len(byProject))
	for _, name := range sortedKeys(byProject) {
		policy := byProject[name]
		sort.Slice(policy.Services, func(i, j int) bool {
			return policy.Services[i].Service < policy.Services[j].Service
		})
		out = append(out, *policy)
	}
	return syncer.SyncPolicies(ctx, out)
}

// reapNetwork detaches network attachments belonging to no known alloc.
//
// "Known" is deliberately generous — desired, recorded, or running. An alloc
// that is mid-create is desired but has no record yet, and detaching it would
// cut the network out from under a workload that is about to start. Reclaiming
// a leaked IP a pass later is free; taking down a live alloc is not.
func (r *Reconciler) reapNetwork(ctx context.Context, w World, attachments map[string]network.Attachment) int {
	if len(attachments) == 0 {
		return 0
	}

	known := make(map[string]struct{}, len(w.Records)+len(w.Actual))
	for _, d := range w.Desired {
		for i := range d.Count {
			known[AllocID(d.Project, d.Service, i)] = struct{}{}
		}
	}
	for id := range w.Records {
		known[id] = struct{}{}
	}
	for id := range w.Actual {
		known[id] = struct{}{}
	}

	var reaped int
	for _, id := range sortedKeys(attachments) {
		if _, ok := known[id]; ok {
			continue
		}
		if err := r.network.Detach(ctx, runtime.AllocSpec{ID: id}); err != nil {
			r.log.Error("reap network attachment", "alloc", id, "error", err)
			continue
		}
		reaped++
		r.log.Info("reaped orphaned network attachment", "alloc", id)
	}
	return reaped
}

// Observe turns "what containerd reports" into durable facts: crashes recorded,
// backoff deadlines set, restart budgets marked exhausted. It returns only the
// records that changed, so a steady-state pass writes nothing to the Store.
func Observe(w World) map[string]AllocRecord {
	changed := map[string]AllocRecord{}

	byService := make(map[string]Desired, len(w.Desired))
	for _, d := range w.Desired {
		byService[d.Project+"/"+d.Service] = d
	}

	for id, status := range w.Actual {
		record, ok := w.Records[id]
		if !ok {
			continue // orphan: the planner removes it, there is nothing to record
		}
		desired, isDesired := byService[record.Project+"/"+record.Service]

		switch status.State {
		case runtime.StateRunning:
			if record.State != AllocRunning {
				record.State = AllocRunning
				record.NextRestartAt = time.Time{}
				record.UpdatedAt = w.Now
				changed[id] = record
			}

		case runtime.StateStopped:
			// Only interesting if we thought it was running: that is a crash.
			if record.State != AllocRunning && record.State != AllocPending {
				continue
			}
			if !isDesired || record.Index >= desired.Count {
				continue // being scaled in or removed; not a crash
			}
			record.LastExitCode = status.ExitCode
			record.LastExitAt = exitTime(status, w.Now)
			record.UpdatedAt = w.Now

			if record.Restarts >= desired.Restart.attempts() {
				record.State = AllocFailed
			} else {
				// Wait before restarting. The delay escalates with the attempt
				// number so a service that crashes on startup does not spin.
				record.State = AllocBackoff
				record.NextRestartAt = w.Now.Add(desired.Restart.delayFor(record.Restarts + 1))
			}
			changed[id] = record
		}
	}
	return changed
}

func exitTime(status runtime.Status, fallback time.Time) time.Time {
	if status.ExitedAt.IsZero() {
		return fallback
	}
	return status.ExitedAt
}

// apply executes one action.
func (r *Reconciler) apply(ctx context.Context, w World, action Action) error {
	desired, ok := desiredFor(w, action)
	switch action.Kind {
	case ActionCreate, ActionStart, ActionRestart:
		if !ok {
			return fmt.Errorf("no desired state for %s", action.AllocID)
		}
	}

	switch action.Kind {
	case ActionCreate:
		return r.create(ctx, desired, action)

	case ActionStart:
		if err := r.driver.Start(ctx, action.Project, action.AllocID); err != nil {
			return err
		}
		return r.markRunning(ctx, w, action)

	case ActionRestart:
		// Tear the old container down first: containerd will not reuse the id,
		// and a half-dead task would keep its cgroup and netns pinned.
		if err := r.teardown(ctx, desired, action); err != nil {
			return err
		}
		return r.create(ctx, desired, action)

	case ActionRemove:
		return r.remove(ctx, w, desired, ok, action)

	default:
		return fmt.Errorf("unknown action %q", action.Kind)
	}
}

func (r *Reconciler) create(ctx context.Context, desired Desired, action Action) error {
	// Which resolver an alloc talks to is a property of the node, not the job,
	// so it is filled in here rather than carried through the Store.
	if path, err := r.resolvConfFor(desired.Project); err != nil {
		// Not fatal: an alloc with the image's own resolv.conf can still reach
		// external names, it just cannot resolve peers by their internal name.
		// Refusing to start it would turn a degraded deploy into no deploy.
		r.log.Warn("cannot provide internal DNS to alloc",
			"project", desired.Project, "alloc", action.AllocID, "error", err)
	} else {
		desired.ResolvConfPath = path
	}

	spec := AllocSpecFor(desired, action.Index, r.logDir, r.volumeDir)

	if _, err := r.driver.EnsureImage(ctx, desired.Project, desired.Image); err != nil {
		return fmt.Errorf("image: %w", err)
	}
	// Volume directories exist before the task does. A bind mount whose source
	// is missing would otherwise be created by the runtime as a root-owned
	// directory at an unpredictable moment, or fail the alloc outright.
	if err := r.ensureVolumes(desired, action.Index); err != nil {
		return err
	}
	// Network before task: an alloc must never run without its network, and on
	// Cilium an unlabelled endpoint has its traffic denied (M0 spikes ①, ②).
	if r.network != nil {
		if err := r.network.Attach(ctx, spec); err != nil {
			return fmt.Errorf("attach network: %w", err)
		}
	} else {
		spec.NetnsPath = ""
	}
	if err := r.driver.Create(ctx, spec); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if err := r.driver.Start(ctx, desired.Project, spec.ID); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	now := r.now()
	record := AllocRecord{
		ID: spec.ID, Project: desired.Project, Service: desired.Service, Index: action.Index,
		Image: desired.Image, State: AllocRunning, CreatedAt: now, UpdatedAt: now,
	}
	if existing, err := r.loadRecord(ctx, desired.Project, desired.Service, action.Index); err == nil {
		// Preserve the restart history across a restart: the budget is the
		// whole point, and resetting it here would make attempts unbounded.
		record.CreatedAt = existing.CreatedAt
		record.Restarts = existing.Restarts
		record.LastExitCode = existing.LastExitCode
		record.LastExitAt = existing.LastExitAt
		if action.Kind == ActionRestart {
			record.Restarts++
		}
	}
	return r.persist(ctx, map[string]AllocRecord{record.ID: record})
}

// ensureVolumes creates each declared volume's host directory. Data is never
// deleted on teardown: a volume outliving its alloc is the entire point (§8).
//
// It walks the service's volumes rather than the spec's mounts, because not
// every mount is a volume. resolv.conf is bind-mounted from a *file*, and
// running MkdirAll over the mount list would try to turn it into a directory —
// which fails, and takes the whole alloc with it.
func (r *Reconciler) ensureVolumes(d Desired, index int) error {
	for _, v := range d.Volumes {
		path := VolumeHostPath(r.volumeDir, d.Project, d.Service, index, v.Name)
		if err := os.MkdirAll(path, 0o750); err != nil {
			return fmt.Errorf("volume %s: %w", v.Name, err)
		}
	}
	return nil
}

func (r *Reconciler) teardown(ctx context.Context, desired Desired, action Action) error {
	if err := r.driver.Stop(ctx, action.Project, action.AllocID, r.stopGrace); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	if err := r.driver.Remove(ctx, action.Project, action.AllocID); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	// Detach after the task is gone: CNI DEL needs the namespace to still
	// exist (M0 spike ②).
	if r.network != nil {
		spec := AllocSpecFor(desired, action.Index, r.logDir, r.volumeDir)
		if err := r.network.Detach(ctx, spec); err != nil {
			return fmt.Errorf("detach network: %w", err)
		}
	}
	return nil
}

func (r *Reconciler) remove(ctx context.Context, w World, desired Desired, stillDeclared bool, action Action) error {
	if err := r.teardown(ctx, desired, action); err != nil {
		return err
	}

	record, ok := w.Records[action.AllocID]
	if !ok {
		return nil // nothing durable to clean up
	}
	// An alloc that exhausted its restart budget keeps its record, marked
	// failed: `kanea ps` must be able to explain why it is not running. The
	// decision comes from the record and the policy, never from the reason
	// string — that text is for humans.
	//
	// But only while the service still exists. Once it is deleted, keeping the
	// record would leave a permanent ghost in `kanea ps` that no command could
	// clear.
	if stillDeclared && (record.State == AllocFailed || record.Restarts >= desired.Restart.attempts()) {
		record.State = AllocFailed
		record.UpdatedAt = r.now()
		return r.persist(ctx, map[string]AllocRecord{record.ID: record})
	}
	_, err := r.store.Apply(ctx, store.DeleteMutation(store.KindAlloc, record.Key()))
	return err
}

func (r *Reconciler) markRunning(ctx context.Context, w World, action Action) error {
	return r.updateRecord(ctx, w, action, func(rec *AllocRecord) {
		rec.State = AllocRunning
		rec.NextRestartAt = time.Time{}
		rec.UpdatedAt = r.now()
	})
}

func (r *Reconciler) updateRecord(ctx context.Context, w World, action Action, mutate func(*AllocRecord)) error {
	record, ok := w.Records[action.AllocID]
	if !ok {
		return nil
	}
	mutate(&record)
	return r.persist(ctx, map[string]AllocRecord{record.ID: record})
}

// persist writes alloc records in one batch, so a multi-alloc change commits
// and replicates atomically (store.Apply allocates a single index per batch).
func (r *Reconciler) persist(ctx context.Context, records map[string]AllocRecord) error {
	muts := make([]store.Mutation, 0, len(records))
	for _, rec := range sortedRecords(records) {
		mut, err := store.PutMutation(store.KindAlloc, rec.Key(), rec)
		if err != nil {
			return err
		}
		muts = append(muts, mut)
	}
	if len(muts) == 0 {
		return nil
	}
	_, err := r.store.Apply(ctx, muts...)
	return err
}

// ---- state loading ----

func (r *Reconciler) loadDesired(ctx context.Context) ([]Desired, error) {
	var out []Desired
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[Desired](ctx, r.store, store.KindService, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

func (r *Reconciler) loadRecords(ctx context.Context) (map[string]AllocRecord, error) {
	out := map[string]AllocRecord{}
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[AllocRecord](ctx, r.store, store.KindAlloc, opts)
		if err != nil {
			return nil, err
		}
		for _, rec := range values {
			out[rec.ID] = rec
		}
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

func (r *Reconciler) loadRecord(ctx context.Context, project, service string, index int) (AllocRecord, error) {
	rec, _, err := store.GetValue[AllocRecord](ctx, r.store, store.KindAlloc, AllocKey(project, service, index))
	return rec, err
}

// loadActual asks the driver about every project that appears in desired state
// or in the records — the latter so an alloc whose service was deleted is still
// discovered and cleaned up.
func (r *Reconciler) loadActual(ctx context.Context, desired []Desired, records map[string]AllocRecord) (map[string]runtime.Status, error) {
	projects := map[string]struct{}{}
	for _, d := range desired {
		projects[d.Project] = struct{}{}
	}
	for _, rec := range records {
		projects[rec.Project] = struct{}{}
	}

	out := map[string]runtime.Status{}
	for _, project := range sortedKeys(projects) {
		statuses, err := r.driver.List(ctx, project)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", project, err)
		}
		for _, s := range statuses {
			out[s.ID] = s
		}
	}
	return out, nil
}

func desiredFor(w World, action Action) (Desired, bool) {
	for _, d := range w.Desired {
		if d.Project == action.Project && d.Service == action.Service {
			return d, true
		}
	}
	return Desired{Project: action.Project, Service: action.Service}, false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedRecords(m map[string]AllocRecord) []AllocRecord {
	out := make([]AllocRecord, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// NetnsNetwork is the M1 network: a persistent netns per alloc, no CNI. M2
// replaces it with the Cilium attach (CNI ADD plus the endpoint label patch)
// behind the same interface — the ordering guarantees are identical, which is
// why the seam is here.
type NetnsNetwork struct{}

// Attach creates the alloc's network namespace.
func (NetnsNetwork) Attach(_ context.Context, spec runtime.AllocSpec) error {
	_, err := runtime.CreateNetns(spec.ID)
	return err
}

// Detach removes it. Called only after the task is gone.
func (NetnsNetwork) Detach(_ context.Context, spec runtime.AllocSpec) error {
	return runtime.DeleteNetns(spec.ID)
}

// NetnsNetwork deliberately does not implement NetworkInspector. /run/netns is a
// shared host resource and a bare namespace carries no mark of who made it, so
// "everything I did not expect" would include namespaces belonging to other
// tools — and reaping means deleting. The Cilium driver can reap precisely
// because its endpoints carry an ownership label.
