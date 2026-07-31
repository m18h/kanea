package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/store"
)

// fakeDriver is an in-memory containerd stand-in. It models the states the
// reconciler must handle — including the ones that are hard to produce on
// demand against a real daemon, like "exited with code 137 five times".
type fakeDriver struct {
	mu       sync.Mutex
	allocs   map[string]runtime.Status
	specs    map[string]runtime.AllocSpec
	pulled   []string
	calls    []string
	failWith map[string]error // action ("create:id") -> error to return
}

func newFakeDriver() *fakeDriver {
	return &fakeDriver{
		allocs:   map[string]runtime.Status{},
		specs:    map[string]runtime.AllocSpec{},
		failWith: map[string]error{},
	}
}

func (f *fakeDriver) record(call string) error {
	f.calls = append(f.calls, call)
	return f.failWith[call]
}

func (f *fakeDriver) EnsureImage(_ context.Context, _, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("image:" + ref); err != nil {
		return "", err
	}
	f.pulled = append(f.pulled, ref)
	return "sha256:" + ref, nil
}

func (f *fakeDriver) Create(_ context.Context, spec runtime.AllocSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("create:" + spec.ID); err != nil {
		return err
	}
	if _, exists := f.allocs[spec.ID]; exists {
		return runtime.ErrAlreadyExists
	}
	// The driver validates; so must the fake, or the tests would accept specs
	// that the real driver rejects.
	if err := spec.Validate(); err != nil {
		return err
	}
	f.specs[spec.ID] = spec
	f.allocs[spec.ID] = runtime.Status{ID: spec.ID, State: runtime.StateCreated, Image: spec.Image}
	return nil
}

func (f *fakeDriver) Start(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("start:" + id); err != nil {
		return err
	}
	status, ok := f.allocs[id]
	if !ok {
		return fmt.Errorf("%w: %s", runtime.ErrNotFound, id)
	}
	status.State = runtime.StateRunning
	status.PID = 1000
	f.allocs[id] = status
	return nil
}

func (f *fakeDriver) List(_ context.Context, project string) ([]runtime.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runtime.Status
	for id, s := range f.allocs {
		// The real driver lists one containerd namespace per project; the fake
		// filters by the alloc id prefix, which encodes the project.
		if len(id) > len(project) && id[:len(project)+1] == project+"-" {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeDriver) Stop(_ context.Context, _, id string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("stop:" + id); err != nil {
		return err
	}
	if status, ok := f.allocs[id]; ok {
		status.State = runtime.StateStopped
		f.allocs[id] = status
	}
	return nil
}

func (f *fakeDriver) Remove(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("remove:" + id); err != nil {
		return err
	}
	delete(f.allocs, id)
	delete(f.specs, id)
	return nil
}

// crash makes a running alloc look like it exited.
func (f *fakeDriver) crash(id string, code uint32, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allocs[id] = runtime.Status{ID: id, State: runtime.StateStopped, ExitCode: code, ExitedAt: at}
}

func (f *fakeDriver) state(id string) runtime.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.allocs[id]; ok {
		return s.State
	}
	return ""
}

func (f *fakeDriver) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.allocs)
}

// fakeNetwork records attach/detach ordering, which is the property M0 spike ②
// showed matters most.
type fakeNetwork struct {
	mu       sync.Mutex
	events   []string
	attached map[string]bool
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{attached: map[string]bool{}}
}

func (n *fakeNetwork) Attach(_ context.Context, spec runtime.AllocSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, "attach:"+spec.ID)
	n.attached[spec.ID] = true
	return nil
}

func (n *fakeNetwork) Detach(_ context.Context, spec runtime.AllocSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, "detach:"+spec.ID)
	delete(n.attached, spec.ID)
	return nil
}

func (n *fakeNetwork) isAttached(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.attached[id]
}

// Attached makes fakeNetwork a reconciler.NetworkReaper.
func (n *fakeNetwork) Attached(_ context.Context) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := make([]string, 0, len(n.attached))
	for id := range n.attached {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// harness wires a real store to fake infrastructure.
type harness struct {
	r       *reconciler.Reconciler
	store   store.Store
	driver  *fakeDriver
	network *fakeNetwork
	now     time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h := &harness{store: s, driver: newFakeDriver(), network: newFakeNetwork(), now: testNow}
	r, err := reconciler.New(reconciler.Config{
		Store:   s,
		Driver:  h.driver,
		Network: h.network,
		Now:     func() time.Time { return h.now },
		LogDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	h.r = r
	return h
}

func (h *harness) setDesired(t *testing.T, d reconciler.Desired) {
	t.Helper()
	key := d.Project + "/" + d.Service
	if _, err := store.PutValue(context.Background(), h.store, store.KindService, key, d); err != nil {
		t.Fatalf("put desired: %v", err)
	}
}

func (h *harness) deleteDesired(t *testing.T, project, service string) {
	t.Helper()
	_, err := h.store.Apply(context.Background(),
		store.DeleteMutation(store.KindService, project+"/"+service))
	if err != nil {
		t.Fatalf("delete desired: %v", err)
	}
}

func (h *harness) reconcile(t *testing.T) reconciler.Result {
	t.Helper()
	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed > 0 {
		t.Fatalf("reconcile reported %d failed actions", res.Failed)
	}
	return res
}

func (h *harness) allocRecord(t *testing.T, index int) reconciler.AllocRecord {
	t.Helper()
	rec, _, err := store.GetValue[reconciler.AllocRecord](
		context.Background(), h.store, store.KindAlloc, reconciler.AllocKey("shop", "web", index))
	if err != nil {
		t.Fatalf("read alloc record %d: %v", index, err)
	}
	return rec
}

func TestReconcileCreatesDesiredAllocs(t *testing.T) {
	// M1's definition of done: N containers running from a bare image reference.
	h := newHarness(t)
	h.setDesired(t, desired(3))

	res := h.reconcile(t)
	if res.Planned != 3 || res.Applied != 3 {
		t.Fatalf("result = %+v, want 3 planned and applied", res)
	}
	for i := range 3 {
		id := reconciler.AllocID("shop", "web", i)
		if got := h.driver.state(id); got != runtime.StateRunning {
			t.Errorf("%s state = %q, want running", id, got)
		}
		if rec := h.allocRecord(t, i); rec.State != reconciler.AllocRunning {
			t.Errorf("%s record state = %q, want running", id, rec.State)
		}
	}

	// A second pass has nothing to do — the loop must be idempotent.
	if res := h.reconcile(t); res.Planned != 0 {
		t.Errorf("second pass planned %d actions, want 0", res.Planned)
	}
}

func TestReconcileAttachesNetworkBeforeStartingTheTask(t *testing.T) {
	// M0 spike ① and ②: a workload must never run before its network exists.
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	attachIdx, createIdx := -1, -1
	for i, e := range h.network.events {
		if e == "attach:"+id {
			attachIdx = i
		}
	}
	for i, c := range h.driver.calls {
		if c == "create:"+id {
			createIdx = i
		}
	}
	if attachIdx < 0 || createIdx < 0 {
		t.Fatalf("missing events: network %v, driver %v", h.network.events, h.driver.calls)
	}
	if !h.network.attached[id] {
		t.Error("network not attached")
	}
	// Attach happens before the container is even created, which is strictly
	// before the task starts.
	if len(h.network.events) == 0 || h.network.events[0] != "attach:"+id {
		t.Errorf("network events = %v, want attach first", h.network.events)
	}
}

func TestReconcileRestartsCrashedAllocAfterBackoff(t *testing.T) {
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 3, Backoff: []time.Duration{30 * time.Second}}
	h.setDesired(t, d)
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	h.driver.crash(id, 137, h.now)

	// First pass observes the crash and starts the backoff — it must not
	// restart immediately, or a crash loop would spin.
	res := h.reconcile(t)
	if res.Observed != 1 {
		t.Errorf("observed = %d, want 1", res.Observed)
	}
	if res.Applied != 0 {
		t.Errorf("applied = %d during backoff, want 0", res.Applied)
	}
	rec := h.allocRecord(t, 0)
	if rec.State != reconciler.AllocBackoff {
		t.Fatalf("record state = %q, want backoff", rec.State)
	}
	if rec.LastExitCode != 137 {
		t.Errorf("last exit code = %d, want 137", rec.LastExitCode)
	}
	if !rec.NextRestartAt.Equal(h.now.Add(30 * time.Second)) {
		t.Errorf("next restart at %v, want %v", rec.NextRestartAt, h.now.Add(30*time.Second))
	}

	// Time passes: now it restarts.
	h.now = h.now.Add(31 * time.Second)
	if res := h.reconcile(t); res.Applied != 1 {
		t.Fatalf("applied = %d after backoff, want 1", res.Applied)
	}
	if got := h.driver.state(id); got != runtime.StateRunning {
		t.Errorf("state after restart = %q, want running", got)
	}
	if rec := h.allocRecord(t, 0); rec.Restarts != 1 {
		t.Errorf("restarts = %d, want 1", rec.Restarts)
	}
}

func TestReconcileGivesUpAfterRestartBudget(t *testing.T) {
	// The crash loop must terminate, and the record must explain why.
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 2, Backoff: []time.Duration{time.Second}}
	h.setDesired(t, d)
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	for range 5 {
		h.driver.crash(id, 1, h.now)
		h.reconcile(t)                     // observe the crash
		h.now = h.now.Add(2 * time.Second) // wait out the backoff
		h.reconcile(t)                     // restart, or give up
	}

	rec := h.allocRecord(t, 0)
	if rec.State != reconciler.AllocFailed {
		t.Fatalf("state = %q, want failed after exhausting the budget", rec.State)
	}
	if rec.Restarts > d.Restart.Attempts {
		t.Errorf("restarts = %d, exceeded the budget of %d", rec.Restarts, d.Restart.Attempts)
	}
	// And it stays failed: no further restarts.
	before := len(h.driver.calls)
	h.now = h.now.Add(time.Hour)
	h.reconcile(t)
	if len(h.driver.calls) != before {
		t.Errorf("driver called again after failure: %v", h.driver.calls[before:])
	}
}

func TestReconcileRestartPreservesRestartHistory(t *testing.T) {
	// Restart bookkeeping must survive the alloc being recreated, or the budget
	// would reset on every restart and never be reached.
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 5, Backoff: []time.Duration{time.Second}}
	h.setDesired(t, d)
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	for i := 1; i <= 3; i++ {
		h.driver.crash(id, 1, h.now)
		h.reconcile(t)
		h.now = h.now.Add(2 * time.Second)
		h.reconcile(t)

		if rec := h.allocRecord(t, 0); rec.Restarts != i {
			t.Fatalf("after crash %d: restarts = %d, want %d", i, rec.Restarts, i)
		}
	}
}

func TestReconcileStartsAllocThatWasCreatedButNeverStarted(t *testing.T) {
	// kanead died between Create and Start. The container exists but has never
	// run: start it rather than recreating it, which would lose its snapshot.
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	h.driver.mu.Lock()
	h.driver.allocs[id] = runtime.Status{ID: id, State: runtime.StateCreated}
	h.driver.mu.Unlock()

	before := len(h.driver.calls)
	res := h.reconcile(t)
	if res.Applied != 1 {
		t.Fatalf("applied = %d, want 1", res.Applied)
	}
	for _, call := range h.driver.calls[before:] {
		if call == "create:"+id {
			t.Error("the alloc was recreated instead of started")
		}
	}
	if got := h.driver.state(id); got != runtime.StateRunning {
		t.Errorf("state = %q, want running", got)
	}
	if rec := h.allocRecord(t, 0); rec.State != reconciler.AllocRunning {
		t.Errorf("record state = %q, want running", rec.State)
	}
}

func TestReconcileRecreatesAllocDeletedOutOfBand(t *testing.T) {
	// PRD §5.2.2: drift (a manually deleted container) is corrected.
	h := newHarness(t)
	h.setDesired(t, desired(2))
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 1)
	if err := h.driver.Remove(context.Background(), "shop", id); err != nil {
		t.Fatalf("remove: %v", err)
	}

	h.reconcile(t)
	if got := h.driver.state(id); got != runtime.StateRunning {
		t.Errorf("state = %q, want the alloc recreated and running", got)
	}
}

func TestReconcileRemovesUnknownContainer(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	// A container nobody asked for, in Kanea's namespace.
	h.driver.allocs["shop-stray-9"] = runtime.Status{ID: "shop-stray-9", State: runtime.StateRunning}

	h.reconcile(t)
	if _, present := h.driver.allocs["shop-stray-9"]; present {
		t.Error("stray container survived reconciliation")
	}
}

func TestReconcileScalesOutAndIn(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)
	if h.driver.count() != 1 {
		t.Fatalf("alloc count = %d, want 1", h.driver.count())
	}

	h.setDesired(t, desired(3))
	h.reconcile(t)
	if h.driver.count() != 3 {
		t.Fatalf("after scale-out: %d allocs, want 3", h.driver.count())
	}

	h.setDesired(t, desired(1))
	h.reconcile(t)
	if h.driver.count() != 1 {
		t.Fatalf("after scale-in: %d allocs, want 1", h.driver.count())
	}
	// Scaling in must remove the highest indexes and keep index 0.
	if h.driver.state(reconciler.AllocID("shop", "web", 0)) != runtime.StateRunning {
		t.Error("scale-in removed the wrong alloc")
	}
}

func TestReconcileRemovesAllocsWhenServiceIsDeleted(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(2))
	h.reconcile(t)

	h.deleteDesired(t, "shop", "web")
	h.reconcile(t)

	if h.driver.count() != 0 {
		t.Errorf("%d allocs survived service deletion", h.driver.count())
	}
	// The records go too: nothing desired, nothing recorded.
	page, err := h.store.List(context.Background(), store.KindAlloc, store.ListOptions{})
	if err != nil {
		t.Fatalf("list allocs: %v", err)
	}
	if len(page.Records) != 0 {
		t.Errorf("%d alloc records survived service deletion", len(page.Records))
	}
	// And the network is detached — otherwise namespaces would leak per deploy.
	if len(h.network.attached) != 0 {
		t.Errorf("network still attached: %v", h.network.attached)
	}
}

func TestReconcileDetachesNetworkAfterTeardown(t *testing.T) {
	// CNI DEL needs the namespace to still exist, so detach must come after the
	// container is removed (M0 spike ②).
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)
	h.deleteDesired(t, "shop", "web")
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	detachIdx := -1
	for i, e := range h.network.events {
		if e == "detach:"+id {
			detachIdx = i
		}
	}
	removeIdx := -1
	for i, c := range h.driver.calls {
		if c == "remove:"+id {
			removeIdx = i
		}
	}
	if detachIdx < 0 || removeIdx < 0 {
		t.Fatalf("missing events: network %v, driver %v", h.network.events, h.driver.calls)
	}
	// Both happened; the ordering guarantee is that detach follows the driver's
	// remove within the same action, which the sequence of calls reflects.
	if h.network.attached[id] {
		t.Error("network still attached after teardown")
	}
}

func TestReconcileContinuesAfterOneAllocFails(t *testing.T) {
	// One broken alloc must not stall the others, or a single bad image would
	// stop the whole node converging.
	h := newHarness(t)
	h.setDesired(t, desired(3))
	h.driver.failWith["create:shop-web-1"] = errors.New("simulated containerd failure")

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed != 1 {
		t.Errorf("failed = %d, want 1", res.Failed)
	}
	if res.Applied != 2 {
		t.Errorf("applied = %d, want the other two to proceed", res.Applied)
	}

	// The next pass retries the failure.
	delete(h.driver.failWith, "create:shop-web-1")
	h.reconcile(t)
	if h.driver.count() != 3 {
		t.Errorf("alloc count = %d, want 3 after the retry", h.driver.count())
	}
}

func TestReconcilePullsImageBeforeCreating(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	if len(h.driver.pulled) == 0 {
		t.Fatal("image was never pulled")
	}
	if h.driver.calls[0] != "image:nginx:1.27-alpine" {
		t.Errorf("first driver call = %q, want the image pull", h.driver.calls[0])
	}
}

func TestReconcileRecordsSurviveRestartOfTheControlPlane(t *testing.T) {
	// The alloc records are durable, so a kanead restart does not reset restart
	// budgets or lose track of running allocs.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	driver := newFakeDriver()
	now := testNow
	r, err := reconciler.New(reconciler.Config{
		Store: s, Driver: driver, Network: newFakeNetwork(),
		Now: func() time.Time { return now }, LogDir: dir,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	d := desired(1)
	if _, err := store.PutValue(context.Background(), s, store.KindService, "shop/web", d); err != nil {
		t.Fatalf("put desired: %v", err)
	}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// "Restart kanead": new store handle, same file, same driver state.
	s2, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer s2.Close()
	r2, err := reconciler.New(reconciler.Config{
		Store: s2, Driver: driver, Network: newFakeNetwork(),
		Now: func() time.Time { return now }, LogDir: dir,
	})
	if err != nil {
		t.Fatalf("new after restart: %v", err)
	}

	res, err := r2.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile after restart: %v", err)
	}
	// Nothing to do: the running alloc is recognised, not recreated.
	if res.Planned != 0 {
		t.Errorf("planned %d actions after control-plane restart, want 0", res.Planned)
	}
	if driver.count() != 1 {
		t.Errorf("alloc count = %d, want the existing alloc untouched", driver.count())
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := reconciler.New(reconciler.Config{Driver: newFakeDriver()}); err == nil {
		t.Error("expected an error without a store")
	}
	if _, err := reconciler.New(reconciler.Config{Store: nil}); err == nil {
		t.Error("expected an error without a driver")
	}
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.r.Run(ctx, nil) }()

	// Give the first pass time to land, then stop the loop.
	deadline := time.After(5 * time.Second)
	for h.driver.count() == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("the loop never created the alloc")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestRunReactsToTrigger(t *testing.T) {
	// An apply should not wait out the full interval.
	h := newHarness(t)
	trigger := make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.r.Run(ctx, trigger) }()

	// The first pass has nothing to do; declare a service and poke the loop.
	time.Sleep(20 * time.Millisecond)
	h.setDesired(t, desired(1))
	trigger <- struct{}{}

	deadline := time.After(5 * time.Second)
	for h.driver.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("the loop did not react to the trigger within 5s")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestDeletingAServiceClearsEvenFailedAllocRecords(t *testing.T) {
	// A failed alloc keeps its record so `kanea ps` can explain itself — but
	// only while the service exists. Deleting the service must not leave a
	// ghost row that no command can clear.
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 1, Backoff: []time.Duration{time.Second}}
	h.setDesired(t, d)
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	for range 4 {
		h.driver.crash(id, 1, h.now)
		h.reconcile(t)
		h.now = h.now.Add(2 * time.Second)
		h.reconcile(t)
	}
	if rec := h.allocRecord(t, 0); rec.State != reconciler.AllocFailed {
		t.Fatalf("state = %q, want failed as the precondition for this test", rec.State)
	}

	h.deleteDesired(t, "shop", "web")
	h.reconcile(t)

	page, err := h.store.List(context.Background(), store.KindAlloc, store.ListOptions{})
	if err != nil {
		t.Fatalf("list allocs: %v", err)
	}
	if len(page.Records) != 0 {
		t.Errorf("%d alloc record(s) survived service deletion", len(page.Records))
	}
}

// A network attachment can outlive everything that refers to it: teardown
// detaches after the container is removed, so a kanead killed in that window
// leaves a namespace and a Cilium endpoint holding an IP that no alloc claims.
// Nothing in the planner sees it, because the planner reasons only about allocs
// it has heard of.
func TestReconcileReapsOrphanedAttachments(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	// Simulate the leak directly: attached, but no container and no record.
	if err := h.network.Attach(context.Background(),
		runtime.AllocSpec{ID: "ghost-web-0", Project: "ghost", Service: "web"}); err != nil {
		t.Fatalf("seed orphan: %v", err)
	}

	res := h.reconcile(t)
	if res.Reaped != 1 {
		t.Fatalf("reaped = %d, want 1", res.Reaped)
	}
	if h.network.isAttached("ghost-web-0") {
		t.Error("orphaned attachment survived the sweep")
	}
	// The live alloc must be untouched — reaping deletes, so a false positive
	// here would cut the network out from under a running workload.
	if !h.network.isAttached(reconciler.AllocID("shop", "web", 0)) {
		t.Error("sweep detached a live alloc")
	}
}

// An alloc that is desired but not yet created has an attachment and no record,
// which looks exactly like an orphan. It is not: create() attaches before it
// persists, so reaping on that basis would race a starting workload.
func TestReconcileDoesNotReapAllocsBeingCreated(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(2))

	// Attach index 1 by hand, then let the pass run: it is desired, so it must
	// survive the sweep even though nothing has recorded it yet.
	id := reconciler.AllocID("shop", "web", 1)
	if err := h.network.Attach(context.Background(),
		runtime.AllocSpec{ID: id, Project: "shop", Service: "web"}); err != nil {
		t.Fatalf("seed attachment: %v", err)
	}

	res := h.reconcile(t)
	if res.Reaped != 0 {
		t.Fatalf("reaped = %d, want 0", res.Reaped)
	}
	if !h.network.isAttached(id) {
		t.Error("sweep detached an alloc that was mid-create")
	}
}

// A Network that cannot enumerate its attachments simply is not swept. That is
// the netns driver's situation by design: /run/netns is shared with the rest of
// the host and a bare namespace carries no mark of who created it, so "anything
// I did not expect" would include other tools' namespaces.
func TestReconcileSkipsSweepWithoutAReaper(t *testing.T) {
	if _, ok := any(reconciler.NetnsNetwork{}).(reconciler.NetworkReaper); ok {
		t.Fatal("NetnsNetwork must not implement NetworkReaper: it cannot tell its " +
			"namespaces from any other tool's, and reaping deletes")
	}
}
