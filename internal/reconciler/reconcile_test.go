package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/network"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/storage"
	"github.com/m18h/kanea/internal/store"
)

// fakeDriver is an in-memory containerd stand-in. It models the states the
// reconciler must handle: including the ones that are hard to produce on
// demand against a real daemon, like "exited with code 137 five times".
type fakeDriver struct {
	mu       sync.Mutex
	allocs   map[string]runtime.Status
	specs    map[string]runtime.AllocSpec
	pulled   []string
	pullAuth []string
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

func (f *fakeDriver) EnsureImage(_ context.Context, img runtime.ImageRef) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("image:" + img.Ref); err != nil {
		return "", err
	}
	f.pulled = append(f.pulled, img.Ref)
	f.pullAuth = append(f.pullAuth, string(img.Auth))
	return "sha256:" + img.Ref, nil
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

	// policy sync state
	policySyncs [][]network.ProjectPolicy
	policyErr   error

	// load-balancing state
	ips       map[string]string
	nextIP    int
	notReady  map[string]bool
	attachErr error
	lbSyncs   [][]network.Service
	lbErr     error

	// repair state (v1.65)
	repairs   []runtime.AllocSpec
	repairErr error

	// egress state (v1.65)
	egressCalls int
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{
		attached: map[string]bool{},
		ips:      map[string]string{},
		notReady: map[string]bool{},
	}
}

// SyncServices makes fakeNetwork a reconciler.LoadBalancer.
func (n *fakeNetwork) SyncServices(_ context.Context, services []network.Service) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lbErr != nil {
		return n.lbErr
	}
	n.lbSyncs = append(n.lbSyncs, services)
	return nil
}

func (n *fakeNetwork) lastLBSync() []network.Service {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.lbSyncs) == 0 {
		return nil
	}
	return n.lbSyncs[len(n.lbSyncs)-1]
}

// backendsOf returns the addresses currently advertised for a service.
func (n *fakeNetwork) backendsOf(project, service string) []string {
	for _, svc := range n.lastLBSync() {
		if svc.Project == project && svc.Service == service {
			ips := make([]string, 0, len(svc.Backends))
			for _, b := range svc.Backends {
				ips = append(ips, b.IPv4)
			}
			return ips
		}
	}
	return nil
}

func (n *fakeNetwork) vipOf(project, service string) string {
	for _, svc := range n.lastLBSync() {
		if svc.Project == project && svc.Service == service {
			return svc.VIP
		}
	}
	return ""
}

func (n *fakeNetwork) Attach(_ context.Context, spec runtime.AllocSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, "attach:"+spec.ID)
	n.attached[spec.ID] = true
	if _, ok := n.ips[spec.ID]; !ok {
		n.nextIP++
		n.ips[spec.ID] = fmt.Sprintf("10.200.1.%d", n.nextIP)
	}
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

// SyncPolicies makes fakeNetwork a reconciler.PolicySyncer.
func (n *fakeNetwork) SyncPolicies(_ context.Context, projects []network.ProjectPolicy) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	names := make([]string, 0, len(projects))
	for _, p := range projects {
		names = append(names, p.Project)
	}
	n.events = append(n.events, "policy:"+strings.Join(names, ","))
	if n.policyErr != nil {
		return n.policyErr
	}
	n.policySyncs = append(n.policySyncs, projects)
	return nil
}

func (n *fakeNetwork) lastPolicySync() []network.ProjectPolicy {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.policySyncs) == 0 {
		return nil
	}
	return n.policySyncs[len(n.policySyncs)-1]
}

// policyProjects is the project names of the most recent sync.
func (n *fakeNetwork) policyProjects() []string {
	out := []string{}
	for _, p := range n.lastPolicySync() {
		out = append(out, p.Project)
	}
	return out
}

// allowFromOf returns the peers a service was granted in the last sync.
func (n *fakeNetwork) allowFromOf(project, service string) []string {
	for _, p := range n.lastPolicySync() {
		if p.Project != project {
			continue
		}
		for _, svc := range p.Services {
			if svc.Service != service {
				continue
			}
			out := make([]string, 0, len(svc.AllowFrom))
			for _, peer := range svc.AllowFrom {
				out = append(out, peer.String())
			}
			return out
		}
	}
	return nil
}

func (n *fakeNetwork) eventLog() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.events)
}

// RepairIdentity makes fakeNetwork a reconciler.IdentityRepairer (v1.65): a
// successful repair readies the attachment, exactly as re-writing the real
// identity map entry does.
func (n *fakeNetwork) RepairIdentity(_ context.Context, spec runtime.AllocSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.repairErr != nil {
		return n.repairErr
	}
	n.repairs = append(n.repairs, spec)
	delete(n.notReady, spec.ID)
	return nil
}

// EnsureEgress makes fakeNetwork a reconciler.EgressEnsurer (v1.65).
func (n *fakeNetwork) EnsureEgress(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.egressCalls++
	return nil
}

// Attachments makes fakeNetwork a reconciler.NetworkInspector. The fake hands
// each alloc a deterministic address so backend selection can be asserted.
func (n *fakeNetwork) Attachments(_ context.Context) (map[string]network.Attachment, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.attachErr != nil {
		return nil, n.attachErr
	}
	out := make(map[string]network.Attachment, len(n.attached))
	for id := range n.attached {
		out[id] = network.Attachment{AllocID: id, IPv4: n.ipFor(id), Ready: !n.notReady[id]}
	}
	return out, nil
}

// ipFor assigns a stable fake address per alloc, in first-attach order.
func (n *fakeNetwork) ipFor(id string) string {
	if ip, ok := n.ips[id]; ok {
		return ip
	}
	return ""
}

// harness wires a real store to fake infrastructure.
type harness struct {
	r       *reconciler.Reconciler
	store   store.Store
	driver  *fakeDriver
	network *fakeNetwork
	now     time.Time
}

// newHarness builds a reconciler over fakes. The variadic hooks let a test
// adjust the config it is actually about (edge routing, base domain) without
// every other test having to know those fields exist.
func newHarness(t *testing.T, with ...func(*reconciler.Config)) *harness {
	t.Helper()

	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h := &harness{store: s, driver: newFakeDriver(), network: newFakeNetwork(), now: testNow}
	cfg := reconciler.Config{
		Store:     s,
		Driver:    h.driver,
		Network:   h.network,
		Now:       func() time.Time { return h.now },
		LogDir:    t.TempDir(),
		VolumeDir: t.TempDir(),
	}
	for _, apply := range with {
		apply(&cfg)
	}
	r, err := reconciler.New(cfg)
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

	// A second pass has nothing to do: the loop must be idempotent.
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
	// before the task starts. Policy sync legitimately precedes both.
	var networkOps []string
	for _, e := range h.network.eventLog() {
		if !strings.HasPrefix(e, "policy:") {
			networkOps = append(networkOps, e)
		}
	}
	if len(networkOps) == 0 || networkOps[0] != "attach:"+id {
		t.Errorf("network events = %v, want attach first", h.network.eventLog())
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

	// First pass observes the crash and starts the backoff: it must not
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
	// And the network is detached; otherwise namespaces would leak per deploy.
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
	// A failed alloc keeps its record so `kanea ps` can explain itself, but
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
// leaves a namespace and a datapath attachment holding an IP that no alloc claims.
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
	// The live alloc must be untouched: reaping deletes, so a false positive
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
func TestReconcileSkipsSweepWithoutAnInspector(t *testing.T) {
	if _, ok := any(reconciler.NetnsNetwork{}).(reconciler.NetworkInspector); ok {
		t.Fatal("NetnsNetwork must not implement NetworkInspector: it cannot tell its " +
			"namespaces from any other tool's, and reaping deletes")
	}
}

// Policy is derived from desired state, so it belongs in the convergence loop.
func TestReconcileSyncsPolicyForEveryProject(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	blog := desired(1)
	blog.Project = "blog"
	h.setDesired(t, blog)

	h.reconcile(t)

	want := []string{"blog", "shop"}
	if got := h.network.policyProjects(); !slices.Equal(got, want) {
		t.Fatalf("policy sync = %v, want %v", got, want)
	}
}

// An endpoint that no policy selects has no ingress enforcement at all: it is
// reachable from every workload on the node. So a policy write that fails must
// stop the pass *before* anything attaches: convergence stalling is
// recoverable, a workload started unprotected is not.
func TestReconcileFailsClosedWhenPolicyCannotBeWritten(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(2))
	h.network.policyErr = errors.New("policy directory is read-only")

	if _, err := h.r.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile = nil, want the policy failure")
	}
	if got := h.driver.count(); got != 0 {
		t.Fatalf("%d allocs were created despite the policy failure", got)
	}
	for _, e := range h.network.eventLog() {
		if strings.HasPrefix(e, "attach:") {
			t.Fatalf("an alloc attached before its policy existed: %v", h.network.eventLog())
		}
	}
}

// Ordering, not just presence: the policy must be in place before the first
// endpoint appears, or there is a window in which a new project's allocs are
// running with nothing selecting them.
func TestReconcileSyncsPolicyBeforeAttaching(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	events := h.network.eventLog()
	firstAttach, firstPolicy := -1, -1
	for i, e := range events {
		if firstPolicy < 0 && strings.HasPrefix(e, "policy:") {
			firstPolicy = i
		}
		if firstAttach < 0 && strings.HasPrefix(e, "attach:") {
			firstAttach = i
		}
	}
	if firstPolicy < 0 || firstAttach < 0 {
		t.Fatalf("expected both a policy sync and an attach: %v", events)
	}
	if firstPolicy > firstAttach {
		t.Fatalf("attached before policy was written: %v", events)
	}
}

// desiredWithPort is a service that has something to load balance.
func desiredWithPort(count int) reconciler.Desired {
	d := desired(count)
	d.Ports = []reconciler.Port{{Name: "http", Container: 8080}}
	return d
}

func TestReconcileProgramsServiceFrontend(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.reconcile(t)

	svc := h.network.lastLBSync()
	if len(svc) != 1 {
		t.Fatalf("load-balanced services = %d, want 1", len(svc))
	}
	if svc[0].VIP != "10.201.0.1" {
		t.Errorf("VIP = %q, want the first address in the pool", svc[0].VIP)
	}
	if len(svc[0].Ports) != 1 || svc[0].Ports[0].Port != 8080 || svc[0].Ports[0].TargetPort != 8080 {
		t.Errorf("ports = %+v, want http 8080->8080", svc[0].Ports)
	}
	if got := h.network.backendsOf("shop", "web"); len(got) != 2 {
		t.Errorf("backends = %v, want both allocs", got)
	}
}

// A service with no declared ports has nothing to load balance, and minting a
// frontend for it would burn an address and publish an endpoint that refuses
// every connection.
func TestReconcileSkipsServicesWithoutPorts(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	if got := h.network.lastLBSync(); len(got) != 0 {
		t.Fatalf("load-balanced services = %+v, want none", got)
	}
}

// The VIP is the address DNS answers with and clients cache. It has to survive
// everything that legitimately churns underneath it (restarts, rescheduling,
// scale changes) or existing clients end up pointing at nothing.
func TestServiceVIPIsStableAcrossChurn(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.reconcile(t)
	original := h.network.vipOf("shop", "web")
	if original == "" {
		t.Fatal("no VIP assigned")
	}

	// Crash an alloc, let it restart, and scale the service.
	id := reconciler.AllocID("shop", "web", 0)
	h.driver.crash(id, 137, h.now)
	h.reconcile(t)
	h.now = h.now.Add(time.Hour)
	h.reconcile(t)
	h.setDesired(t, desiredWithPort(3))
	h.reconcile(t)

	if got := h.network.vipOf("shop", "web"); got != original {
		t.Fatalf("VIP moved from %q to %q", original, got)
	}
}

// The assignment lives in the Store precisely so a fresh reconciler (a kanead
// restart, or a datapath rebuilt from scratch) hands back the same address.
func TestServiceVIPSurvivesReconcilerRestart(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(1))
	h.reconcile(t)
	original := h.network.vipOf("shop", "web")

	// A new reconciler over the same store is what a kanead restart looks like.
	restarted, err := reconciler.New(reconciler.Config{
		Store: h.store, Driver: h.driver, Network: h.network,
		Now: func() time.Time { return h.now }, LogDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if _, err := restarted.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := h.network.vipOf("shop", "web"); got != original {
		t.Fatalf("VIP after restart = %q, want %q", got, original)
	}
}

// Backends are "serving right now", not "desired". An alloc waiting out a
// restart backoff still has a record and may still hold an attachment; routing
// real requests into it is a black hole.
func TestBackendsExcludeAllocsThatAreNotRunning(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.reconcile(t)
	if got := h.network.backendsOf("shop", "web"); len(got) != 2 {
		t.Fatalf("backends = %v, want 2 before the crash", got)
	}

	// Crash one alloc; the observing pass puts it in backoff.
	h.driver.crash(reconciler.AllocID("shop", "web", 0), 137, h.now)
	h.reconcile(t)

	got := h.network.backendsOf("shop", "web")
	if len(got) != 1 {
		t.Fatalf("backends = %v, want only the survivor", got)
	}
}

// An endpoint whose identity has not resolved cannot receive traffic anyway:
// advertising it just sends requests into a drop. Since v1.65 the pass first
// tries to repair such an endpoint, so this pins the un-repairable case: the
// exclusion must hold when repair cannot help.
func TestBackendsExcludeUnreadyEndpoints(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.reconcile(t)

	h.network.mu.Lock()
	h.network.notReady[reconciler.AllocID("shop", "web", 1)] = true
	h.network.repairErr = errors.New("no attachment to repair")
	h.network.mu.Unlock()
	h.reconcile(t)

	if got := h.network.backendsOf("shop", "web"); len(got) != 1 {
		t.Fatalf("backends = %v, want only the ready endpoint", got)
	}
}

// A not-Ready attachment whose alloc the Store still declares is repaired
// map-only and advertised again in the same pass (v1.65): the state a
// pinned-map schema wipe leaves behind must not persist until the alloc is
// replaced.
func TestUnreadyAttachmentsAreRepairedAndReadvertised(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.reconcile(t)

	h.network.mu.Lock()
	h.network.notReady[reconciler.AllocID("shop", "web", 1)] = true
	h.network.mu.Unlock()
	h.reconcile(t)

	if got := h.network.backendsOf("shop", "web"); len(got) != 2 {
		t.Fatalf("backends = %v, want both after the repair", got)
	}
	h.network.mu.Lock()
	defer h.network.mu.Unlock()
	if len(h.network.repairs) != 1 {
		t.Fatalf("repairs = %+v, want exactly one", h.network.repairs)
	}
	if r := h.network.repairs[0]; r.Project != "shop" || r.Service != "web" {
		t.Fatalf("repair spec = %+v, want the record's project/service", r)
	}
}

// The egress plumbing is re-asserted from the pass (v1.65): a firewall reload
// that flushed the masquerade rule must cost seconds, not a kanead restart.
func TestEgressIsEnsuredEveryPass(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desired(1))
	h.reconcile(t)

	h.network.mu.Lock()
	defer h.network.mu.Unlock()
	if h.network.egressCalls == 0 {
		t.Fatal("EnsureEgress was never called from the pass")
	}
}

// A released address is reusable: a project torn down and rebuilt should not
// walk the pool forward forever.
func TestServiceVIPIsReleasedOnDelete(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(1))
	h.reconcile(t)
	first := h.network.vipOf("shop", "web")

	h.deleteDesired(t, "shop", "web")
	h.reconcile(t)

	other := desiredWithPort(1)
	other.Service = "api"
	h.setDesired(t, other)
	h.reconcile(t)

	if got := h.network.vipOf("shop", "api"); got != first {
		t.Fatalf("new service got %q, want the released address %q", got, first)
	}
}

// Two services must never share a frontend.
func TestServiceVIPsAreDistinct(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(1))
	api := desiredWithPort(1)
	api.Service = "api"
	h.setDesired(t, api)
	blog := desiredWithPort(1)
	blog.Project = "blog"
	h.setDesired(t, blog)
	h.reconcile(t)

	seen := map[string]string{}
	for _, svc := range h.network.lastLBSync() {
		key := svc.Project + "/" + svc.Service
		if other, clash := seen[svc.VIP]; clash {
			t.Fatalf("%s and %s share frontend %s", other, key, svc.VIP)
		}
		seen[svc.VIP] = key
	}
	if len(seen) != 3 {
		t.Fatalf("got %d distinct frontends, want 3", len(seen))
	}
}

// Stale load balancing points at allocs that were healthy seconds ago: a
// degraded service, not an unprotected one. Failing the pass would stop crash
// recovery over a routing update.
func TestLoadBalancerFailureDoesNotStallConvergence(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.network.lbErr = errors.New("state file is read-only")

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile = %v, want the pass to continue", err)
	}
	if res.Applied != 2 {
		t.Fatalf("applied = %d, want both allocs created despite the LB failure", res.Applied)
	}
}

// A restarted alloc must return to the backend set in the pass that restarts
// it, not the one after. Its record still reads "backoff" at that moment
// (written by the pass that observed the crash) while containerd already
// reports it running. Trusting the record would drop a healthy backend for a
// full interval on every crash.
func TestBackendsIncludeAllocRestartedThisPass(t *testing.T) {
	h := newHarness(t)
	h.setDesired(t, desiredWithPort(2))
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	h.driver.crash(id, 137, h.now)
	h.reconcile(t) // observes the crash, records backoff
	if got := h.network.backendsOf("shop", "web"); len(got) != 1 {
		t.Fatalf("backends during backoff = %v, want only the survivor", got)
	}

	h.now = h.now.Add(time.Hour) // backoff expires
	h.reconcile(t)               // restarts the alloc

	if rec := h.allocRecord(t, 0); rec.Restarts == 0 {
		t.Fatalf("alloc was not restarted: %+v", rec)
	}
	if got := h.network.backendsOf("shop", "web"); len(got) != 2 {
		t.Fatalf("backends after restart = %v, want both allocs back", got)
	}
}

// A service with no ports never gets a frontend, so holding an address for it
// would consume one for its whole life and shift every later assignment along.
func TestPortlessServicesDoNotConsumeFrontendAddresses(t *testing.T) {
	h := newHarness(t)

	// "client" sorts before "web", so it would take the first address if
	// portless services were allocated one.
	client := desired(1)
	client.Service = "client"
	h.setDesired(t, client)
	h.setDesired(t, desiredWithPort(1))
	h.reconcile(t)

	if got := h.network.vipOf("shop", "web"); got != "10.201.0.1" {
		t.Fatalf("web VIP = %q, want the first address in the pool", got)
	}
}

// Not every mount is a volume: resolv.conf is bind-mounted from a file. An
// ensureVolumes that walked the mount list would try to MkdirAll over it and
// take the whole alloc down with it.
func TestReconcileDoesNotTreatFileMountsAsVolumes(t *testing.T) {
	h := newHarness(t)

	// Point the alloc at a real file, the way the DNS wiring does.
	dir := t.TempDir()
	resolv := filepath.Join(dir, "shop.resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 10.200.1.1\n"), 0o644); err != nil {
		t.Fatalf("seed resolv.conf: %v", err)
	}

	d := desired(1)
	d.ResolvConfPath = resolv
	d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}
	h.setDesired(t, d)

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Applied != 1 {
		t.Fatalf("applied = %d failed = %d, want the alloc to start", res.Applied, res.Failed)
	}

	// The file must still be a file.
	info, err := os.Stat(resolv)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.IsDir() {
		t.Fatal("resolv.conf was replaced by a directory")
	}
}

// The reconciler carries the allowlist from the spec through to the policy
// writer, grouped by project.
func TestReconcileForwardsServiceAllowlists(t *testing.T) {
	h := newHarness(t)

	api := desiredWithPort(1)
	api.Service = "api"
	api.AllowFrom = []reconciler.PeerRef{{Project: "analytics", Service: "collector"}}
	h.setDesired(t, api)
	h.setDesired(t, desiredWithPort(1)) // shop/web, no allowlist
	h.reconcile(t)

	if got := h.network.allowFromOf("shop", "api"); !slices.Equal(got, []string{"analytics/collector"}) {
		t.Fatalf("api allowlist = %v", got)
	}
	// A service that asked for nothing must not get a document at all.
	if got := h.network.allowFromOf("shop", "web"); got != nil {
		t.Errorf("web allowlist = %v, want none", got)
	}
}

// fakeMounter stands in for the storage manager.
type fakeMounter struct {
	mu       sync.Mutex
	ensured  []string
	pruned   []string
	hostErr  error
	hostPath string
}

func (f *fakeMounter) Ensure(_ context.Context, req storage.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, req.Target)
	return nil
}

func (f *fakeMounter) Prune(_ context.Context, keep map[string]struct{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruned = nil
	for target := range keep {
		f.pruned = append(f.pruned, target)
	}
	return nil
}

func (f *fakeMounter) ResolveHost(path string, _ bool) (string, error) {
	if f.hostErr != nil {
		return "", f.hostErr
	}
	if f.hostPath != "" {
		return f.hostPath, nil
	}
	return path, nil
}

// A host volume is bind-mounted straight from the operator's directory: there
// is nothing under data_dir to derive, and copying it there would give the
// container a different filesystem than the one the operator named.
func TestHostVolumeMountsTheOperatorsDirectory(t *testing.T) {
	h := newHarness(t)
	mounter := &fakeMounter{}
	r, err := reconciler.New(reconciler.Config{
		Store: h.store, Driver: h.driver, Network: h.network, Mounts: mounter,
		Now: func() time.Time { return h.now }, LogDir: t.TempDir(), VolumeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	d := desired(1)
	d.Volumes = []reconciler.Volume{{
		Name: "config", Storage: "app-config", MountPath: "/etc/app",
		Resource: storage.Resource{Name: "app-config", Type: storage.TypeHost, Path: "/srv/shop/config"},
	}}
	h.setDesired(t, d)

	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	spec, ok := h.driver.specs[reconciler.AllocID("shop", "web", 0)]
	if !ok {
		t.Fatal("alloc was not created")
	}
	var source string
	for _, m := range spec.Mounts {
		if m.Destination == "/etc/app" {
			source = m.Source
		}
	}
	if source != "/srv/shop/config" {
		t.Fatalf("mount source = %q, want the operator's directory", source)
	}
	// A host directory needs no mount command; it is already a directory here.
	if len(mounter.ensured) != 0 {
		t.Errorf("a host volume ran a mount: %v", mounter.ensured)
	}
}

// A host path the operator has not allowed must stop the alloc, not warn and
// carry on with a directory nobody sanctioned.
func TestHostVolumeRejectedByTheAllowlistFailsTheAlloc(t *testing.T) {
	h := newHarness(t)
	mounter := &fakeMounter{hostErr: storage.ErrHostPathNotAllowed}
	r, err := reconciler.New(reconciler.Config{
		Store: h.store, Driver: h.driver, Network: h.network, Mounts: mounter,
		Now: func() time.Time { return h.now }, LogDir: t.TempDir(), VolumeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	d := desired(1)
	d.Volumes = []reconciler.Volume{{
		Name: "config", Storage: "app-config", MountPath: "/etc/app",
		Resource: storage.Resource{Name: "app-config", Type: storage.TypeHost, Path: "/etc"},
	}}
	h.setDesired(t, d)

	res, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("failed = %d, want the alloc to fail", res.Failed)
	}
	if h.driver.count() != 0 {
		t.Fatal("an alloc started with a host path the operator did not allow")
	}
}

func TestReconcileWaitsForAServiceWithNoImageYet(t *testing.T) {
	// A service declared with a `build` block and no `task.image` is legitimate
	// (§6.2 R8): the first successful build pins the digest. Until then there is
	// nothing to pull, and scheduling it anyway would fail an alloc against an
	// empty reference on every backoff for as long as the build takes, which
	// looks to an operator exactly like a broken deploy rather than a pending one.
	h := newHarness(t)
	waiting := desired(2)
	waiting.Image = ""
	h.setDesired(t, waiting)

	if res := h.reconcile(t); res.Planned != 0 {
		t.Fatalf("planned %d actions for a service with no image, want 0", res.Planned)
	}

	// And it starts as soon as the build gives it one, with no other change.
	built := desired(2)
	built.Image = "registry.example.com/shop/web@sha256:cafebabe"
	h.setDesired(t, built)

	if res := h.reconcile(t); res.Planned != 2 || res.Applied != 2 {
		t.Fatalf("result = %+v, want 2 planned and applied once the image exists", res)
	}
	for i := range 2 {
		id := reconciler.AllocID("shop", "web", i)
		if got := h.driver.state(id); got != runtime.StateRunning {
			t.Errorf("%s state = %q, want running", id, got)
		}
	}
}

func TestReconcileDeploysANewImageToARunningService(t *testing.T) {
	// The end-to-end shape of `kanea run` against a service that is already up,
	// and of M7's push → build → deploy. Before the spec hash existed this test
	// would have observed the old image still running, indefinitely.
	h := newHarness(t)
	d := desired(1)
	h.setDesired(t, d)
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	if got := h.driver.specs[id].Image; got != d.Image {
		t.Fatalf("first deploy ran %q, want %q", got, d.Image)
	}

	d.Image = "nginx:1.28-alpine"
	h.setDesired(t, d)
	h.reconcile(t)

	if got := h.driver.specs[id].Image; got != d.Image {
		t.Fatalf("after the deploy the alloc still runs %q, want %q", got, d.Image)
	}
	if rec := h.allocRecord(t, 0); rec.SpecHash != reconciler.SpecHash(d) {
		t.Errorf("record was not stamped with the deployed spec")
	}
}

func TestDeployGivesTheNewSpecItsOwnRestartBudget(t *testing.T) {
	// A service that crash-looped until its budget was spent must be fixable by
	// deploying the fix. If the new alloc inherited the old one's restart count
	// it would be marked failed on its first hiccup.
	h := newHarness(t)
	d := desired(1)
	d.Restart = reconciler.RestartPolicy{Attempts: 2, Backoff: []time.Duration{time.Second}}
	h.setDesired(t, d)
	h.reconcile(t)

	id := reconciler.AllocID("shop", "web", 0)
	for range 2 {
		h.driver.crash(id, 1, h.now)
		h.reconcile(t)
		h.now = h.now.Add(2 * time.Second)
		h.reconcile(t)
	}
	h.driver.crash(id, 1, h.now)
	h.reconcile(t)
	if rec := h.allocRecord(t, 0); rec.State != reconciler.AllocFailed {
		t.Fatalf("alloc state = %q, want %q after the budget was spent", rec.State, reconciler.AllocFailed)
	}

	d.Image = "nginx:1.28-alpine"
	h.setDesired(t, d)
	h.reconcile(t)

	rec := h.allocRecord(t, 0)
	if rec.State != reconciler.AllocRunning {
		t.Fatalf("after the fix was deployed the alloc is %q, want %q", rec.State, reconciler.AllocRunning)
	}
	if rec.Restarts != 0 {
		t.Errorf("the new spec inherited %d restarts; it should start with a clean budget", rec.Restarts)
	}
}

// PRD §6.2 R24: a local volume's directory is chowned and chmodded before the
// alloc that needs it starts.

// TestLocalVolumeOwnershipIsApplied chowns to the caller's own ids, which is
// the one chown an unprivileged test process is allowed to make. It still
// exercises the syscall: the interesting failure is not calling it at all.
func TestLocalVolumeOwnershipIsApplied(t *testing.T) {
	volumeDir := t.TempDir()
	h := newHarness(t, func(c *reconciler.Config) { c.VolumeDir = volumeDir })

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid()) // #nosec G115; real ids
	mode := uint32(0o700)
	d := desired(1)
	d.Volumes = []reconciler.Volume{{
		Name: "data", Storage: "local-ssd", MountPath: "/var/lib/data",
		UID: &uid, GID: &gid, Mode: &mode,
	}}
	h.setDesired(t, d)

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Applied != 1 {
		t.Fatalf("applied = %d failed = %d, want the alloc to start", res.Applied, res.Failed)
	}

	path := reconciler.VolumePath(volumeDir, d, 0, d.Volumes[0])
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat volume: %v", err)
	}
	// 0700 rather than the 0750 MkdirAll creates, and it must survive umask;
	// MkdirAll honours it, so a mode that was only ever passed to MkdirAll
	// would come out masked.
	if got := info.Mode().Perm(); got != os.FileMode(mode) {
		t.Errorf("volume mode = %04o, want %04o", got, mode)
	}
}

// A volume that declares no ownership is left exactly as it was before R24:
// created by MkdirAll and not touched again.
func TestUnownedLocalVolumeIsNotChmodded(t *testing.T) {
	volumeDir := t.TempDir()
	h := newHarness(t, func(c *reconciler.Config) { c.VolumeDir = volumeDir })

	d := desired(1)
	d.Volumes = []reconciler.Volume{{Name: "data", Storage: "local-ssd", MountPath: "/var/lib/data"}}
	h.setDesired(t, d)

	if _, err := h.r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	path := reconciler.VolumePath(volumeDir, d, 0, d.Volumes[0])
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat volume: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Errorf("volume mode = %04o, want the 0750 MkdirAll creates", got)
	}
}

// A chown that fails fails the alloc, like a mount that fails (PRD §8). A
// workload started against a directory it cannot write reports healthy and
// does the wrong thing for as long as nobody looks.
func TestVolumeOwnershipFailureFailsTheAlloc(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chown to an arbitrary uid succeeds")
	}
	volumeDir := t.TempDir()
	h := newHarness(t, func(c *reconciler.Config) { c.VolumeDir = volumeDir })

	// A uid this process cannot chown to. Changing a file's owner needs
	// CAP_CHOWN; an unprivileged process may not give its files away.
	other := uint32(os.Getuid() + 1)
	d := desired(1)
	d.Volumes = []reconciler.Volume{{
		Name: "data", Storage: "local-ssd", MountPath: "/var/lib/data", UID: &other,
	}}
	h.setDesired(t, d)

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed != 1 || res.Applied != 0 {
		t.Fatalf("applied = %d failed = %d, want the alloc to fail", res.Applied, res.Failed)
	}
	if _, ok := h.driver.specs[reconciler.AllocID("shop", "web", 0)]; ok {
		t.Error("the alloc was created despite its volume not being ownable")
	}
}

// A host volume is the operator's directory. R15 says Kanea never creates it
// and never deletes it, and R24 says it never chowns it either: the refusal
// is at `plan`, and this is the structural half of it.
func TestHostVolumeIsNeverChowned(t *testing.T) {
	hostDir := t.TempDir()
	if err := os.Chmod(hostDir, 0o755); err != nil {
		t.Fatalf("seed host dir: %v", err)
	}
	h := newHarness(t)
	mounter := &fakeMounter{hostPath: hostDir}
	r, err := reconciler.New(reconciler.Config{
		Store: h.store, Driver: h.driver, Network: h.network, Mounts: mounter,
		Now: func() time.Time { return h.now }, LogDir: t.TempDir(), VolumeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}

	// Ownership on a host volume cannot be declared: validation refuses it;
	// so this asserts that a record carrying it anyway still does not touch
	// the directory.
	uid, mode := uint32(os.Getuid()), uint32(0o700) // #nosec G115; real id
	d := desired(1)
	d.Volumes = []reconciler.Volume{{
		Name: "config", Storage: "app-config", MountPath: "/etc/app",
		Resource: storage.Resource{Name: "app-config", Type: storage.TypeHost, Path: hostDir},
		UID:      &uid, Mode: &mode,
	}}
	h.setDesired(t, d)

	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	info, err := os.Stat(hostDir)
	if err != nil {
		t.Fatalf("stat host dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("host directory mode = %04o, want the operator's 0755 untouched", got)
	}
}
