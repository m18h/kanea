package autoupdate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/store"
)

const (
	testImage  = "docker.io/library/nginx:1.27"
	oldDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	serviceKey = "shop/web"
)

var testNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

// fakeResolver answers with whatever the registry is pretending to hold.
type fakeResolver struct {
	digest string
	err    error
	calls  int
}

func (f *fakeResolver) ResolveRemote(context.Context, runtime.ImageRef) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.digest, nil
}

// harness wires a watcher over a real bbolt store, because the compare-and-set
// on write is half of what is being tested and a map would not have it.
type harness struct {
	t        *testing.T
	store    store.Store
	resolver *fakeResolver
	watcher  *Watcher
	events   []notify.Event
	now      time.Time
}

func newHarness(t *testing.T, d reconciler.Desired) *harness {
	t.Helper()
	st, err := store.Open(store.Options{Path: t.TempDir() + "/state.db"})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if _, err := store.PutValue(context.Background(), st, store.KindService, serviceKey, d); err != nil {
		t.Fatalf("seed service: %v", err)
	}

	h := &harness{t: t, store: st, resolver: &fakeResolver{digest: newDigest}, now: testNow}
	w, err := New(Config{
		Store:    st,
		Resolver: h.resolver,
		Now:      func() time.Time { return h.now },
		Emit:     func(e notify.Event) { h.events = append(h.events, e) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.watcher = w
	return h
}

func (h *harness) sweep() {
	h.t.Helper()
	if err := h.watcher.Once(context.Background()); err != nil {
		h.t.Fatalf("sweep: %v", err)
	}
}

func (h *harness) desired() reconciler.Desired {
	h.t.Helper()
	d, _, err := store.GetValue[reconciler.Desired](context.Background(), h.store, store.KindService, serviceKey)
	if err != nil {
		h.t.Fatalf("read service: %v", err)
	}
	return d
}

// seedAllocs writes alloc records at a given spec hash and health.
func (h *harness) seedAllocs(d reconciler.Desired, healthy bool) {
	h.t.Helper()
	for i := range d.Count {
		rec := reconciler.AllocRecord{
			ID:       reconciler.AllocID(d.Project, d.Service, i),
			Project:  d.Project,
			Service:  d.Service,
			Index:    i,
			State:    reconciler.AllocRunning,
			SpecHash: reconciler.SpecHash(d),
			Healthy:  healthy,
		}
		if _, err := store.PutValue(context.Background(), h.store,
			store.KindAlloc, rec.Key(), rec); err != nil {
			h.t.Fatalf("seed alloc: %v", err)
		}
	}
}

func (h *harness) eventNames() []string {
	names := make([]string, 0, len(h.events))
	for _, e := range h.events {
		names = append(names, e.Name)
	}
	return names
}

func autoService() reconciler.Desired {
	return reconciler.Desired{
		Project: "shop",
		Service: "web",
		Count:   1,
		Image:   testImage,
		Update:  reconciler.UpdatePolicy{Auto: true},
	}
}

// A service that has not asked for this must never be polled. The registry
// request is the observable part: no poll, no request.
func TestAServiceWithoutAutoIsNeverPolled(t *testing.T) {
	d := autoService()
	d.Update.Auto = false
	h := newHarness(t, d)

	h.sweep()

	if h.resolver.calls != 0 {
		t.Errorf("resolver was called %d times for a service with auto off", h.resolver.calls)
	}
	if got := h.desired().PinnedImage; got != "" {
		t.Errorf("pinned %q on a service that did not ask", got)
	}
}

func TestAMovedTagIsPinnedAndTheTagIsKept(t *testing.T) {
	h := newHarness(t, autoService())

	h.sweep()

	d := h.desired()
	if want := "docker.io/library/nginx@" + newDigest; d.PinnedImage != want {
		t.Errorf("PinnedImage = %q, want %q", d.PinnedImage, want)
	}
	// The declared tag has to survive: it is what the next poll re-resolves.
	if d.Image != testImage {
		t.Errorf("Image = %q, want the declared tag %q", d.Image, testImage)
	}
	if d.RunImage() != d.PinnedImage {
		t.Errorf("RunImage() = %q, want the pinned digest", d.RunImage())
	}
	if d.ImageUpdatedAt.IsZero() {
		t.Error("ImageUpdatedAt was not stamped, so the deadline never runs")
	}
}

// The pinned reference must not carry the tag as well. `repo:tag@sha256:…` is
// legal and reads as though the tag still decides something, when it does not.
func TestThePinnedReferenceDropsTheTag(t *testing.T) {
	h := newHarness(t, autoService())
	h.sweep()

	if pinned := h.desired().PinnedImage; strings.Contains(pinned, ":1.27@") {
		t.Errorf("PinnedImage = %q, want the tag dropped", pinned)
	}
}

// A poll inside the interval is not a poll. Without this the tick rate would be
// the poll rate, and the registry would notice.
func TestTheIntervalIsHonoured(t *testing.T) {
	h := newHarness(t, autoService())
	h.sweep()
	converge(t, h)

	before := h.resolver.calls
	h.now = h.now.Add(reconciler.DefaultUpdateInterval / 2)
	h.sweep()

	if h.resolver.calls != before {
		t.Errorf("resolver called %d more times inside the interval", h.resolver.calls-before)
	}

	h.now = h.now.Add(reconciler.DefaultUpdateInterval)
	h.sweep()
	if h.resolver.calls == before {
		t.Error("resolver was not called after the interval elapsed")
	}
}

// converge settles the in-flight update the way a healthy reconciler would.
func converge(t *testing.T, h *harness) {
	t.Helper()
	h.seedAllocs(h.desired(), true)
	h.sweep()
}

func TestAConvergedUpdateClearsTheRollbackTarget(t *testing.T) {
	h := newHarness(t, autoService())
	h.sweep() // pins
	h.seedAllocs(h.desired(), true)

	h.sweep() // settles

	d := h.desired()
	if d.RollbackImage != "" {
		t.Errorf("RollbackImage = %q, want it cleared once the update converged", d.RollbackImage)
	}
	if !d.ImageUpdatedAt.IsZero() {
		t.Error("ImageUpdatedAt is still set, so the deadline is still running")
	}
	if names := h.eventNames(); !contains(names, notify.EventImageUpdated) {
		t.Errorf("events = %v, want %s", names, notify.EventImageUpdated)
	}
}

// The whole point of keeping the previous reference. Unattended is exactly the
// case where nobody is watching to notice and fix a bad image.
func TestAnUpdateThatDoesNotConvergeIsReverted(t *testing.T) {
	first := autoService()
	first.PinnedImage = "docker.io/library/nginx@" + oldDigest
	h := newHarness(t, first)

	h.sweep() // pins the new digest, keeping the old as the rollback target
	if got := h.desired().RollbackImage; got != first.PinnedImage {
		t.Fatalf("RollbackImage = %q, want the digest that was running", got)
	}

	// Nothing ever becomes healthy, and the deadline passes.
	h.now = h.now.Add(reconciler.DefaultUpdateDeadline + time.Minute)
	h.sweep()

	d := h.desired()
	if d.PinnedImage != first.PinnedImage {
		t.Errorf("PinnedImage = %q, want a revert to %q", d.PinnedImage, first.PinnedImage)
	}
	if d.RollbackImage != "" {
		t.Errorf("RollbackImage = %q, want it cleared after the revert", d.RollbackImage)
	}
	if names := h.eventNames(); !contains(names, notify.EventImageUpdateFailed) {
		t.Errorf("events = %v, want %s", names, notify.EventImageUpdateFailed)
	}
}

// Before the deadline the watcher does nothing at all — a slow pull is not a
// failed update.
func TestAnUpdateInsideItsDeadlineIsLeftAlone(t *testing.T) {
	h := newHarness(t, autoService())
	h.sweep()
	pinned := h.desired().PinnedImage

	h.now = h.now.Add(reconciler.DefaultUpdateDeadline / 2)
	h.sweep()

	if got := h.desired().PinnedImage; got != pinned {
		t.Errorf("PinnedImage = %q, want it left at %q", got, pinned)
	}
	if len(h.events) != 0 {
		t.Errorf("events = %v, want none while the deadline is still running", h.eventNames())
	}
}

// AllocRecord.Healthy is only ever written by a probe, so a service with no
// check block has it false for every alloc forever. Requiring it there would
// revert every update the feature ever made.
func TestAServiceWithNoCheckConvergesOnRunningAlone(t *testing.T) {
	h := newHarness(t, autoService()) // no Check
	h.sweep()
	h.seedAllocs(h.desired(), false) // never probed, so never "healthy"

	h.sweep()

	if !h.desired().ImageUpdatedAt.IsZero() {
		t.Error("a check-free service was left in flight, so its update would be reverted")
	}
	if names := h.eventNames(); !contains(names, notify.EventImageUpdated) {
		t.Errorf("events = %v, want the update to have converged", names)
	}
}

// A service that does declare a check must actually pass it.
func TestAServiceWithACheckMustBeHealthy(t *testing.T) {
	d := autoService()
	d.Check = &reconciler.HealthCheck{Type: "http", Path: "/healthz", Port: 8080}
	h := newHarness(t, d)

	h.sweep()
	h.seedAllocs(h.desired(), false) // running, failing its probe
	h.sweep()

	// ImageUpdatedAt is the in-flight marker, not RollbackImage: a first pin
	// has no previous digest to roll back to, so an empty RollbackImage there
	// says nothing about whether the update settled.
	if h.desired().ImageUpdatedAt.IsZero() {
		t.Error("an unhealthy update was treated as converged")
	}

	h.now = h.now.Add(reconciler.DefaultUpdateDeadline + time.Minute)
	h.sweep()
	if names := h.eventNames(); !contains(names, notify.EventImageUpdateFailed) {
		t.Errorf("events = %v, want the unhealthy update reverted", names)
	}
}

// An unreachable registry is a bad minute, not a bad image: nothing is pinned,
// nothing is reverted, and the check is recorded so the retry waits out the
// service's own interval rather than hammering on every tick.
func TestAnUnreachableRegistryChangesNothing(t *testing.T) {
	h := newHarness(t, autoService())
	h.resolver.err = errors.New("dial tcp: connection refused")

	h.sweep()

	d := h.desired()
	if d.PinnedImage != "" {
		t.Errorf("PinnedImage = %q, want nothing pinned", d.PinnedImage)
	}
	if d.ImageCheckedAt.IsZero() {
		t.Error("the failed check was not recorded, so it retries on every tick")
	}

	before := h.resolver.calls
	h.sweep()
	if h.resolver.calls != before {
		t.Error("a failed poll was retried immediately instead of on the interval")
	}
}

// A tag that has not moved is not an update. Re-pinning the same digest would
// bump the store index and wake the reconciler for nothing.
func TestAnUnchangedTagDoesNotRedeploy(t *testing.T) {
	h := newHarness(t, autoService())
	h.sweep()
	converge(t, h)
	pinned := h.desired().PinnedImage

	h.now = h.now.Add(reconciler.DefaultUpdateInterval + time.Minute)
	h.sweep()

	d := h.desired()
	if d.PinnedImage != pinned {
		t.Errorf("PinnedImage = %q, want it unchanged at %q", d.PinnedImage, pinned)
	}
	if d.RollbackImage != "" {
		t.Errorf("RollbackImage = %q, want no update to have started", d.RollbackImage)
	}
}

// Settling the update in flight matters more than noticing the next one:
// stacking a pin on an unconverged deploy is how a bad image gets a rollback
// target that is also bad.
func TestAnInFlightUpdateIsNotPolledAgain(t *testing.T) {
	h := newHarness(t, autoService())
	h.sweep()
	before := h.resolver.calls

	h.now = h.now.Add(reconciler.DefaultUpdateInterval + time.Minute)
	h.resolver.digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	h.sweep()

	if h.resolver.calls != before {
		t.Error("the registry was polled while an update was still in flight")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
