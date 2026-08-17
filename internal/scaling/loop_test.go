package scaling_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// fleet is an in-memory stand-in for the Store.
type fleet struct {
	mu       sync.Mutex
	services []scaling.Service
	// setErr fails SetCount, standing in for a rejected write. failFor narrows
	// that to one service.
	setErr  error
	failFor string
	calls   []scaling.Service
}

func (f *fleet) Services(context.Context) ([]scaling.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]scaling.Service(nil), f.services...), nil
}

func (f *fleet) SetCount(_ context.Context, service string, count int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil && (f.failFor == "" || f.failFor == service) {
		return f.setErr
	}
	f.calls = append(f.calls, scaling.Service{Key: service, Count: count})
	for i := range f.services {
		if f.services[i].Key == service {
			f.services[i].Count = count
		}
	}
	return nil
}

// recorder captures decisions the loop acted on.
type recorder struct {
	mu        sync.Mutex
	decisions []scaling.Decision
}

func (r *recorder) ScaleDecided(_ context.Context, d scaling.Decision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decisions = append(r.decisions, d)
}

// breaker is a switch a test can flip.
type breaker struct {
	open bool
}

func (b *breaker) Allow() (bool, string) {
	if b.open {
		return false, "restart rate is too high"
	}
	return true, ""
}

func newLoop(t *testing.T, f *fleet, adjust ...func(*scaling.LoopConfig)) (*scaling.Loop, *evalHarness) {
	t.Helper()
	h := newEval(t)
	cfg := scaling.LoopConfig{Evaluator: h.eval, Fleet: f, Now: h.clock.now}
	for _, apply := range adjust {
		apply(&cfg)
	}
	loop, err := scaling.NewLoop(cfg)
	if err != nil {
		t.Fatalf("NewLoop: %v", err)
	}
	return loop, h
}

func busyService(key string, count int) scaling.Service {
	return scaling.Service{
		Key: key, Count: count,
		Policy: scaling.Policy{
			Min: 1, Max: 10,
			Rules:    []scaling.Rule{{Metric: scaling.MetricCPU, Target: 70}},
			Cooldown: time.Minute,
		},
	}
}

func TestLoopAppliesADecision(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	loop, h := newLoop(t, f)
	h.feed("shop/web", scaling.MetricCPU, 140, 6)

	changed, err := loop.Once(context.Background())
	if err != nil {
		t.Fatalf("Once: %v", err)
	}
	if changed != 1 {
		t.Fatalf("changed = %d, want 1", changed)
	}
	if len(f.calls) != 1 || f.calls[0].Count != 4 {
		t.Fatalf("SetCount calls = %+v; want one to 4", f.calls)
	}
}

func TestLoopLeavesServicesWithoutAPolicyAlone(t *testing.T) {
	f := &fleet{services: []scaling.Service{{Key: "shop/web", Count: 3}}}
	loop, h := newLoop(t, f)
	h.feed("shop/web", scaling.MetricCPU, 1000, 6)

	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("scaled a service with no policy: %+v", f.calls)
	}
}

func TestLoopRecordsWhatItDid(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	rec := &recorder{}
	loop, h := newLoop(t, f, func(cfg *scaling.LoopConfig) { cfg.Recorder = rec })
	h.feed("shop/web", scaling.MetricCPU, 140, 6)

	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(rec.decisions) != 1 {
		t.Fatalf("decisions = %+v, want one recorded", rec.decisions)
	}
	// §9.2: every action emits an event, and the event has to say why.
	if rec.decisions[0].Reason == "" || rec.decisions[0].Rule != scaling.MetricCPU {
		t.Errorf("recorded decision does not explain itself: %+v", rec.decisions[0])
	}
}

func TestLoopDoesNotRecordDecisionsItDidNotApply(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	rec := &recorder{}
	loop, h := newLoop(t, f, func(cfg *scaling.LoopConfig) { cfg.Recorder = rec })
	// Inside tolerance: no change, so no event. An event log that records
	// non-events is one nobody reads.
	h.feed("shop/web", scaling.MetricCPU, 71, 6)

	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(rec.decisions) != 0 {
		t.Fatalf("recorded a decision that changed nothing: %+v", rec.decisions)
	}
}

func TestTheCircuitBreakerSuppressesScaleActions(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	b := &breaker{open: true}
	loop, h := newLoop(t, f, func(cfg *scaling.LoopConfig) { cfg.Breaker = b })
	h.feed("shop/web", scaling.MetricCPU, 140, 6)

	// §4.3: when the node is unhealthy, adding replicas to a service that is
	// already failing makes the failure bigger.
	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("scaled with the breaker open: %+v", f.calls)
	}

	// And once it closes, the decision is still there to act on.
	b.open = false
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("did not scale after the breaker closed: %+v", f.calls)
	}
}

func TestASuppressedActionDoesNotStartTheCooldown(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	b := &breaker{open: true}
	loop, h := newLoop(t, f, func(cfg *scaling.LoopConfig) { cfg.Breaker = b })

	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	// The breaker closes immediately. Nothing was applied, so nothing is in
	// cooldown, and the service scales on the very next pass.
	b.open = false
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("a suppressed action left the service in cooldown: %+v", f.calls)
	}
}

func TestAFailedWriteIsRetriedNextPass(t *testing.T) {
	f := &fleet{
		services: []scaling.Service{busyService("shop/web", 2)},
		setErr:   errors.New("store is busy"),
	}
	loop, h := newLoop(t, f)
	h.feed("shop/web", scaling.MetricCPU, 140, 6)

	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("a failed write failed the whole pass: %v", err)
	}

	f.setErr = nil
	h.feed("shop/web", scaling.MetricCPU, 140, 6)
	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("the retry never happened: %+v", f.calls)
	}
}

func TestOneFailingServiceDoesNotStopTheOthers(t *testing.T) {
	f := &fleet{
		services: []scaling.Service{busyService("shop/web", 2), busyService("shop/api", 2)},
		setErr:   errors.New("store is busy"),
		failFor:  "shop/web",
	}
	loop, h := newLoop(t, f)
	h.feedAll(scaling.MetricCPU, 140, 6, "shop/web", "shop/api")

	changed, err := loop.Once(context.Background())
	if err != nil {
		t.Fatalf("a failed write failed the whole pass: %v", err)
	}
	// One service the Store refused must not cost the other its decision.
	if changed != 1 {
		t.Fatalf("changed = %d, want the one that succeeded", changed)
	}
	if len(f.calls) != 1 || f.calls[0].Key != "shop/api" {
		t.Fatalf("calls = %+v; want shop/api scaled despite shop/web failing", f.calls)
	}
}

func TestLoopForgetsServicesThatWentAway(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	loop, h := newLoop(t, f)
	h.feed("shop/web", scaling.MetricCPU, 140, 6)

	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(h.eval.Services()) != 1 {
		t.Fatalf("no state recorded: %v", h.eval.Services())
	}

	// The service is deleted. Its cooldown and history go with it, so a name
	// reused later starts clean rather than inheriting a stranger's history.
	f.services = nil
	if _, err := loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if len(h.eval.Services()) != 0 {
		t.Fatalf("state survived the service: %v", h.eval.Services())
	}
}

func TestNewLoopRequiresItsCollaborators(t *testing.T) {
	h := newEval(t)
	if _, err := scaling.NewLoop(scaling.LoopConfig{Fleet: &fleet{}}); err == nil {
		t.Error("a loop with no evaluator was accepted")
	}
	if _, err := scaling.NewLoop(scaling.LoopConfig{Evaluator: h.eval}); err == nil {
		t.Error("a loop with no fleet was accepted")
	}
}

// The autoscaling exit criterion in §20: "service scales 2→N→2 on synthetic load
// per policy". This is that, driven through the loop rather than the evaluator,
// so it covers the wiring as well as the arithmetic.
func TestServiceScalesUpAndBackDown(t *testing.T) {
	f := &fleet{services: []scaling.Service{busyService("shop/web", 2)}}
	loop, h := newLoop(t, f)
	ctx := context.Background()

	// Load arrives and stays. Several passes, each spaced past the cooldown.
	for range 4 {
		h.feed("shop/web", scaling.MetricCPU, 200, 6)
		if _, err := loop.Once(ctx); err != nil {
			t.Fatalf("Once: %v", err)
		}
		h.clock.advance(2 * time.Minute)
	}
	peak := f.services[0].Count
	if peak <= 2 {
		t.Fatalf("never scaled up: count = %d", peak)
	}

	// The load goes away and stays away, for longer than the scale-down
	// stabilization window.
	for range 10 {
		h.feed("shop/web", scaling.MetricCPU, 1, 6)
		if _, err := loop.Once(ctx); err != nil {
			t.Fatalf("Once: %v", err)
		}
		h.clock.advance(2 * time.Minute)
	}
	if got := f.services[0].Count; got != 1 {
		t.Fatalf("settled at %d replicas after the load stopped, want the declared min of 1 (peak was %d)",
			got, peak)
	}
}
