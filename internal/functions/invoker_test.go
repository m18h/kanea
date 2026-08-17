package functions

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// fakeSource serves a fixed target list.
type fakeSource struct {
	mu      sync.Mutex
	targets []Target
}

func (f *fakeSource) Targets(context.Context) ([]Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Target(nil), f.targets...), nil
}

func (f *fakeSource) set(targets ...Target) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = targets
}

// capture records what a function received.
type capture struct {
	mu   sync.Mutex
	hits []hit
	// status lets a test make the upstream fail.
	status int
	done   chan struct{}
}

type hit struct {
	path    string
	trigger string
	body    []byte
	headers http.Header
}

func (h hit) header(name string) string { return h.headers.Get(name) }

func newCapture(t *testing.T) (*capture, string) {
	t.Helper()
	c := &capture{status: http.StatusOK, done: make(chan struct{}, 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.hits = append(c.hits, hit{
			path: r.URL.Path, trigger: r.Header.Get("X-Kanea-Trigger"), body: body,
			headers: r.Header.Clone(),
		})
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
		select {
		case c.done <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)
	return c, srv.URL
}

func (c *capture) wait(t *testing.T) hit {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no invocation arrived")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[len(c.hits)-1]
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hits)
}

func newTestInvoker(t *testing.T, src Source, publish func(notify.Event)) *Invoker {
	t.Helper()
	inv, err := New(Config{
		Source: src, Publish: publish,
		RetryBase: time.Millisecond, Timeout: 2 * time.Second,
		sleep: func(context.Context, time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestEventTriggerInvokesWithTheEventBody(t *testing.T) {
	captured, url := newCapture(t)
	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "fanout", BaseURL: url,
		Events: []EventTrigger{{On: []string{"deploy.failed"}, Path: "/kanea/event"}},
	})
	inv := newTestInvoker(t, src, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inv.Run(ctx) }()

	event := notify.NewEvent(notify.EventDeployFailed, "shop", "web", "deploy failed", time.Now())
	inv.Record(ctx, event)

	got := captured.wait(t)
	if got.path != "/kanea/event" || got.trigger != "event" {
		t.Fatalf("invocation = %q trigger %q, want /kanea/event event", got.path, got.trigger)
	}
	var delivered notify.Event
	if err := json.Unmarshal(got.body, &delivered); err != nil {
		t.Fatalf("body is not an event: %v", err)
	}
	if delivered.Name != notify.EventDeployFailed || delivered.Service != "web" {
		t.Fatalf("delivered = %+v, want the original event", delivered)
	}

	// The outcome is recorded after the response returns, so poll briefly.
	deadline := time.After(2 * time.Second)
	for {
		stats := inv.Snapshot()["shop/fanout"]
		if stats.Invocations == 1 && stats.Failures == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("stats = %+v, want one clean invocation", stats)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// An event that matches no trigger invokes nothing, and a function.* event
// invokes nothing whatever the filters say (R26's runtime half).
func TestLoopGuardSkipsFunctionEvents(t *testing.T) {
	captured, url := newCapture(t)
	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "fanout", BaseURL: url,
		// A filter that would match anything the vocabulary holds.
		Events: []EventTrigger{{On: []string{"*"}}},
	})
	inv := newTestInvoker(t, src, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inv.Run(ctx) }()

	inv.Record(ctx, notify.NewEvent(notify.EventFunctionInvokeFailed, "shop", "other",
		"a function failure", time.Now()))
	// A matching, legitimate event afterwards proves the loop is live and the
	// first was skipped rather than still queued.
	inv.Record(ctx, notify.NewEvent(notify.EventDeployFailed, "shop", "web", "x", time.Now()))

	got := captured.wait(t)
	var delivered notify.Event
	_ = json.Unmarshal(got.body, &delivered)
	if delivered.Name != notify.EventDeployFailed {
		t.Fatalf("delivered %q; the function.* event should have been skipped", delivered.Name)
	}
	if captured.count() != 1 {
		t.Fatalf("hits = %d, want 1", captured.count())
	}
}

// Retries are bounded, and exhausting them emits function.invoke_failed: the
// error event, not one per attempt.
func TestExhaustedRetriesEmitInvokeFailed(t *testing.T) {
	captured, url := newCapture(t)
	captured.status = http.StatusInternalServerError

	var mu sync.Mutex
	var published []notify.Event
	publish := func(e notify.Event) {
		mu.Lock()
		defer mu.Unlock()
		published = append(published, e)
	}

	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "broken", BaseURL: url,
		Events: []EventTrigger{{On: []string{"deploy.failed"}}},
	})
	inv := newTestInvoker(t, src, publish)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inv.Run(ctx) }()

	inv.Record(ctx, notify.NewEvent(notify.EventDeployFailed, "shop", "web", "x", time.Now()))

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(published)
		mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no invoke_failed event was published")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if captured.count() != DefaultMaxAttempts {
		t.Fatalf("attempts = %d, want %d", captured.count(), DefaultMaxAttempts)
	}
	mu.Lock()
	defer mu.Unlock()
	if published[0].Name != notify.EventFunctionInvokeFailed || published[0].Service != "broken" {
		t.Fatalf("published = %+v", published[0])
	}
	stats := inv.Snapshot()["shop/broken"]
	if stats.Failures != 1 {
		t.Fatalf("stats = %+v, want one failure", stats)
	}
}

// Record never blocks: past the queue depth it drops and counts (constraint
// #8's Publish discipline).
func TestRecordIsNonBlockingAndCountsDrops(t *testing.T) {
	src := &fakeSource{}
	inv, err := New(Config{Source: src, QueueDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	// No Run loop: nothing consumes the queue.
	e := notify.NewEvent(notify.EventDeployFailed, "p", "s", "x", time.Now())
	for range 5 {
		inv.Record(context.Background(), e)
	}
	if got := inv.Dropped(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}

// A cron whose time has come fires once and re-arms from now: a tick the
// daemon slept through is skipped, never replayed.
func TestCronFiresAndSkipsMissedTicks(t *testing.T) {
	captured, url := newCapture(t)
	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "nightly", BaseURL: url,
		Crons: []CronTrigger{{Schedule: "0 3 * * *", Path: "/nightly"}},
	})

	// A controllable clock, starting just before 03:00.
	now := time.Date(2026, 8, 10, 2, 59, 0, 0, time.UTC)
	var clock sync.Mutex
	current := now
	inv, err := New(Config{
		Source: src,
		Now: func() time.Time {
			clock.Lock()
			defer clock.Unlock()
			return current
		},
		RetryBase: time.Millisecond,
		sleep:     func(context.Context, time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inv.reload(ctx)

	// Nothing due yet.
	inv.fireDueCrons(ctx)
	if captured.count() != 0 {
		t.Fatal("fired before the schedule")
	}

	// Jump the clock past several missed days: exactly one fire, not three.
	clock.Lock()
	current = now.Add(72 * time.Hour)
	clock.Unlock()
	inv.fireDueCrons(ctx)

	got := captured.wait(t)
	if got.path != "/nightly" || got.trigger != "cron" {
		t.Fatalf("cron invocation = %+v", got)
	}
	// Wait out any stragglers, then confirm a single delivery.
	time.Sleep(50 * time.Millisecond)
	if captured.count() != 1 {
		t.Fatalf("hits = %d, want 1: missed ticks are skipped, not replayed", captured.count())
	}

	// The schedule re-armed against the new now, so an immediate re-check
	// fires nothing.
	inv.fireDueCrons(ctx)
	time.Sleep(50 * time.Millisecond)
	if captured.count() != 1 {
		t.Fatalf("hits = %d after re-check, want 1", captured.count())
	}
}

// A reload must not re-arm a schedule that is already counting down: applying
// an unrelated change at 02:59 must not push tonight's 03:00 into tomorrow.
func TestReloadCarriesNextFireOver(t *testing.T) {
	_, url := newCapture(t)
	src := &fakeSource{}
	target := Target{
		Project: "shop", Service: "nightly", BaseURL: url,
		Crons: []CronTrigger{{Schedule: "0 3 * * *", Path: "/nightly"}},
	}
	src.set(target)

	now := time.Date(2026, 8, 10, 2, 0, 0, 0, time.UTC)
	inv, err := New(Config{Source: src, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inv.reload(ctx)

	inv.mu.Lock()
	first := inv.targets[0].crons[0].next
	inv.mu.Unlock()

	// Reload with the same target; next must not move.
	inv.reload(ctx)
	inv.mu.Lock()
	second := inv.targets[0].crons[0].next
	inv.mu.Unlock()
	if !first.Equal(second) {
		t.Fatalf("next fire moved on reload: %s -> %s", first, second)
	}
	if want := time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC); !first.Equal(want) {
		t.Fatalf("next = %s, want %s", first, want)
	}
}

// fakeResolver serves a fixed secret, or an error.
type fakeResolver struct {
	secret []byte
	err    error
}

func (f fakeResolver) Resolve(context.Context, string) ([]byte, error) {
	return f.secret, f.err
}

// A signed invocation carries the webhook wire format, and the signature
// verifies over the exact body sent: a function verifies it the same way it
// verifies a Kanea webhook.
func TestSignedInvocation(t *testing.T) {
	captured, url := newCapture(t)
	secret := []byte("a-shared-signing-secret")
	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "signed", BaseURL: url,
		SigningRef: "secret:shop/sign",
		Events:     []EventTrigger{{On: []string{"deploy.failed"}}},
	})
	inv, err := New(Config{
		Source: src, Resolver: fakeResolver{secret: secret},
		RetryBase: time.Millisecond, sleep: func(context.Context, time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = inv.Run(ctx) }()

	inv.Record(ctx, notify.NewEvent(notify.EventDeployFailed, "shop", "web", "x", time.Now()))
	got := captured.wait(t)

	ts := got.header(notify.TimestampHeader)
	sig := got.header(notify.SignatureHeader)
	if ts == "" || sig == "" {
		t.Fatalf("signed POST missing headers: ts=%q sig=%q", ts, sig)
	}
	if want := notify.Sign(secret, ts, got.body); sig != want {
		t.Fatalf("signature = %q, want %q (over the exact body)", sig, want)
	}
}

// A signing_ref that will not resolve fails the invocation rather than
// sending unsigned (R26): a dropped control must not look like a delivery.
func TestSigningFailureDropsRatherThanSendsUnsigned(t *testing.T) {
	captured, url := newCapture(t)
	var published []notify.Event
	var mu sync.Mutex

	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "signed", BaseURL: url,
		SigningRef: "secret:shop/missing",
		Events:     []EventTrigger{{On: []string{"deploy.failed"}}},
	})
	inv, err := New(Config{
		Source:   src,
		Resolver: fakeResolver{err: errResolve},
		Publish: func(e notify.Event) {
			mu.Lock()
			defer mu.Unlock()
			published = append(published, e)
		},
		RetryBase: time.Millisecond, sleep: func(context.Context, time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inv.reload(ctx)
	inv.invoke(ctx, src.targets[0], "/", "event", []byte("{}"))

	if captured.count() != 0 {
		t.Fatalf("an unsigned POST was sent %d times; it should have been dropped", captured.count())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(published) != 1 || published[0].Name != notify.EventFunctionInvokeFailed {
		t.Fatalf("published = %+v, want one invoke_failed", published)
	}
	if inv.Snapshot()["shop/signed"].Failures != 1 {
		t.Fatal("the dropped invocation was not counted as a failure")
	}
}

var errResolve = errTest("no such secret")

type errTest string

func (e errTest) Error() string { return string(e) }

// The client refuses redirects: the target is a VIP this node derived, and an
// answer pointing elsewhere does not get followed there (§14 A10's spirit,
// without consulting a guard whose input this is not).
func TestInvokerRefusesRedirects(t *testing.T) {
	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leak" {
			redirected = true
			return
		}
		http.Redirect(w, r, "/leak", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	src := &fakeSource{}
	src.set(Target{
		Project: "shop", Service: "fn", BaseURL: srv.URL,
		Events: []EventTrigger{{On: []string{"deploy.failed"}}},
	})
	inv := newTestInvoker(t, src, nil)
	ctx := context.Background()
	inv.reload(ctx)

	body, _ := json.Marshal(notify.NewEvent(notify.EventDeployFailed, "p", "s", "x", time.Now()))
	inv.invoke(ctx, src.targets[0], "/", "event", body)

	if redirected {
		t.Fatal("the invoker followed a redirect")
	}
	// A refused redirect is a failed invocation, honestly counted.
	if stats := inv.Snapshot()["shop/fn"]; stats.Failures != 1 {
		t.Fatalf("stats = %+v, want the redirect counted as a failure", stats)
	}
}
