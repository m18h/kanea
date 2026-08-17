// Package functions invokes wasm functions on their event and cron triggers
// (PRD v1.39, §6.2 R26, §11).
//
// Every function is a long-running wasi-http server; this package is the two
// kanead-side callers that POST to it. The event invoker is a tee on the
// notification dispatcher's feed (routes are startup-static, the Sink sees
// every event live) and the cron scheduler is a timer over the same target
// table. Both derive every URL from the function's Store-allocated VIP: the
// spec has no field for a target (R26), which is why this client is
// deliberately NOT behind notify's SSRF egress guard; its destinations are
// private by construction and cannot be chosen by a spec author. Consulting
// the guard would be theatre; weakening it for private ranges would be a hole.
package functions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m18h/kanea/internal/functions/cron"
	"github.com/m18h/kanea/internal/notify"
)

// Defaults for the invoker.
const (
	// DefaultQueueDepth bounds events waiting to be matched. Past it, Record
	// drops and counts: constraint #8's Publish discipline, copied exactly.
	DefaultQueueDepth = 1024
	// DefaultMaxAttempts bounds delivery attempts, retries included.
	DefaultMaxAttempts = 3
	// DefaultRetryBase is the first backoff step; it doubles from there.
	DefaultRetryBase = 2 * time.Second
	// DefaultTimeout bounds one invocation attempt.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxConcurrent bounds in-flight invocations, so an event storm
	// against a slow function queues here rather than growing goroutines.
	DefaultMaxConcurrent = 16
	// maxResponseBytes caps how much of a function's answer is drained. The
	// invoker reads nothing from the body; the cap is what makes that claim
	// hold against a function that answers with a stream.
	maxResponseBytes = 64 << 10
	// latencyRing is how many recent invocation latencies are kept, per
	// function: in memory, never the Store (constraint #2).
	latencyRing = 32
)

// Target is one function the invokers can reach: its VIP endpoint and its
// triggers, derived from the Store by the Source.
type Target struct {
	Project string
	Service string
	// BaseURL is http://<VIP>:<port>: derived, never declared (R26).
	BaseURL string
	// SigningRef names the secret event/cron POSTs are MACed with (R26,
	// v1.40). Empty means unsigned. A reference, resolved per delivery: the
	// resolved secret never lives on the target list.
	SigningRef string
	Events     []EventTrigger
	Crons      []CronTrigger
}

// Resolver turns a signing reference into its secret. Defined at the consumer;
// the daemon passes the secrets store.
type Resolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// EventTrigger mirrors the reconciler's shape without importing it: this
// package is mechanism, and the Source is where the vocabularies meet.
type EventTrigger struct {
	On   []string
	Path string
}

// CronTrigger is a validated five-field schedule and its path.
type CronTrigger struct {
	Schedule string
	Path     string
}

// Source lists the current targets. Defined here, at the consumer; cmd/kanea
// implements it over the Store.
type Source interface {
	Targets(ctx context.Context) ([]Target, error)
}

// Stats is one function's invocation counters, served over the API and reset
// by a restart: the rate lives in the datapath's counters (§9.1), this is
// the invoker's own bookkeeping.
type Stats struct {
	Invocations uint64    `json:"invocations"`
	Failures    uint64    `json:"failures"`
	LastInvoked time.Time `json:"last_invoked,omitzero"`
	// LatenciesMS are the most recent invocation latencies, newest last.
	LatenciesMS []float64 `json:"latencies_ms,omitempty"`
}

// Config configures the invoker.
type Config struct {
	Source Source
	Logger *slog.Logger
	// Resolver turns a function's signing_ref into its secret, per delivery
	// (R26, v1.40). Nil means signing references cannot be honoured: a
	// function that declares one then fails to invoke rather than sending
	// unsigned, which is the fail-closed direction.
	Resolver Resolver
	// Publish emits function.invoke_failed once a delivery's retries are
	// spent. Nil drops the events (tests).
	Publish func(notify.Event)
	// Client overrides the hardened default (tests). The default refuses
	// redirects: the target is a VIP this node allocated, and anything
	// answering 3xx to somewhere else does not get followed there.
	Client      *http.Client
	QueueDepth  int
	MaxAttempts int
	RetryBase   time.Duration
	Timeout     time.Duration
	Now         func() time.Time
	// sleep is injectable so retry tests do not wait.
	sleep func(context.Context, time.Duration)
}

// Invoker matches events against triggers, runs the cron schedule, and POSTs.
type Invoker struct {
	src      Source
	log      *slog.Logger
	resolver Resolver
	publish  func(notify.Event)
	client   *http.Client
	queue    chan notify.Event
	wake     chan struct{}
	sem      chan struct{}
	now      func() time.Time
	sleep    func(context.Context, time.Duration)

	maxAttempts int
	retryBase   time.Duration
	timeout     time.Duration

	dropped  atomic.Int64
	warnOnce sync.Once

	mu      sync.Mutex
	targets []compiledTarget
	stats   map[string]*Stats
}

// compiledTarget is a target with its event filters compiled once.
type compiledTarget struct {
	Target
	filters []compiledEvent
	crons   []compiledCron
}

type compiledEvent struct {
	filter notify.Filter
	path   string
}

type compiledCron struct {
	// expr is the raw expression, kept so a reload can carry a counting-down
	// next-fire over by identity.
	expr     string
	schedule cron.Schedule
	path     string
	next     time.Time
}

// New builds an invoker. Run starts it.
func New(cfg Config) (*Invoker, error) {
	if cfg.Source == nil {
		return nil, errors.New("functions: no target source")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.QueueDepth <= 0 {
		cfg.QueueDepth = DefaultQueueDepth
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.RetryBase <= 0 {
		cfg.RetryBase = DefaultRetryBase
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.sleep == nil {
		cfg.sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: cfg.Timeout,
			// Refused, not followed; the same rule the egress guard applies
			// (§14 A10): a redirect is the answer changing its own address.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("functions: redirects are refused")
			},
		}
	}
	return &Invoker{
		src: cfg.Source, log: cfg.Logger, resolver: cfg.Resolver,
		publish: cfg.Publish, client: cfg.Client,
		queue: make(chan notify.Event, cfg.QueueDepth),
		wake:  make(chan struct{}, 1),
		sem:   make(chan struct{}, DefaultMaxConcurrent),
		now:   cfg.Now, sleep: cfg.sleep,
		maxAttempts: cfg.MaxAttempts, retryBase: cfg.RetryBase, timeout: cfg.Timeout,
		stats: map[string]*Stats{},
	}, nil
}

// Record implements notify.Sink: a non-blocking bounded enqueue with a drop
// counter and a warn-once. Called on the dispatcher's goroutine, which must
// never wait on anything this package does.
func (i *Invoker) Record(_ context.Context, e notify.Event) {
	select {
	case i.queue <- e:
	default:
		i.dropped.Add(1)
		i.warnOnce.Do(func() {
			i.log.Warn("function invoker queue is full; dropping events",
				"depth", cap(i.queue),
				"detail", "drops are counted; this message is not repeated")
		})
	}
}

// Dropped is the count of events Record could not queue.
func (i *Invoker) Dropped() int64 { return i.dropped.Load() }

// Wake tells the invoker desired state changed, so `kanea apply` wires a new
// trigger with no restart. Non-blocking, like every wake in kanead.
func (i *Invoker) Wake() {
	select {
	case i.wake <- struct{}{}:
	default:
	}
}

// Run matches events and fires cron schedules until ctx ends.
func (i *Invoker) Run(ctx context.Context) error {
	i.reload(ctx)

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	i.armCron(timer)

	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-i.queue:
			i.dispatchEvent(ctx, e)
		case <-i.wake:
			i.reload(ctx)
			i.armCron(timer)
		case <-timer.C:
			i.fireDueCrons(ctx)
			i.armCron(timer)
		}
	}
}

// reload rebuilds the target table from the Source.
func (i *Invoker) reload(ctx context.Context) {
	targets, err := i.src.Targets(ctx)
	if err != nil {
		// The old table keeps serving; a Store hiccup must not drop triggers.
		i.log.Error("cannot reload function triggers", "error", err)
		return
	}
	now := i.now()

	i.mu.Lock()
	defer i.mu.Unlock()

	// Carry the old next-fire times over, keyed by (function, schedule): a
	// reload must not re-arm a schedule that was already counting down, or
	// every apply would push every cron fire into the future.
	previous := map[string]time.Time{}
	for _, t := range i.targets {
		for _, c := range t.crons {
			previous[t.Project+"/"+t.Service+"\x00"+c.path+"\x00"+c.expr] = c.next
		}
	}

	compiled := make([]compiledTarget, 0, len(targets))
	for _, t := range targets {
		ct := compiledTarget{Target: t}
		for _, ev := range t.Events {
			// SeverityInfo floor: a trigger's patterns already say what it
			// wants, and a floor would silently drop info events it named.
			filter, err := notify.NewFilter(ev.On, notify.SeverityInfo)
			if err != nil {
				// R26 validated this at plan; a record that got here another
				// way is skipped and named, never guessed at.
				i.log.Error("function has an invalid event trigger; skipping it",
					"function", t.Project+"/"+t.Service, "error", err)
				continue
			}
			ct.filters = append(ct.filters, compiledEvent{filter: filter, path: ev.Path})
		}
		for _, cr := range t.Crons {
			schedule, err := cron.Parse(cr.Schedule)
			if err != nil {
				i.log.Error("function has an invalid cron trigger; skipping it",
					"function", t.Project+"/"+t.Service, "error", err)
				continue
			}
			cc := compiledCron{expr: cr.Schedule, schedule: schedule, path: cr.Path}
			key := t.Project + "/" + t.Service + "\x00" + cr.Path + "\x00" + cr.Schedule
			if next, ok := previous[key]; ok && next.After(now) {
				cc.next = next
			} else if next, err := schedule.Next(now); err == nil {
				cc.next = next
			} else {
				i.log.Error("cron schedule never fires; skipping it",
					"function", t.Project+"/"+t.Service, "schedule", cr.Schedule)
				continue
			}
			ct.crons = append(ct.crons, cc)
		}
		compiled = append(compiled, ct)
	}
	i.targets = compiled
}

// dispatchEvent fans one event to every matching trigger.
func (i *Invoker) dispatchEvent(ctx context.Context, e notify.Event) {
	// The runtime half of R26's loop guard: even a record that bypassed the
	// parser cannot make a function.* event invoke a function.
	if notify.IsFunctionEvent(e.Name) {
		return
	}
	body, err := json.Marshal(e)
	if err != nil {
		return // unreachable for notify.Event; nothing useful to deliver
	}

	i.mu.Lock()
	type delivery struct {
		target Target
		path   string
	}
	var due []delivery
	for _, t := range i.targets {
		for _, f := range t.filters {
			if f.filter.Match(e) {
				due = append(due, delivery{target: t.Target, path: f.path})
				break // one event, one invocation per function
			}
		}
	}
	i.mu.Unlock()

	for _, d := range due {
		i.invokeAsync(ctx, d.target, d.path, "event", body)
	}
}

// fireDueCrons invokes every schedule whose time has come and re-arms it.
func (i *Invoker) fireDueCrons(ctx context.Context) {
	now := i.now()

	type delivery struct {
		target   Target
		path     string
		schedule string
	}
	var due []delivery

	i.mu.Lock()
	for ti := range i.targets {
		t := &i.targets[ti]
		for ci := range t.crons {
			c := &t.crons[ci]
			if c.next.IsZero() || c.next.After(now) {
				continue
			}
			due = append(due, delivery{target: t.Target, path: c.path, schedule: c.expr})
			// Next from now, not from the missed tick: ticks a stopped daemon
			// slept through are skipped, never replayed (PRD v1.37's shape;
			// catch-up state would be per-sample durable state).
			if next, err := c.schedule.Next(now); err == nil {
				c.next = next
			} else {
				c.next = time.Time{}
			}
		}
	}
	i.mu.Unlock()

	for _, d := range due {
		//nolint:errcheck // a map[string]string cannot fail to marshal
		body, _ := json.Marshal(map[string]string{
			"trigger":  "cron",
			"schedule": d.schedule,
			"fired_at": now.UTC().Format(time.RFC3339),
		})
		i.invokeAsync(ctx, d.target, d.path, "cron", body)
	}
}

// armCron points the timer at the soonest next fire.
func (i *Invoker) armCron(timer *time.Timer) {
	i.mu.Lock()
	var soonest time.Time
	for _, t := range i.targets {
		for _, c := range t.crons {
			if c.next.IsZero() {
				continue
			}
			if soonest.IsZero() || c.next.Before(soonest) {
				soonest = c.next
			}
		}
	}
	i.mu.Unlock()

	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	if soonest.IsZero() {
		// Nothing scheduled. A long re-arm rather than no timer keeps the
		// select shape simple; a reload re-arms properly.
		timer.Reset(time.Hour)
		return
	}
	d := time.Until(soonest)
	if d < 0 {
		d = 0
	}
	timer.Reset(d)
}

// invokeAsync delivers on its own goroutine, bounded by the semaphore so a
// storm against a slow function queues here rather than growing without
// limit.
func (i *Invoker) invokeAsync(ctx context.Context, t Target, path, kind string, body []byte) {
	select {
	case i.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	go func() {
		defer func() { <-i.sem }()
		i.invoke(ctx, t, path, kind, body)
	}()
}

// invoke POSTs with bounded retries; exhausting them emits
// function.invoke_failed (§11): the only function.* event, and one no
// function trigger can match.
func (i *Invoker) invoke(ctx context.Context, t Target, path, kind string, body []byte) {
	if path == "" {
		path = "/"
	}
	url := t.BaseURL + path
	name := t.Project + "/" + t.Service

	started := i.now()

	// Resolve the signing secret once per invocation, not per attempt: the
	// value is the same across retries, and a reference that stops resolving
	// fails the invocation rather than sending unsigned (R26); a declared
	// control silently dropped is worse than one never claimed.
	var signing []byte
	if t.SigningRef != "" {
		if i.resolver == nil {
			i.failSigning(t, kind, "no resolver configured for signing_ref")
			return
		}
		secret, err := i.resolver.Resolve(ctx, t.SigningRef)
		if err != nil {
			i.failSigning(t, kind, "cannot resolve signing_ref: "+err.Error())
			return
		}
		signing = secret
	}

	var lastErr error
	for attempt := 1; attempt <= i.maxAttempts; attempt++ {
		if err := i.post(ctx, url, kind, body, signing); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return
			}
			if attempt < i.maxAttempts {
				i.sleep(ctx, i.retryBase*time.Duration(1<<(attempt-1)))
			}
			continue
		}
		i.recordOutcome(name, started, true)
		return
	}

	i.recordOutcome(name, started, false)
	i.log.Warn("function invocation failed; retries exhausted",
		"function", name, "trigger", kind, "error", lastErr)
	if i.publish != nil {
		i.publish(notify.NewEvent(notify.EventFunctionInvokeFailed, t.Project, t.Service,
			fmt.Sprintf("%s trigger: %d attempts failed: %s", kind, i.maxAttempts, lastErr),
			i.now()))
	}
}

// post is one attempt. When signing is non-nil the body is MACed with the
// webhook channel's exact format (R26, v1.40) so a function verifies an
// invocation the same way it verifies a Kanea webhook.
func (i *Invoker) post(ctx context.Context, url, kind string, body, signing []byte) error {
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kanea-Trigger", kind)
	if signing != nil {
		// The timestamp is inside the MAC and on the wire, exactly as the
		// webhook channel does it: one Sign, one format.
		ts := strconv.FormatInt(i.now().Unix(), 10)
		req.Header.Set(notify.TimestampHeader, ts)
		req.Header.Set(notify.SignatureHeader, notify.Sign(signing, ts, body))
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // cleanup path
	// Drained under a cap and discarded: the invoker reads nothing from a
	// function's answer, and the cap is what makes that true for a function
	// that answers with a stream.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes)) //nolint:errcheck // best-effort drain
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return nil
}

// failSigning records an invocation lost because its signature could not be
// produced. Counted as a failure and surfaced as function.invoke_failed; the
// fail-closed direction (R26): unsigned delivery to a function that verifies
// is a dropped control wearing a delivery's clothes.
func (i *Invoker) failSigning(t Target, kind, reason string) {
	i.recordOutcome(t.Project+"/"+t.Service, i.now(), false)
	i.log.Warn("function invocation not signed; dropping it",
		"function", t.Project+"/"+t.Service, "trigger", kind, "reason", reason)
	if i.publish != nil {
		i.publish(notify.NewEvent(notify.EventFunctionInvokeFailed, t.Project, t.Service,
			kind+" trigger: "+reason, i.now()))
	}
}

// recordOutcome updates one function's counters.
func (i *Invoker) recordOutcome(name string, started time.Time, ok bool) {
	elapsed := i.now().Sub(started)

	i.mu.Lock()
	defer i.mu.Unlock()
	st := i.stats[name]
	if st == nil {
		st = &Stats{}
		i.stats[name] = st
	}
	st.Invocations++
	if !ok {
		st.Failures++
	}
	st.LastInvoked = started
	st.LatenciesMS = append(st.LatenciesMS, float64(elapsed.Milliseconds()))
	if len(st.LatenciesMS) > latencyRing {
		st.LatenciesMS = st.LatenciesMS[len(st.LatenciesMS)-latencyRing:]
	}
}

// Snapshot returns a copy of every function's counters, keyed by
// "project/service". Absent until the first invocation: "no data is never
// zero" applies to bookkeeping too.
func (i *Invoker) Snapshot() map[string]Stats {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make(map[string]Stats, len(i.stats))
	for name, st := range i.stats {
		clone := *st
		clone.LatenciesMS = append([]float64(nil), st.LatenciesMS...)
		out[name] = clone
	}
	return out
}
