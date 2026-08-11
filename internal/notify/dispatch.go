package notify

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The dispatcher (PRD §11: storm protection, rate limits, at-least-once with
// retry, "failures logged, never block the control plane").
//
// The shape follows from one rule (AGENTS.md #8): emitting an event must never
// block the thing that emitted it. A reconciler noticing forty crashed allocs
// is already having a bad minute; making it wait on Telegram's API would turn a
// notification subsystem into an outage amplifier.
//
// So Publish is a non-blocking send onto a bounded queue with a drop counter,
// and everything expensive — coalescing, rate limiting, retrying — happens
// behind it on the dispatcher's own goroutine.

// Defaults for the dispatcher.
const (
	// DefaultQueueDepth bounds the events waiting to be routed. Past it,
	// Publish drops and counts rather than waiting.
	DefaultQueueDepth = 1024
	// DefaultCoalesceWindow is how long a channel gathers events before
	// sending. §11's "42 allocs restarted in 5m" is this window doing its job:
	// long enough that a storm becomes one message, short enough that a single
	// deploy failure still arrives while someone is watching.
	DefaultCoalesceWindow = 10 * time.Second
	// DefaultMaxBatch caps one message. A digest of a thousand events is not
	// more useful than a digest of fifty saying there were a thousand.
	DefaultMaxBatch = 50
	// DefaultMaxAttempts bounds delivery attempts, retries included.
	DefaultMaxAttempts = 4
	// DefaultRetryBase is the first backoff step; it doubles from there.
	DefaultRetryBase = 2 * time.Second
	// DefaultRateLimit is how many messages one channel may send per minute.
	// A crash-looping fleet must never get the Telegram bot rate-limited or
	// blocked, which is a limit imposed on Kanea if Kanea does not impose one
	// on itself.
	DefaultRateLimit = 10
)

// Sink receives every event that survives its channel's filter, in addition to
// the channels themselves — the dashboard feed §11 requires all channels be
// mirrored into.
//
// Called on the dispatcher's goroutine and expected not to block; the one
// implementation is the Store-backed feed, which is fast and bounded.
type Sink interface {
	Record(ctx context.Context, e Event)
}

// Route is one channel and what it wants.
type Route struct {
	Channel Channel
	Filter  Filter
	// Project scopes the route. Empty means node-wide — a server-level default
	// that sees every project's events. A project-level route sees only its
	// own, which is the boundary that stops one project's chat receiving
	// another's failures.
	Project string
	// RateLimit overrides DefaultRateLimit, in messages per minute. Negative
	// disables the limit, which is a decision an operator has to make on
	// purpose.
	RateLimit int
	// CoalesceWindow overrides DefaultCoalesceWindow.
	CoalesceWindow time.Duration
}

// Config configures the dispatcher.
type Config struct {
	Routes []Route
	Sink   Sink
	Logger *slog.Logger
	// QueueDepth bounds the pending events. Zero means DefaultQueueDepth.
	QueueDepth int
	// MaxBatch caps one message. Zero means DefaultMaxBatch.
	MaxBatch int
	// MaxAttempts bounds delivery attempts. Zero means DefaultMaxAttempts.
	MaxAttempts int
	// RetryBase is the first backoff step. Zero means DefaultRetryBase.
	RetryBase time.Duration
	Now       func() time.Time
	// sleep is injectable so a retry test does not actually wait.
	sleep func(context.Context, time.Duration)
}

// Dispatcher fans events out to channels.
type Dispatcher struct {
	// routes is swappable at runtime (v1.46). Behind an atomic pointer because
	// Test and Channels read it from handler goroutines; the per-route mutable
	// state (pending, sent) is still touched only on Run's goroutine, which is
	// also the only writer of the pointer.
	routes atomic.Pointer[[]*routeState]
	// reload carries a replacement route set to Run's goroutine. Buffered one
	// deep with latest-wins semantics: two reconfigurations in one tick mean
	// only the second describes reality.
	reload chan []Route
	sink   Sink
	log    *slog.Logger
	queue  chan Event
	now    func() time.Time
	sleep  func(context.Context, time.Duration)

	maxBatch    int
	maxAttempts int
	retryBase   time.Duration

	// dropped counts events Publish could not queue. Exported through
	// Dropped() so the exporter can surface it: a silent drop in a
	// notification system is the worst possible failure, so it is counted and
	// logged rather than merely happening.
	dropped atomic.Int64
	// suppressed counts messages a rate limit held back.
	suppressed atomic.Int64
	// delivered and failed count outcomes.
	delivered atomic.Int64
	failed    atomic.Int64

	// warnOnce keeps a full queue from writing a log line per dropped event —
	// which would turn a notification storm into a logging storm.
	warnOnce sync.Once
}

// routeState is a route plus the state coalescing and limiting need.
type routeState struct {
	Route
	pending []Event
	// flushAt is when the pending batch is due. Zero means nothing pending.
	flushAt time.Time
	// sent tracks message times inside the rate-limit window.
	sent []time.Time
	// window is the resolved coalesce window.
	window time.Duration
	// limit is the resolved rate limit.
	limit int
}

// New builds a dispatcher.
func New(cfg Config) (*Dispatcher, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.QueueDepth <= 0 {
		cfg.QueueDepth = DefaultQueueDepth
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = DefaultMaxBatch
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.RetryBase <= 0 {
		cfg.RetryBase = DefaultRetryBase
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.sleep == nil {
		cfg.sleep = sleepCtx
	}

	d := &Dispatcher{
		sink: cfg.Sink, log: cfg.Logger,
		queue:    make(chan Event, cfg.QueueDepth),
		reload:   make(chan []Route, 1),
		now:      cfg.Now,
		sleep:    cfg.sleep,
		maxBatch: cfg.MaxBatch, maxAttempts: cfg.MaxAttempts, retryBase: cfg.RetryBase,
	}
	states, err := buildRouteStates(cfg.Routes, cfg.Logger)
	if err != nil {
		return nil, err
	}
	d.routes.Store(&states)
	return d, nil
}

// buildRouteStates resolves routes into runnable state, shared by New and the
// runtime reload so the two cannot drift.
func buildRouteStates(routes []Route, log *slog.Logger) ([]*routeState, error) {
	var out []*routeState
	for _, r := range routes {
		if r.Channel == nil {
			return nil, errors.New("notify: a route needs a channel")
		}
		// A route whose filter can never match is dropped here rather than
		// consulted per event forever.
		if r.Filter.Empty() {
			log.Warn("notification channel has no event filter and will send nothing",
				"channel", r.Channel.Name(), "project", r.Project)
			continue
		}
		state := &routeState{Route: r, window: r.CoalesceWindow, limit: r.RateLimit}
		if state.window <= 0 {
			state.window = DefaultCoalesceWindow
		}
		if state.limit == 0 {
			state.limit = DefaultRateLimit
		}
		out = append(out, state)
	}
	return out, nil
}

// SetRoutes replaces the route set (v1.46). Safe from any goroutine; the swap
// itself happens on Run's, where the per-route state lives. Latest wins: a
// pending replacement that was never applied is superseded, not queued.
func (d *Dispatcher) SetRoutes(routes []Route) {
	for {
		select {
		case d.reload <- routes:
			return
		default:
			select {
			case <-d.reload:
			default:
			}
		}
	}
}

// Publish queues an event. It never blocks and never fails.
//
// The signature has no error on purpose. Every caller is a control-plane path
// that has something more important to do than handle a notification failure,
// and an error return would only invite someone to write `if err != nil { return
// err }` in a reconcile loop — turning an undeliverable Slack message into a
// failed deploy.
func (d *Dispatcher) Publish(e Event) {
	select {
	case d.queue <- e:
	default:
		d.dropped.Add(1)
		d.warnOnce.Do(func() {
			d.log.Warn("notification queue is full; events are being dropped",
				"depth", cap(d.queue),
				"hint", "check whether a channel is wedged; see the kanea_notify_dropped metric")
		})
	}
}

// Run works the queue until the context ends.
func (d *Dispatcher) Run(ctx context.Context) {
	// A short tick rather than a timer per route: with a handful of routes the
	// difference is noise, and one ticker cannot leak.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush what is pending before going away. A digest that was two
			// seconds from being sent when the daemon restarted is a digest
			// nobody ever sees, and the events in it are exactly the ones that
			// preceded a restart.
			d.flushAll(context.WithoutCancel(ctx), true)
			return
		case e := <-d.queue:
			d.route(ctx, e)
		case routes := <-d.reload:
			d.applyRoutes(ctx, routes)
		case <-ticker.C:
			d.flushAll(ctx, false)
		}
	}
}

// applyRoutes swaps the route set on Run's own goroutine.
//
// Pending digests are force-flushed first, whole set: a digest two seconds
// from sending when the operator reconfigured channels must not be silently
// discarded, and delivering it through the outgoing route is the only honest
// option. Rate windows reset with the routes — reloads are rare, and a
// carried-over window would need identity matching for a property nobody
// observes.
func (d *Dispatcher) applyRoutes(ctx context.Context, routes []Route) {
	d.flushAll(ctx, true)
	states, err := buildRouteStates(routes, d.log)
	if err != nil {
		// Unreachable from the wired path — the builders never hand a nil
		// channel — but a bad set must not tear down the good one.
		d.log.Error("refusing a broken route set; keeping the current channels", "error", err)
		return
	}
	d.routes.Store(&states)
	d.log.Info("notification routes reconfigured", "routes", len(states))
}

// route files one event against every matching channel.
func (d *Dispatcher) route(ctx context.Context, e Event) {
	// The feed sees everything, before and regardless of any channel. It is
	// the record; the channels are the notification.
	if d.sink != nil {
		d.sink.Record(ctx, e)
	}

	now := d.now()
	for _, r := range *d.routes.Load() {
		// A project-level route sees only its own project's events. Without
		// this, one project's chat receives another's failures — the same
		// boundary R5 draws for secrets.
		if r.Project != "" && r.Project != e.Project {
			continue
		}
		if !r.Filter.Match(e) {
			continue
		}

		r.pending = append(r.pending, e)
		if r.flushAt.IsZero() {
			r.flushAt = now.Add(r.window)
		}
		// A full batch goes now rather than waiting out the window: the window
		// exists to gather a storm, and the batch is already a storm.
		if len(r.pending) >= d.maxBatch {
			d.flush(ctx, r, now, false)
		}
	}
}

// flushAll sends every route whose window has closed.
func (d *Dispatcher) flushAll(ctx context.Context, force bool) {
	now := d.now()
	for _, r := range *d.routes.Load() {
		if len(r.pending) == 0 {
			continue
		}
		if force || !now.Before(r.flushAt) {
			d.flush(ctx, r, now, force)
		}
	}
}

// flush delivers one route's pending batch.
//
// final bypasses the rate limit. It is set only on the shutdown path: holding a
// batch back is correct while the daemon is running and about to try again, and
// wrong when it is going away — the events would be re-pended into a struct
// nobody will look at, which is a silent loss dressed as backpressure.
func (d *Dispatcher) flush(ctx context.Context, r *routeState, now time.Time, final bool) {
	batch := r.pending
	r.pending, r.flushAt = nil, time.Time{}
	if len(batch) == 0 {
		return
	}

	if !final && !d.allow(r, now) {
		// Held, not dropped. Discarding the digest would lose exactly the
		// events a storm produced, which is the opposite of what coalescing is
		// for: the limit is on *messages* to a third party, not on what the
		// next message may say. They go back to pending and merge into it.
		//
		// Bounded, because a channel that stays limited would otherwise grow
		// this without end. The newest are kept — during a storm the recent
		// state is the useful one — and whatever falls off is counted so the
		// loss is visible rather than silent.
		d.suppressed.Add(1)
		if overflow := len(batch) - d.maxBatch; overflow > 0 {
			batch = batch[overflow:]
			d.dropped.Add(int64(overflow))
		}
		r.pending = append(batch, r.pending...)
		// Retry when the window has room again rather than immediately, so a
		// limited channel is not re-evaluated on every tick.
		r.flushAt = now.Add(r.retryAfter(now))

		// Logged at info, not warning: being rate limited is the system
		// working. It says how much is held so an operator can tell
		// suppression from silence.
		d.log.Info("notification held by the channel rate limit",
			"channel", r.Channel.Name(), "held", len(r.pending),
			"limit_per_minute", r.limit, "retry_in", r.flushAt.Sub(now))
		return
	}

	// Oldest first, so a digest reads as a timeline.
	sort.SliceStable(batch, func(i, j int) bool { return batch[i].At.Before(batch[j].At) })

	if err := d.deliver(ctx, r.Channel, batch); err != nil {
		d.failed.Add(1)
		d.log.Error("notification delivery failed",
			"channel", r.Channel.Name(), "events", len(batch), "error", err)
		return
	}
	d.delivered.Add(1)
}

// retryAfter is how long until the rate-limit window has room.
//
// Derived from the oldest send in the window rather than a fixed delay: that is
// the moment a slot actually frees, so the next attempt is neither early
// (wasting a tick) nor late (delaying an alert past its usefulness).
func (r *routeState) retryAfter(now time.Time) time.Duration {
	if len(r.sent) == 0 {
		return time.Second
	}
	if wait := time.Minute - now.Sub(r.sent[0]); wait > 0 {
		return wait
	}
	return time.Second
}

// allow applies the per-channel rate limit.
//
// A sliding window over send times rather than a token bucket: the thing being
// limited is "messages per minute to a third party that will block us", and a
// bucket's burst allowance is the one property that does not help there.
func (d *Dispatcher) allow(r *routeState, now time.Time) bool {
	if r.limit < 0 {
		return true
	}
	cutoff := now.Add(-time.Minute)
	kept := r.sent[:0]
	for _, t := range r.sent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.sent = kept

	if len(r.sent) >= r.limit {
		return false
	}
	r.sent = append(r.sent, now)
	return true
}

// deliver sends a batch, retrying what is worth retrying.
func (d *Dispatcher) deliver(ctx context.Context, ch Channel, batch []Event) error {
	var err error
	for attempt := range d.maxAttempts {
		if attempt > 0 {
			// Exponential, capped. Nothing here is worth waiting minutes for:
			// a notification that arrives ten minutes after the incident is
			// history, not an alert.
			backoff := min(
				time.Duration(math.Pow(2, float64(attempt-1)))*d.retryBase,
				time.Minute,
			)
			d.sleep(ctx, backoff)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}

		err = ch.Send(ctx, batch)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrPermanent) {
			// Retrying will not fix it, and the queue behind this has other
			// channels waiting.
			return err
		}
		if ctx.Err() != nil {
			return err
		}
	}
	return err
}

// Stats reports the counters, for the exporter and for tests.
type Stats struct {
	// Dropped is events Publish could not queue.
	Dropped int64
	// Suppressed is messages a rate limit held back.
	Suppressed int64
	// Delivered and Failed are message outcomes, not event counts: one
	// delivered digest of forty events is one delivery.
	Delivered int64
	Failed    int64
}

// Stats returns a snapshot.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		Dropped:    d.dropped.Load(),
		Suppressed: d.suppressed.Load(),
		Delivered:  d.delivered.Load(),
		Failed:     d.failed.Load(),
	}
}

// Channels names the configured channels, for reporting configuration back.
func (d *Dispatcher) Channels() []string {
	routes := *d.routes.Load()
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Channel.Name())
	}
	return out
}

// sleepCtx waits, or returns early when the context ends.
func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// TestResult reports what one channel did with a test message.
type TestResult struct {
	Channel string `json:"channel"`
	Project string `json:"project,omitempty"`
	OK      bool   `json:"ok"`
	// Error is the failure, if there was one. It is the channel's own error
	// text, which the channels are careful never to build from a URL that
	// carries a token (see TelegramChannel.Send).
	Error string `json:"error,omitempty"`
}

// Test sends a test message through the matching channels (PRD §11).
//
// Synchronous, and deliberately not routed through Publish: a test exists to
// answer "is this channel wired up", and the queue, the coalescing window and
// the rate limiter all stand between an event and an answer. It also bypasses
// the filters, because a channel configured for `deploy.*` would silently
// discard a test and leave the operator no better informed than before.
//
// It does honour the retry policy, since a channel that works on the second
// attempt does work.
func (d *Dispatcher) Test(project, channel string) []TestResult {
	// Bounded independently of any caller's deadline: an HTTP handler is waiting
	// on this, and a channel pointed at a black hole would otherwise hold the
	// connection for as long as its own timeouts allow.
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var results []TestResult
	for _, r := range *d.routes.Load() {
		name := r.Channel.Name()
		// A project-scoped test never reaches another project's channels, and
		// never the node-wide ones either: an operator testing their own
		// project's Telegram should not page the node administrator.
		if project != "" && r.Project != project {
			continue
		}
		if channel != "" && name != channel && !strings.HasSuffix(name, "/"+channel) {
			continue
		}

		results = append(results, d.testRoute(ctx, r))
	}
	return results
}

// TestNodeChannels tests only the node-wide routes (v1.46) — the ones Test's
// project filter can never name, because their scope is the empty string.
func (d *Dispatcher) TestNodeChannels(channel string) []TestResult {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var results []TestResult
	for _, r := range *d.routes.Load() {
		if r.Project != "" {
			continue
		}
		name := r.Channel.Name()
		if channel != "" && name != channel && !strings.HasSuffix(name, "/"+channel) {
			continue
		}
		results = append(results, d.testRoute(ctx, r))
	}
	return results
}

// testRoute sends one test message through one route.
func (d *Dispatcher) testRoute(ctx context.Context, r *routeState) TestResult {
	event := NewEvent(EventTest, r.Project, "",
		"test message from Kanea — this channel is configured correctly", d.now())
	result := TestResult{Channel: r.Channel.Name(), Project: r.Project, OK: true}
	if err := d.deliver(ctx, r.Channel, []Event{event}); err != nil {
		result.OK, result.Error = false, err.Error()
	}
	return result
}

// testTimeout bounds a whole test action, retries included.
const testTimeout = 30 * time.Second
