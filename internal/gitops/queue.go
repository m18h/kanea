package gitops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// The build queue.
//
// Builds are serialised: §10.2 makes isolation collective, so a second
// concurrent build shares the first's budget rather than getting its own, and
// a queue is therefore a real state a run sits in rather than an instant it
// passes through. That is why `queued` is in the run state machine.
//
// Submitting is asynchronous by necessity: a build takes minutes and an HTTP
// request must not. The caller gets a run id immediately and follows the record.

// DefaultQueueDepth bounds how many builds may be waiting.
//
// Past it, submitting fails rather than blocking. A webhook handler that blocks
// on a full queue holds a connection GitHub will time out, and a queue with no
// bound turns a push loop into unbounded memory plus an unbounded backlog of
// builds for commits nobody is waiting for any more.
const DefaultQueueDepth = 32

// ErrQueueFull means the build queue is at capacity.
var ErrQueueFull = errors.New("gitops: the build queue is full")

// queued is one submitted build.
type queued struct {
	run Run
	req Request
}

// Queue serialises builds behind one worker.
type Queue struct {
	runner *Runner
	work   chan queued
	log    *slog.Logger
	now    func() time.Time
	// emit publishes build events (§11). Nil disables them.
	emit func(project, service, name, message string)
}

// QueueConfig configures the build queue.
type QueueConfig struct {
	Runner *Runner
	// Depth bounds the backlog. Zero means DefaultQueueDepth.
	Depth  int
	Logger *slog.Logger
	Now    func() time.Time
	// Emit publishes build events. The signature is strings rather than a
	// notify.Event so this package does not depend on notify: the daemon
	// adapts, which keeps the dependency pointing one way.
	Emit func(project, service, name, message string)
}

// NewQueue builds the queue.
func NewQueue(cfg QueueConfig) (*Queue, error) {
	if cfg.Runner == nil {
		return nil, errors.New("gitops: a runner is required")
	}
	if cfg.Depth <= 0 {
		cfg.Depth = DefaultQueueDepth
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Queue{
		runner: cfg.Runner, work: make(chan queued, cfg.Depth),
		log: cfg.Logger, now: cfg.Now, emit: cfg.Emit,
	}, nil
}

// Submit records a queued run and enqueues it, returning immediately.
func (q *Queue) Submit(ctx context.Context, req Request) (Run, error) {
	run, err := q.runner.Queue(ctx, req)
	if err != nil {
		return Run{}, err
	}

	select {
	case q.work <- queued{run: run, req: req}:
		q.log.Info("build queued",
			"service", run.ServiceKey(), "run", ShortID(run.ID), "trigger", run.Trigger)
		return run, nil
	default:
		// The record exists, so mark it cancelled rather than leaving a queued
		// run nothing will ever pick up.
		run.Cancel(q.now(), "the build queue was full")
		if uerr := q.runner.runs.Update(ctx, run); uerr != nil {
			q.log.Error("cannot record a rejected build", "run", run.ID, "error", uerr)
		}
		return run, fmt.Errorf("%w (%d waiting)", ErrQueueFull, len(q.work))
	}
}

// Run works the queue until the context ends.
func (q *Queue) Run(ctx context.Context) {
	for {
		// Checked before the select, not only inside it. A select whose cases
		// are both ready picks at random, so a cancelled context does not stop
		// it from taking one more item, and executing that item would fail
		// every Store write, leaving the run stuck at "queued" with nothing
		// left to move it.
		if ctx.Err() != nil {
			q.drain(context.WithoutCancel(ctx))
			return
		}

		select {
		case <-ctx.Done():
			q.drain(context.WithoutCancel(ctx))
			return
		case item := <-q.work:
			if ctx.Err() != nil {
				// Cancelled between the check above and this receive. The item
				// is already out of the channel, so drain will not see it: it
				// has to be cancelled here or it is lost.
				q.cancel(context.WithoutCancel(ctx), item, "kanead stopped before this build started")
				continue
			}
			q.notify(item.run, "build.started",
				"build "+ShortID(item.run.ID)+" started")

			// One at a time, deliberately. The error is already recorded on the
			// run by Execute; what comes back here is a failure to write the
			// record, which is all this can usefully log.
			done, err := q.runner.Execute(ctx, item.run, item.req)
			if err != nil {
				q.log.Error("cannot record a build result",
					"service", item.run.ServiceKey(), "run", item.run.ID, "error", err)
			}
			q.notifyResult(item.run, done)
		}
	}
}

// notify publishes one build event.
func (q *Queue) notify(run Run, name, message string) {
	if q.emit == nil {
		return
	}
	q.emit(run.Project, run.Service, name, message)
}

// notifyResult publishes the outcome of a finished build.
//
// Reads the state rather than the error, because a cancelled build is neither a
// success nor a failure and only the record knows which it was.
func (q *Queue) notifyResult(queued Run, done Run) {
	run := done
	if run.ID == "" {
		run = queued
	}
	switch run.State {
	case RunSucceeded:
		message := "build " + ShortID(run.ID) + " succeeded"
		if run.Image != "" {
			message += " → " + run.Image
		}
		q.notify(run, "build.succeeded", message)
	case RunFailed:
		message := "build " + ShortID(run.ID) + " failed"
		if run.Error != "" {
			message += ": " + run.Error
		}
		q.notify(run, "build.failed", message)
	default:
		// Cancelled, or a state nothing is waiting on. Not a notification:
		// somebody asked for it, so they already know.
	}
}

// drain cancels whatever is still waiting when the daemon stops.
//
// A queued run that nothing will pick up would sit at "queued" forever, and
// after a restart an operator would be looking at a build that never happened
// with no indication that it never will.
func (q *Queue) drain(ctx context.Context) {
	for {
		select {
		case item := <-q.work:
			q.cancel(ctx, item, "kanead stopped before this build started")
		default:
			return
		}
	}
}

// cancel marks one queued run cancelled.
func (q *Queue) cancel(ctx context.Context, item queued, reason string) {
	item.run.Cancel(q.now(), reason)
	if err := q.runner.runs.Update(ctx, item.run); err != nil {
		q.log.Warn("cannot cancel a queued build", "run", item.run.ID, "error", err)
	}
}

// Depth is how many builds are waiting, for the exporter and for a caller
// deciding whether to submit another.
func (q *Queue) Depth() int { return len(q.work) }
