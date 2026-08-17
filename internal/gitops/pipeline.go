package gitops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/store"
)

// Pipeline runs are first-class objects (PRD §10.2).
//
// "First-class" is the requirement, and it means a run outlives the process
// that produced it: an operator asking "what did that deploy build, and from
// which commit" gets an answer an hour later, from a restarted daemon, without
// reading a log. So a run is a Store record like a service or an alloc, not a
// struct in a goroutine's memory.
//
// The build *logs* are the exception, and go to files under the log directory
// like a workload's do (§17). A verbose build is megabytes of output, and the
// Store is a single-writer bbolt whose write budget is spent on state.

// pipelineKind is the bucket runs live in (PRD §5.2.3).
const pipelineKind = store.KindPipeline

// RunState is where a pipeline run has got to.
type RunState string

// Run states. A run moves forward only: queued → running → one terminal state.
const (
	// RunQueued is accepted but not started. Builds are serialised on the node
	// (§10.2 bounds concurrency inside buildkitd), so a queue is a real state
	// rather than an instant.
	RunQueued RunState = "queued"
	// RunRunning is in progress.
	RunRunning RunState = "running"
	// RunSucceeded produced an image.
	RunSucceeded RunState = "succeeded"
	// RunFailed did not. The step that failed carries the reason.
	RunFailed RunState = "failed"
	// RunCancelled was stopped deliberately: by an operator, or by a daemon
	// shutting down mid-build. Distinct from failed because it says nothing
	// about the source.
	RunCancelled RunState = "cancelled"
)

// Terminal reports whether a state is final.
func (s RunState) Terminal() bool {
	return s == RunSucceeded || s == RunFailed || s == RunCancelled
}

// Trigger is what caused a run.
//
// Recorded because it is the first question asked about a surprising deploy:
// "did someone push, or did someone click something".
type Trigger string

// Triggers (PRD §10.2).
const (
	// TriggerPush is a git push, by poll or webhook.
	TriggerPush Trigger = "push"
	// TriggerManual is `kanea build` or the dashboard.
	TriggerManual Trigger = "manual"
	// TriggerDeploy is `kanea run` finding the source newer than the last build.
	TriggerDeploy Trigger = "deploy"
)

// Run is one build of one service.
type Run struct {
	// ID is the Store key's unique half: time-ordered, so a listing is
	// chronological without sorting.
	ID      string `json:"id"`
	Project string `json:"project"`
	Service string `json:"service"`

	State   RunState `json:"state"`
	Trigger Trigger  `json:"trigger"`
	// TriggeredBy is the audit subject that asked, or the git ref for a push.
	TriggeredBy string `json:"triggered_by,omitempty"`

	// Commit is the revision built. A run without one is a build of whatever
	// was on disk, which is a thing `kanea build` can do and a push cannot.
	Commit string `json:"commit,omitempty"`
	// Ref is the branch the commit came from.
	Ref string `json:"ref,omitempty"`

	// Image is the reference that was pushed, and Digest pins it. The deploy
	// uses the digest rather than the tag: a tag is a moving pointer, and
	// §14 A08 wants the thing that ran to be the thing that was built.
	Image  string `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`

	Steps []Step `json:"steps,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Error is why a failed run failed, in one sentence.
	Error string `json:"error,omitempty"`
}

// Step is one stage of a run.
type Step struct {
	Name       string    `json:"name"`
	State      RunState  `json:"state"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Step names. Fixed strings because a dashboard renders them and someone will
// grep for them.
const (
	StepCheckout = "checkout"
	StepBuild    = "build"
	StepPush     = "push"
	StepDeploy   = "deploy"
)

// ServiceKey is "project/service", the form everything else in Kanea keys on.
func (r Run) ServiceKey() string { return r.Project + "/" + r.Service }

// Duration is how long the run took, or how long it has been going.
func (r Run) Duration(now time.Time) time.Duration {
	if r.StartedAt.IsZero() {
		return 0
	}
	if r.FinishedAt.IsZero() {
		return now.Sub(r.StartedAt)
	}
	return r.FinishedAt.Sub(r.StartedAt)
}

// Key is the Store key: "<project>/<service>/<id>".
//
// Prefixed by service so one service's history is a prefix scan, and suffixed
// by a time-ordered id so that scan comes back in order. The bucket holds every
// run on the node, and a listing that had to read all of them to show one
// service's would be the read pattern AGENTS.md #2 forbids.
func (r Run) Key() string { return RunKey(r.Project, r.Service, r.ID) }

// RunKey builds a run's Store key.
func RunKey(project, service, id string) string {
	return project + "/" + service + "/" + id
}

// Runs persists pipeline runs.
type Runs struct {
	store store.Store
	now   func() time.Time
}

// NewRuns builds the run store.
func NewRuns(st store.Store, now func() time.Time) (*Runs, error) {
	if st == nil {
		return nil, errors.New("gitops: a store is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Runs{store: st, now: now}, nil
}

// Create records a queued run and returns it with its id filled in.
func (r *Runs) Create(ctx context.Context, run Run) (Run, error) {
	if run.Project == "" || run.Service == "" {
		return Run{}, errors.New("gitops: a run needs a project and a service")
	}
	if run.State == "" {
		run.State = RunQueued
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = r.now()
	}
	id, err := newRunID(run.StartedAt)
	if err != nil {
		return Run{}, err
	}
	run.ID = id

	if err := r.put(ctx, run); err != nil {
		return Run{}, err
	}
	return run, nil
}

// Update replaces a run.
func (r *Runs) Update(ctx context.Context, run Run) error {
	if run.ID == "" {
		return errors.New("gitops: cannot update a run with no id")
	}
	return r.put(ctx, run)
}

// Get reads one run.
func (r *Runs) Get(ctx context.Context, project, service, id string) (Run, error) {
	run, _, err := store.GetValue[Run](ctx, r.store, pipelineKind, RunKey(project, service, id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Run{}, fmt.Errorf("%w: run %s", ErrNotFound, id)
		}
		return Run{}, err
	}
	return run, nil
}

// ErrNotFound marks a missing run.
var ErrNotFound = errors.New("gitops: not found")

// List returns runs newest first, optionally scoped to one service.
//
// Reverse order at the Store rather than a sort here: the key's time-ordered
// suffix means the newest run is the last key in the range, and "the last ten
// builds" should not read the whole bucket (AGENTS.md #2).
func (r *Runs) List(ctx context.Context, project, service string, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = DefaultRunListLimit
	}
	opts := store.ListOptions{Limit: limit, Reverse: true}
	if project != "" && service != "" {
		opts.Prefix = project + "/" + service + "/"
	} else if project != "" {
		opts.Prefix = project + "/"
	}

	runs, _, err := store.ListValues[Run](ctx, r.store, pipelineKind, opts)
	if err != nil {
		return nil, fmt.Errorf("gitops: list runs: %w", err)
	}
	return runs, nil
}

// DefaultRunListLimit bounds a listing that did not ask for one.
const DefaultRunListLimit = 50

// Latest returns the most recent run for a service, if there is one.
func (r *Runs) Latest(ctx context.Context, project, service string) (Run, bool, error) {
	runs, err := r.List(ctx, project, service, 1)
	if err != nil {
		return Run{}, false, err
	}
	if len(runs) == 0 {
		return Run{}, false, nil
	}
	return runs[0], true, nil
}

// Prune keeps the newest n runs per service and deletes the rest.
//
// Retention per service rather than node-wide: a busy service must not push a
// quiet one's history out, and "the last ten builds of *this*" is the question
// the dashboard actually asks.
func (r *Runs) Prune(ctx context.Context, keep int) (int, error) {
	if keep <= 0 {
		keep = DefaultRunRetention
	}

	all, err := r.listAll(ctx)
	if err != nil {
		return 0, err
	}
	byService := map[string][]Run{}
	for _, run := range all {
		key := run.Project + "/" + run.Service
		byService[key] = append(byService[key], run)
	}

	var muts []store.Mutation
	for _, runs := range byService {
		// listAll returns key order, which is oldest first within a service.
		sort.Slice(runs, func(i, j int) bool { return runs[i].ID > runs[j].ID })
		for i, run := range runs {
			if i < keep {
				continue
			}
			if !run.State.Terminal() {
				// A run still in flight is not history yet, whatever its age.
				continue
			}
			muts = append(muts, store.DeleteMutation(pipelineKind, run.Key()))
		}
	}
	if len(muts) == 0 {
		return 0, nil
	}
	if _, err := r.store.Apply(ctx, muts...); err != nil {
		return 0, fmt.Errorf("gitops: prune runs: %w", err)
	}
	return len(muts), nil
}

// DefaultRunRetention is how many runs per service are kept.
const DefaultRunRetention = 20

// SweepOrphans closes runs a crash left non-terminal (v1.37).
//
// The graceful path never leaves one (shutdown drains the queue and cancels
// what is waiting) but a crash does, and a run nothing will ever move again
// reads as a build still happening, forever. Prune skips non-terminal runs,
// so it would also be pinned against retention.
//
// A queued run is cancelled with the drain's vocabulary rather than
// re-enqueued: the request it was queued with is derived from the project
// config, and re-deriving it now could build something other than what was
// queued. A running run is failed: a build was lost mid-flight, and its log
// may stop mid-line. Everything lands in one Apply batch: the sweep is one
// event, not one per stranded run.
func (r *Runs) SweepOrphans(ctx context.Context) ([]Run, error) {
	all, err := r.listAll(ctx)
	if err != nil {
		return nil, err
	}

	at := r.now()
	var muts []store.Mutation
	var swept []Run
	for _, run := range all {
		if run.State.Terminal() {
			continue
		}
		if run.State == RunQueued {
			run.Cancel(at, "kanead restarted before this build started")
		} else {
			run.Finish(at, errors.New("kanead restarted before this build finished; the build log may be incomplete"))
		}
		mut, err := store.PutMutation(pipelineKind, run.Key(), run)
		if err != nil {
			return nil, err
		}
		muts = append(muts, mut)
		swept = append(swept, run)
	}
	if len(muts) == 0 {
		return nil, nil
	}
	if _, err := r.store.Apply(ctx, muts...); err != nil {
		return nil, fmt.Errorf("gitops: sweep orphaned runs: %w", err)
	}
	return swept, nil
}

func (r *Runs) put(ctx context.Context, run Run) error {
	mut, err := store.PutMutation(pipelineKind, run.Key(), run)
	if err != nil {
		return err
	}
	if _, err := r.store.Apply(ctx, mut); err != nil {
		return fmt.Errorf("gitops: write run %s: %w", run.Key(), err)
	}
	return nil
}

func (r *Runs) listAll(ctx context.Context) ([]Run, error) {
	var out []Run
	opts := store.ListOptions{}
	for {
		runs, page, err := store.ListValues[Run](ctx, r.store, pipelineKind, opts)
		if err != nil {
			return nil, fmt.Errorf("gitops: list runs: %w", err)
		}
		out = append(out, runs...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// ---- run mutation helpers ----
//
// The state machine lives in these rather than in the caller, so "a run went
// straight from queued to succeeded with no steps" is not a shape the runner
// can produce by forgetting a line.

// Start marks a run running.
func (r *Run) Start(at time.Time) {
	r.State = RunRunning
	if r.StartedAt.IsZero() {
		r.StartedAt = at
	}
}

// BeginStep appends a running step.
func (r *Run) BeginStep(name string, at time.Time) {
	r.Steps = append(r.Steps, Step{Name: name, State: RunRunning, StartedAt: at})
}

// EndStep closes the most recent step with the given name.
func (r *Run) EndStep(name string, at time.Time, err error) {
	for i := len(r.Steps) - 1; i >= 0; i-- {
		if r.Steps[i].Name != name || r.Steps[i].State != RunRunning {
			continue
		}
		r.Steps[i].FinishedAt = at
		if err != nil {
			r.Steps[i].State = RunFailed
			r.Steps[i].Error = err.Error()
		} else {
			r.Steps[i].State = RunSucceeded
		}
		return
	}
}

// Finish closes a run.
//
// A nil error succeeds it; anything else fails it and records why. The step is
// closed too if one is still open, because a run cannot be finished while a
// step inside it is still running: that shape would render as a spinner that
// never stops.
func (r *Run) Finish(at time.Time, err error) {
	for i := range r.Steps {
		if r.Steps[i].State == RunRunning {
			r.Steps[i].State = RunFailed
			r.Steps[i].FinishedAt = at
			if err != nil {
				r.Steps[i].Error = err.Error()
			}
		}
	}
	r.FinishedAt = at
	if err != nil {
		r.State = RunFailed
		r.Error = err.Error()
		return
	}
	r.State = RunSucceeded
}

// Cancel marks a run cancelled.
func (r *Run) Cancel(at time.Time, reason string) {
	for i := range r.Steps {
		if r.Steps[i].State == RunRunning {
			r.Steps[i].State = RunCancelled
			r.Steps[i].FinishedAt = at
		}
	}
	r.State = RunCancelled
	r.FinishedAt = at
	r.Error = reason
}

// newRunID mints a time-ordered id.
//
// Fixed-width nanoseconds plus a random suffix, the same shape the audit log
// uses: key order is chronological order, and two runs starting in the same
// nanosecond still get distinct keys.
func newRunID(at time.Time) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("gitops: random: %w", err)
	}
	return fmt.Sprintf("%020d-%s", at.UTC().UnixNano(), hex.EncodeToString(suffix)), nil
}

// ShortID is the human-facing form of a run id: the random suffix alone.
//
// The nanosecond prefix exists to sort, not to be read aloud. A CLI showing
// `kanea build` output has room for eight characters, and eight hex characters
// distinguish every run a service will ever have.
func ShortID(id string) string {
	if _, suffix, found := strings.Cut(id, "-"); found {
		return suffix
	}
	return id
}
