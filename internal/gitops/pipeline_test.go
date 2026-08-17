package gitops_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/store"
)

// clock is a controllable time source: run ordering and retention are both
// time-shaped, and neither is testable against a real clock.
type clock struct{ at time.Time }

func (c *clock) now() time.Time          { return c.at }
func (c *clock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newRuns(t *testing.T) (*gitops.Runs, *clock, store.Store) {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	c := &clock{at: time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)}
	runs, err := gitops.NewRuns(st, c.now)
	if err != nil {
		t.Fatalf("NewRuns: %v", err)
	}
	return runs, c, st
}

// create records a run for a service, advancing the clock so ids order.
func create(t *testing.T, runs *gitops.Runs, c *clock, project, service string) gitops.Run {
	t.Helper()
	run, err := runs.Create(context.Background(), gitops.Run{
		Project: project, Service: service, Trigger: gitops.TriggerManual,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	c.advance(time.Second)
	return run
}

func TestCreateStampsAQueuedRun(t *testing.T) {
	runs, c, _ := newRuns(t)

	run, err := runs.Create(context.Background(), gitops.Run{
		Project: "shop", Service: "web", Trigger: gitops.TriggerPush, Commit: "abc123",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if run.ID == "" {
		t.Fatal("no id assigned")
	}
	// Queued, not running: builds are serialised on the node, so a queue is a
	// real state rather than an instant.
	if run.State != gitops.RunQueued {
		t.Errorf("state = %q, want queued", run.State)
	}
	if !run.StartedAt.Equal(c.at) {
		t.Errorf("started = %v, want the injected clock", run.StartedAt)
	}
}

func TestCreateNeedsAService(t *testing.T) {
	runs, _, _ := newRuns(t)
	if _, err := runs.Create(context.Background(), gitops.Run{Project: "shop"}); err == nil {
		t.Fatal("a run with no service was accepted")
	}
}

func TestRunsRoundTrip(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	// Created directly rather than through the helper, which advances the clock
	// after stamping StartedAt: the duration under test is measured from it.
	run, err := runs.Create(ctx, gitops.Run{Project: "shop", Service: "web"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	run.Start(c.at)
	run.BeginStep(gitops.StepBuild, c.at)
	c.advance(30 * time.Second)
	run.EndStep(gitops.StepBuild, c.at, nil)
	run.Image = "registry.example.com/shop/web:abc123"
	run.Digest = "sha256:deadbeef"
	run.Finish(c.at, nil)

	if err := runs.Update(ctx, run); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, gerr := runs.Get(ctx, "shop", "web", run.ID)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if got.State != gitops.RunSucceeded || got.Digest != "sha256:deadbeef" {
		t.Fatalf("run = %+v", got)
	}
	if len(got.Steps) != 1 || got.Steps[0].State != gitops.RunSucceeded {
		t.Fatalf("steps = %+v", got.Steps)
	}
	if got.Duration(c.at) != 30*time.Second {
		t.Errorf("duration = %v, want 30s", got.Duration(c.at))
	}
}

func TestGetMissingRun(t *testing.T) {
	runs, _, _ := newRuns(t)
	if _, err := runs.Get(context.Background(), "shop", "web", "nope"); !errors.Is(err, gitops.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListIsNewestFirst(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	var created []gitops.Run
	for range 5 {
		created = append(created, create(t, runs, c, "shop", "web"))
	}

	got, err := runs.List(ctx, "shop", "web", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("runs = %d, want 5", len(got))
	}
	// The newest build is the one an operator wants first, and the key's
	// time-ordered suffix is what makes that a reverse scan rather than a sort.
	for i, run := range got {
		want := created[len(created)-1-i]
		if run.ID != want.ID {
			t.Fatalf("run[%d] = %s, want %s, not newest first", i, run.ID, want.ID)
		}
	}
}

func TestListScopesToAService(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	create(t, runs, c, "shop", "web")
	create(t, runs, c, "shop", "api")
	create(t, runs, c, "blog", "web")
	// A service whose name starts the same way must not be swept in by the
	// prefix: "web" would otherwise take "web-admin" with it.
	create(t, runs, c, "shop", "web-admin")

	scoped, err := runs.List(ctx, "shop", "web", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(scoped) != 1 {
		t.Fatalf("runs = %+v, want just shop/web", scoped)
	}

	project, err := runs.List(ctx, "shop", "", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(project) != 3 {
		t.Fatalf("project runs = %d, want 3", len(project))
	}

	all, err := runs.List(ctx, "", "", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("all runs = %d, want 4", len(all))
	}
}

func TestListIsBounded(t *testing.T) {
	runs, c, _ := newRuns(t)
	for range 10 {
		create(t, runs, c, "shop", "web")
	}

	got, err := runs.List(context.Background(), "shop", "web", 3)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("runs = %d, want the requested 3", len(got))
	}
}

func TestLatest(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	if _, ok, err := runs.Latest(ctx, "shop", "web"); err != nil || ok {
		t.Fatalf("Latest on an empty history = %v, %v", ok, err)
	}

	create(t, runs, c, "shop", "web")
	last := create(t, runs, c, "shop", "web")

	got, ok, err := runs.Latest(ctx, "shop", "web")
	if err != nil || !ok {
		t.Fatalf("Latest: %v, %v", ok, err)
	}
	if got.ID != last.ID {
		t.Fatalf("latest = %s, want %s", got.ID, last.ID)
	}
}

func TestPruneKeepsPerService(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	// A busy service and a quiet one. Retention is per service so the busy one
	// cannot push the quiet one's only build out of history.
	for range 10 {
		run := create(t, runs, c, "shop", "web")
		run.Finish(c.at, nil)
		if err := runs.Update(ctx, run); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}
	quiet := create(t, runs, c, "blog", "site")
	quiet.Finish(c.at, nil)
	if err := runs.Update(ctx, quiet); err != nil {
		t.Fatalf("Update: %v", err)
	}

	pruned, err := runs.Prune(ctx, 3)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 7 {
		t.Fatalf("pruned = %d, want 7", pruned)
	}

	web, err := runs.List(ctx, "shop", "web", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(web) != 3 {
		t.Fatalf("kept %d runs for the busy service, want 3", len(web))
	}
	blog, err := runs.List(ctx, "blog", "site", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(blog) != 1 {
		t.Fatalf("the quiet service lost its history: %d runs", len(blog))
	}
}

func TestPruneKeepsRunsStillInFlight(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	for range 5 {
		run := create(t, runs, c, "shop", "web")
		run.Finish(c.at, nil)
		if err := runs.Update(ctx, run); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}
	// A build that is still going is not history yet, whatever its age;
	// deleting it would leave a runner writing to a record that is gone.
	running := create(t, runs, c, "shop", "web")
	running.Start(c.at)
	if err := runs.Update(ctx, running); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if _, err := runs.Prune(ctx, 1); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := runs.Get(ctx, "shop", "web", running.ID); err != nil {
		t.Fatalf("an in-flight run was pruned: %v", err)
	}
}

func TestFinishClosesAnOpenStep(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	run := gitops.Run{Project: "shop", Service: "web"}
	run.Start(c.at)
	run.BeginStep(gitops.StepBuild, c.at)

	c.advance(time.Second)
	run.Finish(c.at, errors.New("buildkitd went away"))

	// A finished run with a step still marked running renders as a spinner
	// that never stops.
	if run.Steps[0].State == gitops.RunRunning {
		t.Fatal("a step was left running inside a finished run")
	}
	if run.State != gitops.RunFailed || run.Error == "" {
		t.Fatalf("run = %+v, want a failure with a reason", run)
	}
}

func TestEndStepRecordsTheFailure(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	run := gitops.Run{Project: "shop", Service: "web"}
	run.BeginStep(gitops.StepCheckout, c.at)
	run.EndStep(gitops.StepCheckout, c.at, nil)
	run.BeginStep(gitops.StepBuild, c.at)
	run.EndStep(gitops.StepBuild, c.at, errors.New("no such file: Containerfile"))

	if run.Steps[0].State != gitops.RunSucceeded {
		t.Errorf("checkout = %q, want succeeded", run.Steps[0].State)
	}
	if run.Steps[1].State != gitops.RunFailed {
		t.Errorf("build = %q, want failed", run.Steps[1].State)
	}
	// Which step failed and why is the whole point of recording steps at all.
	if run.Steps[1].Error == "" {
		t.Error("a failed step carries no reason")
	}
}

func TestCancelIsNotAFailure(t *testing.T) {
	c := &clock{at: time.Unix(1_800_000_000, 0).UTC()}
	run := gitops.Run{Project: "shop", Service: "web"}
	run.Start(c.at)
	run.BeginStep(gitops.StepBuild, c.at)
	run.Cancel(c.at, "kanead is shutting down")

	// A cancelled build says nothing about the source; a failed one blames it.
	if run.State != gitops.RunCancelled {
		t.Fatalf("state = %q, want cancelled", run.State)
	}
	if !run.State.Terminal() {
		t.Error("cancelled is not terminal")
	}
}

func TestRunIDsSortChronologicallyAndAreUnique(t *testing.T) {
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	// Two runs in the same nanosecond must not collide: the second would
	// silently replace the first in the Store.
	seen := map[string]bool{}
	var ids []string
	for range 50 {
		run, err := runs.Create(ctx, gitops.Run{Project: "shop", Service: "web"})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if seen[run.ID] {
			t.Fatalf("duplicate run id %s", run.ID)
		}
		seen[run.ID] = true
		ids = append(ids, run.ID)
	}
	_ = c

	stored, err := runs.List(ctx, "shop", "web", 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(stored) != len(ids) {
		t.Fatalf("stored %d runs, created %d; ids collided in the Store", len(stored), len(ids))
	}
}

func TestShortIDIsTheReadableHalf(t *testing.T) {
	runs, c, _ := newRuns(t)
	run := create(t, runs, c, "shop", "web")

	short := gitops.ShortID(run.ID)
	// The nanosecond prefix exists to sort, not to be read aloud.
	if short == run.ID || len(short) != 8 {
		t.Fatalf("ShortID(%q) = %q, want the 8-character suffix", run.ID, short)
	}
	if fmt.Sprintf("%020d-%s", run.StartedAt.UTC().UnixNano(), short) != run.ID {
		t.Errorf("the short id is not the id's suffix: %q", short)
	}
}

func TestSweepOrphansClosesWhatACrashLeft(t *testing.T) {
	// A crash strands runs the graceful drain would have closed (v1.37): a
	// queued run is cancelled with the drain's vocabulary, a running one is
	// failed with its open step closed, and finished runs are untouched.
	runs, c, st := newRuns(t)
	ctx := context.Background()

	queued := create(t, runs, c, "shop", "web")

	running := create(t, runs, c, "shop", "api")
	running.Start(c.at)
	running.BeginStep(gitops.StepBuild, c.at)
	if err := runs.Update(ctx, running); err != nil {
		t.Fatalf("Update: %v", err)
	}

	finished := create(t, runs, c, "shop", "worker")
	finished.Start(c.at)
	finished.Finish(c.at, nil)
	if err := runs.Update(ctx, finished); err != nil {
		t.Fatalf("Update: %v", err)
	}

	before, err := st.Index(ctx)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	swept, err := runs.SweepOrphans(ctx)
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if len(swept) != 2 {
		t.Fatalf("swept %d runs, want 2", len(swept))
	}

	got, err := runs.Get(ctx, "shop", "web", queued.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != gitops.RunCancelled {
		t.Errorf("queued run swept to %q, want cancelled", got.State)
	}
	if got.Error == "" {
		t.Error("the cancelled run does not say why")
	}

	got, err = runs.Get(ctx, "shop", "api", running.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != gitops.RunFailed {
		t.Errorf("running run swept to %q, want failed", got.State)
	}
	if len(got.Steps) != 1 || got.Steps[0].State != gitops.RunFailed {
		t.Errorf("the open step was not closed: %+v", got.Steps)
	}

	got, err = runs.Get(ctx, "shop", "worker", finished.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != gitops.RunSucceeded {
		t.Errorf("a finished run was rewritten to %q", got.State)
	}

	// One Apply batch: the sweep is one event, not one per stranded run.
	after, err := st.Index(ctx)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if after != before+1 {
		t.Errorf("the sweep spent %d store batches, want 1", after-before)
	}
}

func TestSweepOrphansWithNothingToDoWritesNothing(t *testing.T) {
	runs, c, st := newRuns(t)
	ctx := context.Background()

	finished := create(t, runs, c, "shop", "web")
	finished.Start(c.at)
	finished.Finish(c.at, nil)
	if err := runs.Update(ctx, finished); err != nil {
		t.Fatalf("Update: %v", err)
	}

	before, err := st.Index(ctx)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	swept, err := runs.SweepOrphans(ctx)
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if len(swept) != 0 {
		t.Fatalf("swept %d runs on a clean bucket", len(swept))
	}
	after, err := st.Index(ctx)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if after != before {
		t.Error("a no-op sweep wrote to the store")
	}
}

func TestSweptRunsAreEventuallyPruned(t *testing.T) {
	// The secondary leak: Prune skips non-terminal runs, so before the sweep a
	// crash-orphaned run was pinned against retention forever.
	runs, c, _ := newRuns(t)
	ctx := context.Background()

	orphan := create(t, runs, c, "shop", "web")
	for range 3 {
		newer := create(t, runs, c, "shop", "web")
		newer.Start(c.at)
		newer.Finish(c.at, nil)
		if err := runs.Update(ctx, newer); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}

	if _, err := runs.SweepOrphans(ctx); err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if _, err := runs.Prune(ctx, 2); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := runs.Get(ctx, "shop", "web", orphan.ID); !errors.Is(err, gitops.ErrNotFound) {
		t.Errorf("the swept orphan survived pruning: %v", err)
	}
}
