package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// fakeDu answers `du` from a table, so a test can move a volume's size around
// without writing gigabytes to a temp directory.
type fakeDu struct {
	mu    sync.Mutex
	sizes map[string]int64
	errs  map[string]error
	calls []string
}

func newFakeDu() *fakeDu {
	return &fakeDu{sizes: map[string]int64{}, errs: map[string]error{}}
}

func (f *fakeDu) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := args[len(args)-1]
	f.calls = append(f.calls, name+" "+path)
	if err, ok := f.errs[path]; ok {
		return []byte("du: cannot read directory"), err
	}
	return fmt.Appendf(nil, "%d\t%s\n", f.sizes[path], path), nil
}

func (f *fakeDu) set(path string, size int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizes[path] = size
}

func (f *fakeDu) fail(path string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[path] = err
}

func (f *fakeDu) pathsCalled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// collector gathers emitted events.
type collector struct {
	mu     sync.Mutex
	events []notify.Event
}

func (c *collector) emit(e notify.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *collector) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.events))
	for _, e := range c.events {
		out = append(out, e.Name)
	}
	return out
}

func newTestSampler(t *testing.T, du Runner, emit func(notify.Event)) *UsageSampler {
	t.Helper()
	return NewUsageSampler(UsageConfig{
		Runner: du, Emit: emit,
		Now: func() time.Time { return time.Unix(0, 0).UTC() },
	})
}

func target(key, path string, budget int64) UsageTarget {
	return UsageTarget{
		Key: key, Project: "shop", Service: "web", Volume: key,
		Path: path, Type: TypeLocal, BudgetBytes: budget,
	}
}

func TestUsageIsAbsentUntilMeasured(t *testing.T) {
	s := newTestSampler(t, newFakeDu(), nil)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 0)})

	// The critical distinction: a volume nobody has measured is not an empty
	// volume, and rendering it as 0 would say it is (§9.2).
	if got, ok := s.Snapshot()["data"]; ok && got.Known {
		t.Errorf("usage = %+v before any measurement, want absent", got)
	}
}

func TestUsageIsMeasuredAndReported(t *testing.T) {
	du := newFakeDu()
	du.set("/vol/data", 4<<30)
	s := newTestSampler(t, du, nil)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 10<<30)})

	s.measureAll(context.Background())

	got := s.Snapshot()["data"]
	if !got.Known {
		t.Fatalf("usage = %+v, want a known reading", got)
	}
	if got.Bytes != 4<<30 {
		t.Errorf("bytes = %d, want %d", got.Bytes, 4<<30)
	}
}

// An s3 volume is a FUSE mount over an object store: walking it is a LIST per
// directory. It is skipped by name, and must not even be attempted.
func TestAnS3VolumeIsNeverWalked(t *testing.T) {
	du := newFakeDu()
	s := newTestSampler(t, du, nil)
	s3 := target("media", "/vol/media", 0)
	s3.Type = TypeS3
	s.SetTargets([]UsageTarget{s3})

	s.measureAll(context.Background())

	if calls := du.pathsCalled(); len(calls) != 0 {
		t.Errorf("du ran %v against an s3 volume", calls)
	}
	if got, ok := s.Snapshot()["media"]; ok && got.Known {
		t.Errorf("usage = %+v for an s3 volume, want absent", got)
	}
}

// A walk that fails reports absence, not zero — the same rule, applied to the
// error path where it is easiest to get wrong.
func TestAFailedWalkReportsAbsenceNotZero(t *testing.T) {
	du := newFakeDu()
	du.fail("/vol/data", errors.New("timed out"))
	s := newTestSampler(t, du, nil)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 10<<30)})

	s.measureAll(context.Background())

	got := s.Snapshot()["data"]
	if got.Known {
		t.Errorf("usage = %+v after a failed walk, want absent", got)
	}
	if got.Err == "" {
		t.Error("no error recorded for a failed walk")
	}
}

// The regression that matters most: a breached budget persists for hours and
// the sampler runs every five minutes. One event, not one per pass.
func TestTheBudgetEventFiresOnTransitionsOnly(t *testing.T) {
	du := newFakeDu()
	du.set("/vol/data", 20<<30)
	events := &collector{}
	s := newTestSampler(t, du, events.emit)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 10<<30)})

	for range 5 {
		s.measureAll(context.Background())
	}
	if got := events.names(); len(got) != 1 || got[0] != notify.EventVolumeOverBudget {
		t.Fatalf("events = %v, want exactly one %s", got, notify.EventVolumeOverBudget)
	}

	// Back under: one recovery event, and still nothing on the passes after.
	du.set("/vol/data", 1<<30)
	for range 5 {
		s.measureAll(context.Background())
	}
	want := []string{notify.EventVolumeOverBudget, notify.EventVolumeUnderBudget}
	if got := events.names(); len(got) != 2 || got[1] != want[1] {
		t.Errorf("events = %v, want %v", got, want)
	}
}

// A volume with no declared budget is measured but never judged: there is
// nothing to be over.
func TestAVolumeWithNoBudgetNeverNotifies(t *testing.T) {
	du := newFakeDu()
	du.set("/vol/data", 900<<30)
	events := &collector{}
	s := newTestSampler(t, du, events.emit)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 0)})

	s.measureAll(context.Background())

	if got := events.names(); len(got) != 0 {
		t.Errorf("events = %v for a volume with no budget, want none", got)
	}
	if !s.Snapshot()["data"].Known {
		t.Error("a volume with no budget should still be measured")
	}
}

// A failed walk must not clear a breach. Absence is not "under budget", and
// resolving an alert with a measurement that never happened is the §9.2
// mistake wearing a notification's clothes.
func TestAFailedWalkDoesNotClearABreach(t *testing.T) {
	du := newFakeDu()
	du.set("/vol/data", 20<<30)
	events := &collector{}
	s := newTestSampler(t, du, events.emit)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 10<<30)})
	s.measureAll(context.Background())

	du.fail("/vol/data", errors.New("timed out"))
	s.measureAll(context.Background())

	for _, name := range events.names() {
		if name == notify.EventVolumeUnderBudget {
			t.Fatal("a failed measurement cleared an over-budget verdict")
		}
	}
}

func TestSetTargetsForgetsVolumesThatAreGone(t *testing.T) {
	du := newFakeDu()
	du.set("/vol/data", 1<<30)
	s := newTestSampler(t, du, nil)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 0)})
	s.measureAll(context.Background())

	s.SetTargets([]UsageTarget{target("other", "/vol/other", 0)})

	if _, ok := s.Snapshot()["data"]; ok {
		t.Error("a removed volume kept its reading")
	}
}

func TestANilEmitNeverPanics(t *testing.T) {
	du := newFakeDu()
	du.set("/vol/data", 20<<30)
	s := newTestSampler(t, du, nil)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 1)})

	s.measureAll(context.Background()) // must not panic
}

func TestParseDuTotal(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want int64
		ok   bool
	}{
		{"plain", "4096\t/vol/data\n", 4096, true},
		// The Runner combines stderr in, so a warning can precede the total.
		{"after a warning", "du: cannot read 'x': Permission denied\n8192\t/vol/data\n", 8192, true},
		{"empty", "   \n", 0, false},
		{"not a number", "lots\t/vol/data\n", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDuTotal(tc.out)
			if tc.ok && err != nil {
				t.Fatalf("parseDuTotal: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected an error")
			}
			if got != tc.want {
				t.Errorf("bytes = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{4 << 20, "4.0 MiB"},
		{10 << 30, "10.0 GiB"},
		{2 << 40, "2.0 TiB"},
	} {
		if got := HumanBytes(tc.in); got != tc.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The measurement must be bounded by one filesystem: a volume containing
// another mount would otherwise report that mount's contents as its own.
func TestTheWalkStaysOnOneFilesystem(t *testing.T) {
	du := newFakeDu()
	s := newTestSampler(t, du, nil)
	s.SetTargets([]UsageTarget{target("data", "/vol/data", 0)})

	s.measureAll(context.Background())

	du.mu.Lock()
	defer du.mu.Unlock()
	if len(du.calls) == 0 || !strings.HasPrefix(du.calls[0], "du ") {
		t.Fatalf("calls = %v, want a du invocation", du.calls)
	}
}

// --- mount events (PRD v1.69, §11) ---

func mountManagerWithEvents(t *testing.T, runner Runner, events *collector) *Manager {
	t.Helper()
	return New(Config{
		Runner:        runner,
		CredentialDir: t.TempDir(),
		CheckTimeout:  200 * time.Millisecond,
		MountTable:    func(string) (bool, error) { return false, nil },
		Emit:          events.emit,
	})
}

func nfsMount(target string) Request {
	return Request{
		Resource: Resource{Name: "nas", Type: TypeNFS, Server: "10.0.0.5", Export: "/tank"},
		Target:   target,
	}
}

// The first successful mount is not a recovery. Reporting it as one would make
// every deploy look like an incident that resolved itself.
func TestAFirstSuccessfulMountIsSilent(t *testing.T) {
	events := &collector{}
	m := mountManagerWithEvents(t, newFakeRunner(), events)

	if err := m.Ensure(context.Background(), nfsMount(t.TempDir())); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got := events.names(); len(got) != 0 {
		t.Errorf("events = %v for a first mount, want none", got)
	}
}

// A dead NFS server is retried every reconcile pass. One event, not one per
// attempt — and one recovery event when it comes back.
func TestMountEventsFireOnTransitionsOnly(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("server not responding")
	events := &collector{}
	m := mountManagerWithEvents(t, runner, events)
	target := t.TempDir()

	// Several attempts. The backoff makes most of them short-circuit, which is
	// exactly the steady state a real node is in.
	for range 5 {
		_ = m.Ensure(context.Background(), nfsMount(target))
	}
	got := events.names()
	if len(got) != 1 || got[0] != notify.EventVolumeMountFailed {
		t.Fatalf("events = %v, want exactly one %s", got, notify.EventVolumeMountFailed)
	}

	// The server comes back.
	delete(runner.failWith, "mount")
	m2 := mountManagerWithEvents(t, runner, events)
	if err := m2.Ensure(context.Background(), nfsMount(target)); err != nil {
		t.Fatalf("Ensure after recovery: %v", err)
	}
	// A fresh Manager has no memory of the failure, so it stays silent — which
	// is the restart case, and is correct: nothing here claims to recover a
	// state it never observed.
	if got := events.names(); len(got) != 1 {
		t.Errorf("events = %v, want the failure alone", got)
	}
}

// Recovery within one Manager's lifetime is the case that matters, and it must
// report exactly once.
func TestAMountRecoveryIsAnnouncedOnce(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("server not responding")
	events := &collector{}
	m := mountManagerWithEvents(t, runner, events)
	target := t.TempDir()

	_ = m.Ensure(context.Background(), nfsMount(target))
	delete(runner.failWith, "mount")
	// Clear the backoff so the next Ensure actually attempts a mount.
	m.mounts[target].failures = 0

	for range 3 {
		if err := m.Ensure(context.Background(), nfsMount(target)); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		// Ensure short-circuits on an already-mounted target, so model the
		// mount table catching up only after the first success.
		withMountTable(m, target)
	}

	want := []string{notify.EventVolumeMountFailed, notify.EventVolumeMountRecovered}
	got := events.names()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("events = %v, want %v", got, want)
	}
}

func TestANilEmitNeverPanicsInTheManager(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("nope")
	m := testManager(t, runner, nil) // no Emit configured

	_ = m.Ensure(context.Background(), nfsMount(t.TempDir())) // must not panic
}
