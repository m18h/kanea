package main

import (
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
)

func TestAllocStateLabelExplainsItself(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		alloc reconciler.AllocRecord
		want  string
	}{
		{
			name:  "failed carries the exit code",
			alloc: reconciler.AllocRecord{State: reconciler.AllocFailed, LastExitCode: 137},
			want:  "failed (exit 137)",
		},
		{
			name: "backoff carries exit code and retry",
			alloc: reconciler.AllocRecord{
				State: reconciler.AllocBackoff, LastExitCode: 1,
				NextRestartAt: now.Add(2 * time.Second),
			},
			want: "backoff (exit 1",
		},
		{
			name:  "running with no probe is just running",
			alloc: reconciler.AllocRecord{State: reconciler.AllocRunning},
			want:  "running",
		},
		{
			name: "running but probed unhealthy says so",
			alloc: reconciler.AllocRecord{
				State: reconciler.AllocRunning, Healthy: false, LastProbeAt: now,
			},
			want: "running (unhealthy)",
		},
		{
			name:  "pending passes through",
			alloc: reconciler.AllocRecord{State: reconciler.AllocPending},
			want:  "pending",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := allocStateLabel(tc.alloc)
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("allocStateLabel = %q, want prefix %q", got, tc.want)
			}
		})
	}
}

// The bug this exists for: `kanea deploy` onto a crash-looped service exited 1
// on the *outgoing* deploy's dead alloc while the new container was starting
// behind it, failing a pipeline that was about to succeed (PRD v1.113).
func TestAWaitIsNotFailedByTheDeployItReplaces(t *testing.T) {
	desired := []reconciler.Desired{{Project: "huddle", Service: "website", Count: 1}}
	hashes := map[string]string{"huddle/website": "sha256:new"}
	id := reconciler.AllocID("huddle", "website", 0)

	cases := []struct {
		name        string
		alloc       reconciler.AllocRecord
		wantFailed  int
		wantRunning int
	}{
		{
			name: "failed under the previous hash is replacing, not failed",
			alloc: reconciler.AllocRecord{
				ID: id, Project: "huddle", Service: "website",
				State: reconciler.AllocFailed, LastExitCode: 1, SpecHash: "sha256:old",
			},
			wantFailed: 0,
		},
		{
			name: "failed on the hash being deployed is this deploy's failure",
			alloc: reconciler.AllocRecord{
				ID: id, Project: "huddle", Service: "website",
				State: reconciler.AllocFailed, LastExitCode: 1, SpecHash: "sha256:new",
			},
			wantFailed: 1,
		},
		{
			// An unstamped record is adopted, never rolled, so the planner will
			// not replace this one either: failing fast is the honest answer.
			name: "an unstamped failed record still fails the wait",
			alloc: reconciler.AllocRecord{
				ID: id, Project: "huddle", Service: "website",
				State: reconciler.AllocFailed, LastExitCode: 1,
			},
			wantFailed: 1,
		},
		{
			name: "the replacement running satisfies it",
			alloc: reconciler.AllocRecord{
				ID: id, Project: "huddle", Service: "website",
				State: reconciler.AllocRunning, SpecHash: "sha256:new",
			},
			wantRunning: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ours, running, failed := allocProgress(desired, hashes, []reconciler.AllocRecord{tc.alloc})
			if len(ours) != 1 {
				t.Fatalf("allocProgress kept %d allocs, want 1", len(ours))
			}
			if failed != tc.wantFailed {
				t.Errorf("failed = %d, want %d", failed, tc.wantFailed)
			}
			if running != tc.wantRunning {
				t.Errorf("running = %d, want %d", running, tc.wantRunning)
			}
		})
	}
}

// Without hashes - an older daemon, or a read that did not answer - the counts
// must be exactly what they were before the comparison existed: this sharpens
// a verdict, and may never be the reason a deploy cannot report one.
func TestAWaitWithoutHashesCountsAsItAlwaysDid(t *testing.T) {
	desired := []reconciler.Desired{{Project: "shop", Service: "web", Count: 2}}
	allocs := []reconciler.AllocRecord{
		{
			ID: reconciler.AllocID("shop", "web", 0), Project: "shop", Service: "web",
			State: reconciler.AllocFailed, SpecHash: "sha256:old",
		},
		{
			ID: reconciler.AllocID("shop", "web", 1), Project: "shop", Service: "web",
			State: reconciler.AllocRunning, SpecHash: "sha256:new",
		},
	}

	_, running, failed := allocProgress(desired, nil, allocs)
	if running != 1 || failed != 1 {
		t.Errorf("running, failed = %d, %d; want 1, 1", running, failed)
	}
}

// A replacing alloc in the straggler table has to say why it is there, or the
// table reads as the reason the command is still waiting when it is the
// opposite: the thing on its way out.
func TestStragglersSayWhenAnAllocIsBeingReplaced(t *testing.T) {
	desired := []reconciler.Desired{{Project: "huddle", Service: "website", Count: 1}}
	allocs := []reconciler.AllocRecord{{
		ID: reconciler.AllocID("huddle", "website", 0), Project: "huddle", Service: "website",
		State: reconciler.AllocFailed, LastExitCode: 1, SpecHash: "sha256:old",
	}}

	var buf strings.Builder
	o := &out{w: &buf}
	printStragglers(o, desired, map[string]string{"huddle/website": "sha256:new"}, allocs)
	if err := o.Err(); err != nil {
		t.Fatalf("printStragglers: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "failed (exit 1) (replacing)") {
		t.Errorf("summary does not mark the alloc as replacing:\n%s", got)
	}
}

// The straggler summary is the reason `kanea run` no longer ends with "see
// `kanea ps`": everything ps would say about a slot that is not up has to be
// in it, including declared slots that have no alloc record at all.
func TestStragglerSummaryNamesEverySlotThatIsNotUp(t *testing.T) {
	desired := []reconciler.Desired{
		{Project: "media", Service: "watchstate", Count: 1},
		{Project: "media", Service: "opds", Count: 1},
		{Project: "media", Service: "jellyfin", Count: 1},
		{Project: "media", Service: "navidrome", Count: 1},
	}
	allocs := []reconciler.AllocRecord{
		{
			ID:    reconciler.AllocID("media", "watchstate", 0),
			State: reconciler.AllocBackoff, LastExitCode: 1,
			NextRestartAt: time.Now().Add(time.Second),
		},
		{
			ID:    reconciler.AllocID("media", "jellyfin", 0),
			State: reconciler.AllocRunning,
		},
		{
			ID:    reconciler.AllocID("media", "navidrome", 0),
			State: reconciler.AllocRunning, Healthy: false, LastProbeAt: time.Now(),
		},
		// media-opds-0 has no record: the reconciler has not created it.
	}

	var buf strings.Builder
	o := &out{w: &buf}
	printStragglers(o, desired, nil, allocs)
	if err := o.Err(); err != nil {
		t.Fatalf("printStragglers: %v", err)
	}
	got := buf.String()

	for _, want := range []string{
		"media-watchstate-0", "backoff (exit 1",
		"media-opds-0", "pending (not created)",
		"media-navidrome-0", "running (unhealthy)",
		"kanea logs",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q:\n%s", want, got)
		}
	}
	// A slot that is up and healthy is not a straggler.
	if strings.Contains(got, "media-jellyfin-0") {
		t.Errorf("summary lists a healthy running alloc:\n%s", got)
	}
}
