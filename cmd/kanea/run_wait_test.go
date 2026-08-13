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
	printStragglers(o, desired, allocs)
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
