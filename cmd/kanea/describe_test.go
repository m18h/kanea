package main

import (
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
)

func TestDeclaredButAbsentDerivesTheGhostRows(t *testing.T) {
	services := []reconciler.Desired{
		{Project: "media", Service: "plex", Count: 2, Image: "plex:latest"},
		{Project: "media", Service: "homer", Count: 0, Image: "homer:latest"},
		{Project: "other", Service: "web", Count: 1, Image: "web:latest"},
	}
	allocs := []reconciler.AllocRecord{
		{Project: "media", Service: "plex", Index: 0},
	}

	ghosts := declaredButAbsent(services, allocs, "", "")
	byID := map[string]psGhost{}
	for _, g := range ghosts {
		byID[g.project+"/"+g.service+"/"+g.id] = g
	}
	if len(ghosts) != 3 {
		t.Fatalf("got %d ghosts, want 3: %+v", len(ghosts), ghosts)
	}
	// plex slot 1 exists as a declaration only.
	slot, ok := byID["media/plex/"+reconciler.AllocID("media", "plex", 1)]
	if !ok || !strings.HasPrefix(slot.state, "pending") {
		t.Errorf("missing or wrong pending row: %+v", ghosts)
	}
	// homer is scaled to zero: one stopped row, no per-slot rows.
	stopped, ok := byID["media/homer/-"]
	if !ok || !strings.HasPrefix(stopped.state, "stopped") {
		t.Errorf("missing or wrong stopped row: %+v", ghosts)
	}

	// The project filter cuts like ps's own.
	if got := declaredButAbsent(services, allocs, "other", ""); len(got) != 1 {
		t.Errorf("project filter: got %+v, want only other/web", got)
	}
}

// Health renders absent as absent (§9.2): a check-free service must read "-",
// never "failing" — AllocRecord.Healthy is only ever written by a probe.
func TestDescribeAllocsRendersUnprobedHealthAsAbsent(t *testing.T) {
	var b strings.Builder
	o := &out{w: &b}
	svc := reconciler.Desired{Project: "media", Service: "plex", Count: 2}
	describeAllocs(o, svc, []reconciler.AllocRecord{
		{ID: "media-plex-0", State: reconciler.AllocRunning, CreatedAt: time.Now()},
		{ID: "media-plex-1", State: reconciler.AllocRunning, CreatedAt: time.Now(),
			Healthy: false, LastProbeAt: time.Now(), HealthMessage: "503"},
	})
	if err := o.Err(); err != nil {
		t.Fatal(err)
	}
	rows := b.String()
	probeless := ""
	for _, line := range strings.Split(rows, "\n") {
		if strings.Contains(line, "media-plex-0") {
			probeless = line
		}
	}
	if !strings.Contains(probeless, "-") || strings.Contains(probeless, "failing") {
		t.Errorf("an unprobed alloc must render health as \"-\":\n%s", rows)
	}
	if !strings.Contains(rows, "failing: 503") {
		t.Errorf("a probed-and-failing alloc must say so with its message:\n%s", rows)
	}
}

func TestDescribeAllocsNamesTheStoppedCase(t *testing.T) {
	var b strings.Builder
	o := &out{w: &b}
	describeAllocs(o, reconciler.Desired{Count: 0}, nil)
	if err := o.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "stopped") {
		t.Errorf("a count-0 service with no allocs must read stopped, got: %s", b.String())
	}
}
