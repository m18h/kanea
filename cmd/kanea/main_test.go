package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
)

func TestUsageListsAllCommands(t *testing.T) {
	var b strings.Builder
	if err := printUsage(&b); err != nil {
		t.Fatalf("printUsage: %v", err)
	}
	out := b.String()
	for _, c := range commands {
		if !strings.Contains(out, c.name) {
			t.Errorf("usage output missing command %q", c.name)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	if err := runVersion(nil); err != nil {
		t.Fatalf("runVersion: %v", err)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	if err := run([]string{"does-not-exist"}); err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestNoArgsPrintsUsage(t *testing.T) {
	if err := run(nil); err != nil {
		t.Fatalf("run with no args should print usage, got: %v", err)
	}
}

// implemented lists the commands that do real work today. Everything else must
// still report the milestone that will bring it, so `kanea backup` says "not
// implemented yet" rather than failing obscurely.
var implemented = map[string]bool{
	"version": true,
	// M1 runtime core:
	"agent": true, "plan": true, "run": true, "stop": true, "ps": true, "logs": true,
	"status": true,
	// M3 ingress:
	"edge": true,
	// M5 auth & secrets:
	"secret": true, "user": true, "token": true,
	// M6 metrics & autoscaling:
	"scale": true,
	// M7 GitOps & pipelines:
	"build": true, "project": true,
	// M9 MCP server:
	"mcp": true,
	// M10 hardening & packaging:
	"backup": true, "restore": true, "init": true, "doctor": true,
	"upgrade": true, "ui": true, "exec": true,
}

func TestUnimplementedCommandsReportMilestone(t *testing.T) {
	for _, c := range commands {
		if implemented[c.name] {
			continue
		}
		if !isStub(c.run) {
			t.Errorf("command %q is not in the implemented list but does not report the milestone", c.name)
		}
	}
}

// isStub reports whether a command still points at the not-implemented stub.
//
// Identity rather than invocation: `kanea agent` and `kanea edge` are daemons
// that bind listeners and run until interrupted, so calling them to find out
// whether they are wired would hang the test suite. It only worked while every
// implemented command happened to fail fast.
func isStub(run func([]string) error) bool {
	return reflect.ValueOf(run).Pointer() == reflect.ValueOf(todo).Pointer()
}

func TestImplementedCommandsAreWired(t *testing.T) {
	// Guards against the opposite mistake: a command listed as implemented but
	// still pointing at the todo stub.
	for name := range implemented {
		var found bool
		for _, c := range commands {
			if c.name != name {
				continue
			}
			found = true
			if isStub(c.run) {
				t.Errorf("command %q is listed as implemented but still points at the stub", name)
			}
		}
		if !found {
			t.Errorf("command %q is listed as implemented but missing from the table", name)
		}
	}
}

func TestServiceHealth(t *testing.T) {
	// `kanea status` is where an operator looks to decide whether to worry, so
	// "ok" must mean settled — not merely "nothing has failed yet".
	tests := []struct {
		name                                         string
		desired, running, backoff, failed, unhealthy int
		want                                         string
		wantSettled                                  bool
	}{
		{"all running", 2, 2, 0, 0, 0, "ok", true},
		{"still starting", 3, 1, 0, 0, 0, "starting", false},
		{"restarting", 2, 1, 1, 0, 0, "1 restarting", false},
		{"failed wins over restarting", 2, 0, 1, 1, 0, "1 failed", false},
		{"scaled to zero and drained", 0, 0, 0, 0, 0, "stopped", true},
		{"draining after a stop", 0, 1, 0, 0, 0, "stopping", false},
		{"scaling in", 1, 3, 0, 0, 0, "stopping", false},
		// An alloc that is up but failing its check is a different problem from
		// one that has not started; reporting it as "starting" would suggest
		// that waiting is enough.
		{"running but failing its check", 2, 2, 0, 0, 1, "1 unhealthy", false},
		{"unhealthy while still scaling up", 3, 2, 0, 0, 1, "1 unhealthy", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, settled := serviceHealth(tc.desired, tc.running, tc.backoff, tc.failed, tc.unhealthy)
			if got != tc.want || settled != tc.wantSettled {
				t.Errorf("serviceHealth(%d,%d,%d,%d,%d) = %q,%v; want %q,%v",
					tc.desired, tc.running, tc.backoff, tc.failed, tc.unhealthy,
					got, settled, tc.want, tc.wantSettled)
			}
		})
	}
}

// A service gated on a dependency has no allocs and therefore no records, so
// "starting" is all the alloc states can say. Status has to reconstruct the
// reason or an operator watches nothing happen and has to read the agent log.
func TestBlockedOnExplainsWhyAServiceHasNotStarted(t *testing.T) {
	api := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1, DependsOn: []string{"postgres", "cache"},
	}
	db := reconciler.Desired{Project: "shop", Service: "postgres", Count: 2}
	cache := reconciler.Desired{Project: "shop", Service: "cache", Count: 1}
	services := []reconciler.Desired{api, db, cache}

	tests := []struct {
		name   string
		counts map[string]*tally
		want   []string
	}{
		{
			name:   "nothing up yet",
			counts: map[string]*tally{},
			want:   []string{"cache", "postgres"},
		},
		{
			name: "one dependency partly up",
			counts: map[string]*tally{
				"shop/postgres": {running: 1}, // wants 2
				"shop/cache":    {running: 1},
			},
			want: []string{"postgres"},
		},
		{
			name: "dependency running but failing its check",
			counts: map[string]*tally{
				"shop/postgres": {running: 2},
				"shop/cache":    {running: 1, unhealthy: 1},
			},
			want: []string{"cache"},
		},
		{
			name: "everything healthy",
			counts: map[string]*tally{
				"shop/postgres": {running: 2},
				"shop/cache":    {running: 1},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := blockedOn(api, services, tc.counts)
			if len(got) != len(tc.want) {
				t.Fatalf("blockedOn = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("blockedOn = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A dependency deliberately scaled to zero is satisfied, not a deadlock.
func TestBlockedOnIgnoresZeroCountAndMissingDependencies(t *testing.T) {
	api := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1, DependsOn: []string{"postgres", "ghost"},
	}
	services := []reconciler.Desired{api, {Project: "shop", Service: "postgres", Count: 0}}

	if got := blockedOn(api, services, map[string]*tally{}); len(got) != 0 {
		t.Fatalf("blockedOn = %v, want nothing blocking", got)
	}
}
