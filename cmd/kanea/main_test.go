package main

import (
	"errors"
	"strings"
	"testing"
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
}

func TestUnimplementedCommandsReportMilestone(t *testing.T) {
	for _, c := range commands {
		if implemented[c.name] {
			continue
		}
		if err := c.run(nil); !errors.Is(err, errNotImplemented) {
			t.Errorf("command %q: expected errNotImplemented, got %v", c.name, err)
		}
	}
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
			if err := c.run(nil); errors.Is(err, errNotImplemented) {
				t.Errorf("command %q is listed as implemented but returns errNotImplemented", name)
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
		name                              string
		desired, running, backoff, failed int
		want                              string
		wantSettled                       bool
	}{
		{"all running", 2, 2, 0, 0, "ok", true},
		{"still starting", 3, 1, 0, 0, "starting", false},
		{"restarting", 2, 1, 1, 0, "1 restarting", false},
		{"failed wins over restarting", 2, 0, 1, 1, "1 failed", false},
		{"scaled to zero and drained", 0, 0, 0, 0, "stopped", true},
		{"draining after a stop", 0, 1, 0, 0, "stopping", false},
		{"scaling in", 1, 3, 0, 0, "stopping", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, settled := serviceHealth(tc.desired, tc.running, tc.backoff, tc.failed)
			if got != tc.want || settled != tc.wantSettled {
				t.Errorf("serviceHealth(%d,%d,%d,%d) = %q,%v; want %q,%v",
					tc.desired, tc.running, tc.backoff, tc.failed, got, settled, tc.want, tc.wantSettled)
			}
		})
	}
}
