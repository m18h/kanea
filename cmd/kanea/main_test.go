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

func TestUnimplementedCommandsReportMilestone(t *testing.T) {
	for _, c := range commands {
		if c.name == "version" {
			continue
		}
		if err := c.run(nil); !errors.Is(err, errNotImplemented) {
			t.Errorf("command %q: expected errNotImplemented, got %v", c.name, err)
		}
	}
}
