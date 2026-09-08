package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/m18h/kanea/internal/api"
)

// testUpgrader builds a daemonUpgrader over a fake release, with the restart
// half stubbed out.
func testUpgrader(running string, source *releaseSource) *daemonUpgrader {
	return &daemonUpgrader{
		log: slog.New(slog.DiscardHandler), version: running,
		stop:        func() {},
		restartEdge: func(context.Context) error { return nil },
		source:      func() *releaseSource { return source },
	}
}

func TestUpgraderCheckComparesRunningToLatest(t *testing.T) {
	source := fakeRelease(t, "v0.31.0", nil)
	cases := []struct {
		running string
		want    bool
	}{
		{"v0.30.0", true},
		{"v0.31.0", false},
		{"v0.32.0", false},
		// A dev build compares equal to everything: it never claims an update
		// it cannot reason about.
		{"dev", false},
	}
	for _, tc := range cases {
		t.Run(tc.running, func(t *testing.T) {
			check, err := testUpgrader(tc.running, source).Check(context.Background())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if check.Running != tc.running || check.Latest != "v0.31.0" {
				t.Fatalf("check = %+v", check)
			}
			if check.UpdateAvailable != tc.want {
				t.Errorf("update_available = %v, want %v", check.UpdateAvailable, tc.want)
			}
		})
	}
}

func TestUpgraderRefusesABadTargetBeforeAnyFetch(t *testing.T) {
	// A nil source panics if reached: the grammar refusal must come first.
	u := testUpgrader("v0.30.0", nil)
	u.source = func() *releaseSource { t.Fatal("a malformed tag reached the release host"); return nil }
	_, err := u.Upgrade(context.Background(), "latest")
	if !errors.Is(err, api.ErrUpgradeBadTarget) {
		t.Fatalf("err = %v, want ErrUpgradeBadTarget", err)
	}
}

func TestUpgraderRefusesADowngrade(t *testing.T) {
	// K-41 with no override: --allow-downgrade is the CLI's, on the node.
	source := fakeRelease(t, "v0.31.0", nil)
	_, err := testUpgrader("v0.30.0", source).Upgrade(context.Background(), "v0.29.0")
	if !errors.Is(err, api.ErrUpgradeDowngrade) {
		t.Fatalf("err = %v, want ErrUpgradeDowngrade", err)
	}
}

func TestUpgraderAlreadyRunningTheTargetDoesNothing(t *testing.T) {
	source := fakeRelease(t, "v0.31.0", nil)
	outcome, err := testUpgrader("v0.31.0", source).Upgrade(context.Background(), "")
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if outcome.RestartNeeded || outcome.Installed != "v0.31.0" {
		t.Fatalf("outcome = %+v, want nothing-to-do at v0.31.0", outcome)
	}
	if len(outcome.Notes) == 0 {
		t.Error("nothing-to-do said nothing")
	}
}

func TestUpgraderRestartOrdersEdgeBeforeSelf(t *testing.T) {
	// The v1.59 order: the edge drains first, then kanead exits into
	// systemd's Restart=always.
	var order []string
	u := testUpgrader("v0.30.0", nil)
	u.restartEdge = func(context.Context) error { order = append(order, "edge"); return nil }
	u.stop = func() { order = append(order, "self") }
	if err := u.Restart(context.Background()); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if len(order) != 2 || order[0] != "edge" || order[1] != "self" {
		t.Fatalf("order = %v, want [edge self]", order)
	}
}

func TestUpgraderStillExitsWhenTheEdgeRefuses(t *testing.T) {
	// The binary is already swapped; stopping here would leave both daemons
	// on the old image with nothing saying so.
	var stopped bool
	u := testUpgrader("v0.30.0", nil)
	u.restartEdge = func(context.Context) error { return errors.New("unit not found") }
	u.stop = func() { stopped = true }
	if err := u.Restart(context.Background()); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if !stopped {
		t.Error("an edge failure kept the old kanead running silently")
	}
}
