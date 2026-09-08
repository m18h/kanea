package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
)

// fakeUpgrader stands in for the daemon's self-update machinery.
type fakeUpgrader struct {
	mu         sync.Mutex
	checks     int
	latest     string
	upgradeErr error
	// block, when set, holds Upgrade until released, announcing itself on
	// entered first: the in-progress test.
	block   chan struct{}
	entered chan struct{}

	canRestart bool
	restarted  atomic.Bool
}

func (f *fakeUpgrader) Check(context.Context) (api.UpgradeCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	return api.UpgradeCheck{Running: "v0.30.0", Latest: f.latest, UpdateAvailable: f.latest != "v0.30.0"}, nil
}

func (f *fakeUpgrader) Upgrade(_ context.Context, target string) (api.UpgradeOutcome, error) {
	if f.block != nil {
		f.entered <- struct{}{}
		<-f.block
	}
	if f.upgradeErr != nil {
		return api.UpgradeOutcome{}, f.upgradeErr
	}
	if target == "" {
		target = f.latest
	}
	if target == "v0.30.0" {
		return api.UpgradeOutcome{Installed: target,
			Notes: []string{"the daemon is already running " + target}}, nil
	}
	return api.UpgradeOutcome{Installed: target,
		Notes: []string{"signature verified", "installed " + target}, RestartNeeded: true}, nil
}

func (f *fakeUpgrader) Restart(context.Context) error {
	f.restarted.Store(true)
	return nil
}

func (f *fakeUpgrader) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

func (f *fakeUpgrader) CanRestart() bool { return f.canRestart }

func withUpgrader(f *fakeUpgrader) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.Upgrader = f }
}

func TestUpgradeRoutesAre503WithoutAnUpgrader(t *testing.T) {
	// "This daemon cannot upgrade itself" is a supported state (a dev run, a
	// non-Linux build) and it is different from a failure.
	h := newHarness(t)
	if status, _ := h.raw(t, http.MethodGet, api.PathUpgrade); status != http.StatusServiceUnavailable {
		t.Errorf("check = %d, want 503", status)
	}
	if status, _ := h.raw(t, http.MethodPost, api.PathUpgrade); status != http.StatusServiceUnavailable {
		t.Errorf("upgrade = %d, want 503", status)
	}
}

func TestUpgradeCheckCachesForAnHour(t *testing.T) {
	// The check runs only when a dashboard asks (PRD v1.107), and the cache is
	// what turns a refetch cadence into at most one upstream request an hour.
	fake := &fakeUpgrader{latest: "v0.31.0"}
	clock := struct {
		mu  sync.Mutex
		now time.Time
	}{now: time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)}
	h := newHarness(t, withUpgrader(fake), func(cfg *api.ServerConfig) {
		cfg.Now = func() time.Time {
			clock.mu.Lock()
			defer clock.mu.Unlock()
			return clock.now
		}
	})

	for i := 0; i < 3; i++ {
		status, body := h.raw(t, http.MethodGet, api.PathUpgrade)
		if status != http.StatusOK {
			t.Fatalf("check %d = %d: %s", i, status, body)
		}
		var check api.UpgradeCheck
		if err := json.Unmarshal([]byte(body), &check); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !check.UpdateAvailable || check.Latest != "v0.31.0" {
			t.Fatalf("check %d = %+v, want v0.31.0 available", i, check)
		}
		if check.CheckedAt.IsZero() {
			t.Fatalf("check %d has no checked_at; the dashboard cannot say how stale it is", i)
		}
	}
	if fake.checkCount() != 1 {
		t.Errorf("three fresh reads cost %d upstream checks, want 1", fake.checkCount())
	}

	clock.mu.Lock()
	clock.now = clock.now.Add(61 * time.Minute)
	clock.mu.Unlock()
	if status, body := h.raw(t, http.MethodGet, api.PathUpgrade); status != http.StatusOK {
		t.Fatalf("stale check = %d: %s", status, body)
	}
	if fake.checkCount() != 2 {
		t.Errorf("a stale cache cost %d upstream checks, want 2", fake.checkCount())
	}
}

func TestUpgradeIsAdminOnly(t *testing.T) {
	// Replacing the node's binary is admin's, and so is making the daemon
	// originate a request to the release host.
	fake := &fakeUpgrader{latest: "v0.31.0"}
	h := newAuthHarness(t, withUpgrader(fake))

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := h.request(t, method, api.PathUpgrade, nil)
		req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
		resp, body := h.do(t, req)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s as viewer = %d, want 403: %s", method, resp.StatusCode, body)
		}
	}
	if fake.checkCount() != 0 {
		t.Errorf("a viewer's request reached the release host (%d checks)", fake.checkCount())
	}
}

func TestUpgradeInstallsAndRestarts(t *testing.T) {
	fake := &fakeUpgrader{latest: "v0.31.0", canRestart: true}
	h := newHarness(t, withUpgrader(fake))

	status, body := h.raw(t, http.MethodPost, api.PathUpgrade)
	if status != http.StatusOK {
		t.Fatalf("upgrade = %d: %s", status, body)
	}
	var resp api.UpgradeResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Installed != "v0.31.0" || !resp.Restarting || resp.RestartRequired {
		t.Fatalf("response = %+v, want v0.31.0 restarting", resp)
	}
	// No backup destination is configured on the harness: that must be a note
	// the admin sees, never a silent skip and never a refusal.
	var noted bool
	for _, note := range resp.Notes {
		if note == "no backup destination is configured on this daemon; "+
			"the schema migration still takes a local copy before it runs" {
			noted = true
		}
	}
	if !noted {
		t.Errorf("notes %q never say the backup was skipped", resp.Notes)
	}

	// The restart is deliberately after the response, so it is only
	// observable by waiting for it.
	deadline := time.Now().Add(5 * time.Second)
	for !fake.restarted.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the daemons never restarted after a restarting:true response")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestUpgradeWithoutASupervisorStagesInstead(t *testing.T) {
	// A kanead that exits with no systemd behind it is just gone, so the
	// response must say a restart is the operator's to perform - the staged
	// posture - and nothing may restart.
	fake := &fakeUpgrader{latest: "v0.31.0", canRestart: false}
	h := newHarness(t, withUpgrader(fake))

	status, body := h.raw(t, http.MethodPost, api.PathUpgrade)
	if status != http.StatusOK {
		t.Fatalf("upgrade = %d: %s", status, body)
	}
	var resp api.UpgradeResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Restarting || !resp.RestartRequired {
		t.Fatalf("response = %+v, want restart_required without restarting", resp)
	}
	time.Sleep(1500 * time.Millisecond)
	if fake.restarted.Load() {
		t.Error("an unsupervised daemon restarted itself")
	}
}

func TestUpgradeAlreadyCurrentDoesNotRestart(t *testing.T) {
	fake := &fakeUpgrader{latest: "v0.30.0", canRestart: true}
	h := newHarness(t, withUpgrader(fake))

	status, body := h.raw(t, http.MethodPost, api.PathUpgrade)
	if status != http.StatusOK {
		t.Fatalf("upgrade = %d: %s", status, body)
	}
	var resp api.UpgradeResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Restarting || resp.RestartRequired {
		t.Fatalf("nothing to do, yet the response promises a restart: %+v", resp)
	}
}

func TestUpgradeErrorStatuses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		// A downgrade is a conflict with the running daemon, with no override
		// over the API (K-41): --allow-downgrade is CLI-on-the-node.
		{"downgrade", fmt.Errorf("%w (v0.29.0 < v0.30.0)", api.ErrUpgradeDowngrade), http.StatusConflict},
		{"bad target", fmt.Errorf("%w: %q", api.ErrUpgradeBadTarget, "latest"), http.StatusBadRequest},
		// Everything else is the release channel's failure, not this daemon's.
		{"unreachable", errors.New("cannot reach github.com"), http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeUpgrader{latest: "v0.31.0", upgradeErr: tc.err}
			h := newHarness(t, withUpgrader(fake))
			if status, body := h.raw(t, http.MethodPost, api.PathUpgrade); status != tc.want {
				t.Errorf("upgrade = %d, want %d: %s", status, tc.want, body)
			}
		})
	}
}

func TestASecondUpgradeIsRefusedWhileOneRuns(t *testing.T) {
	// Two installs racing rename(2) over the same path is a coin flip about
	// which release the node ends up on.
	fake := &fakeUpgrader{latest: "v0.31.0",
		block: make(chan struct{}), entered: make(chan struct{}, 1)}
	h := newHarness(t, withUpgrader(fake))

	first := make(chan int, 1)
	go func() {
		status, _ := h.raw(t, http.MethodPost, api.PathUpgrade)
		first <- status
	}()

	// Wait until the first request is inside Upgrade, then race it.
	select {
	case <-fake.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first upgrade never started")
	}
	if status, body := h.raw(t, http.MethodPost, api.PathUpgrade); status != http.StatusConflict {
		t.Fatalf("a concurrent upgrade = %d, want 409: %s", status, body)
	}

	close(fake.block)
	if status := <-first; status != http.StatusOK {
		t.Fatalf("the first upgrade = %d, want 200", status)
	}
}
