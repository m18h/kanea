//go:build integration

// Integration tests for the containerd driver. They need a real containerd and
// root, so they are tagged out of the normal build and run on the kanea-spike
// VM:
//
//	GOOS=linux GOARCH=arm64 go test -c -tags integration -o runtime.test ./internal/runtime
//	orb -m kanea-spike sudo ./runtime.test -test.v
//
// What is asserted here is exactly what unit tests cannot reach: that the
// hardening and limits in the OCI spec survive into a running container, and
// that the lifecycle behaves as the reconciler will assume.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testProject = "spike-runtime"
	testImage   = "docker.io/library/busybox:1.37"
)

func newDriver(t *testing.T) Driver {
	t.Helper()
	d, err := New(Config{})
	if err != nil {
		t.Skipf("containerd unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close driver: %v", err)
		}
	})
	return d
}

// allocFor builds a spec whose alloc id is unique per test, so a leftover from
// a failed run cannot make the next one pass or fail spuriously.
func allocFor(t *testing.T, command ...string) AllocSpec {
	t.Helper()
	id := fmt.Sprintf("itest-%s-%d", strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")), time.Now().UnixNano()%100000)
	if len(id) > 60 {
		id = id[:60]
	}
	return AllocSpec{
		ID:        id,
		Project:   testProject,
		Service:   "itest",
		Image:     testImage,
		Command:   command,
		Resources: Resources{CPUMillis: 500, MemoryBytes: 128 << 20, PidsLimit: 64},
		LogPath:   filepath.Join(t.TempDir(), "alloc.log"),
	}
}

func mustPull(t *testing.T, d Driver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := d.EnsureImage(ctx, testProject, testImage); err != nil {
		t.Fatalf("pull %s: %v", testImage, err)
	}
}

func TestIntegrationLifecycle(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	spec := allocFor(t, "sleep", "300")
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })

	status, err := d.Status(ctx, spec.Project, spec.ID)
	if err != nil {
		t.Fatalf("status after create: %v", err)
	}
	if status.State != StateCreated {
		t.Errorf("state after create = %q, want %q", status.State, StateCreated)
	}

	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	status, err = d.Status(ctx, spec.Project, spec.ID)
	if err != nil {
		t.Fatalf("status after start: %v", err)
	}
	if status.State != StateRunning {
		t.Fatalf("state after start = %q, want %q", status.State, StateRunning)
	}
	if status.PID == 0 {
		t.Error("running alloc has no pid")
	}

	found := false
	list, err := d.List(ctx, spec.Project)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range list {
		if s.ID == spec.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("alloc %s missing from List", spec.ID)
	}

	if err := d.Stop(ctx, spec.Project, spec.ID, 5*time.Second); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := d.Remove(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := d.Status(ctx, spec.Project, spec.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("status after remove: err = %v, want ErrNotFound", err)
	}
}

func TestIntegrationRemoveIsIdempotent(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)

	// Removing something that never existed, and removing twice, are both
	// paths the reconciler takes during cleanup.
	if err := d.Remove(ctx, testProject, "itest-never-existed"); err != nil {
		t.Errorf("remove of a missing alloc: %v", err)
	}
	if err := d.Stop(ctx, testProject, "itest-never-existed", time.Second); err != nil {
		t.Errorf("stop of a missing alloc: %v", err)
	}
}

func TestIntegrationExitIsObserved(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	spec := allocFor(t, "sh", "-c", "exit 7")
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })

	// Subscribe before starting: an exit that happens between start and
	// subscribe would otherwise be missed, which is exactly the race the
	// reconciler must not have.
	streamCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	exits, err := d.Exits(streamCtx, spec.Project)
	if err != nil {
		t.Fatalf("exits: %v", err)
	}

	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	exit, err := d.Wait(waitCtx, spec.Project, spec.ID)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if exit.ExitCode != 7 {
		t.Errorf("Wait exit code = %d, want 7", exit.ExitCode)
	}

	// The event stream must report the same exit.
	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev, ok := <-exits:
			if !ok {
				t.Fatal("event stream closed before the exit arrived")
			}
			if ev.Err != nil {
				t.Fatalf("event stream error: %v", ev.Err)
			}
			if ev.ID != spec.ID {
				continue // another test's alloc
			}
			if ev.ExitCode != 7 {
				t.Errorf("event exit code = %d, want 7", ev.ExitCode)
			}
			return
		case <-deadline:
			t.Fatal("no exit event within 30s")
		}
	}
}

func TestIntegrationStopKillsAnUncooperativeWorkload(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	// Traps SIGTERM and keeps running: a deploy must not hang on it.
	spec := allocFor(t, "sh", "-c", "trap '' TERM; while true; do sleep 1; done")
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })
	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	start := time.Now()
	if err := d.Stop(ctx, spec.Project, spec.ID, 2*time.Second); err != nil {
		t.Fatalf("stop: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 2*time.Second {
		t.Errorf("stop returned in %v — it did not wait out the grace period", elapsed)
	}
	if elapsed > 30*time.Second {
		t.Errorf("stop took %v — SIGKILL escalation looks broken", elapsed)
	}

	status, err := d.Status(ctx, spec.Project, spec.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != StateStopped {
		t.Errorf("state = %q, want %q", status.State, StateStopped)
	}
}

func TestIntegrationHardeningReachesTheContainer(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	// /proc/self/status reports the effective capability set as a hex mask;
	// all-zero means every capability was dropped.
	spec := allocFor(t, "sh", "-c", "grep -E '^(CapEff|NoNewPrivs)' /proc/self/status")
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })
	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := d.Wait(waitCtx, spec.Project, spec.ID); err != nil {
		t.Fatalf("wait: %v", err)
	}

	out := readLog(t, spec.LogPath)
	if !strings.Contains(out, "CapEff:\t0000000000000000") {
		t.Errorf("effective capabilities are not empty:\n%s", out)
	}
	if !strings.Contains(out, "NoNewPrivs:\t1") {
		t.Errorf("NoNewPrivs is not set:\n%s", out)
	}
}

func TestIntegrationMemoryLimitReachesTheCgroup(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	spec := allocFor(t, "sh", "-c", "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max")
	spec.CgroupPath = CgroupPath(WorkloadSlice, spec.ID)
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })
	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := d.Wait(waitCtx, spec.Project, spec.ID); err != nil {
		t.Fatalf("wait: %v", err)
	}

	out := readLog(t, spec.LogPath)
	wantMem := fmt.Sprintf("%d", 128<<20)
	if !strings.Contains(out, wantMem) {
		t.Errorf("memory.max does not show the limit %s:\n%s", wantMem, out)
	}
	if !strings.Contains(out, "64") {
		t.Errorf("pids.max does not show the limit 64:\n%s", out)
	}
}

func TestIntegrationLogsAreCaptured(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	spec := allocFor(t, "sh", "-c", "echo to-stdout; echo to-stderr >&2")
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })
	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := d.Wait(waitCtx, spec.Project, spec.ID); err != nil {
		t.Fatalf("wait: %v", err)
	}

	out := readLog(t, spec.LogPath)
	for _, want := range []string{"to-stdout", "to-stderr"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}

func TestIntegrationNetnsJoinedByTheTask(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	spec := allocFor(t, "sh", "-c", "ip link show lo")
	netns, err := CreateNetns(spec.ID)
	if err != nil {
		t.Fatalf("create netns: %v", err)
	}
	t.Cleanup(func() { _ = DeleteNetns(spec.ID) })
	spec.NetnsPath = netns

	if !NetnsExists(spec.ID) {
		t.Fatal("netns reported missing right after creation")
	}
	// Idempotent: a retrying reconciler must not tear down a live network.
	if _, err := CreateNetns(spec.ID); err != nil {
		t.Errorf("second CreateNetns: %v", err)
	}

	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })
	if err := d.Start(ctx, spec.Project, spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := d.Wait(waitCtx, spec.Project, spec.ID); err != nil {
		t.Fatalf("wait: %v", err)
	}

	// lo is up because CreateNetns brought it up — CNI plugins do not.
	out := readLog(t, spec.LogPath)
	if !strings.Contains(out, "lo:") || !strings.Contains(out, "UP") {
		t.Errorf("loopback is not up inside the joined netns:\n%s", out)
	}

	if err := DeleteNetns(spec.ID); err != nil {
		t.Fatalf("delete netns: %v", err)
	}
	if NetnsExists(spec.ID) {
		t.Error("netns still present after delete")
	}
}

func TestIntegrationCreateRejectsDuplicateID(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)
	mustPull(t, d)

	spec := allocFor(t, "sleep", "60")
	if err := d.Create(ctx, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), spec.Project, spec.ID) })

	if err := d.Create(ctx, spec); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("second create: err = %v, want ErrAlreadyExists", err)
	}
}

func TestIntegrationEnsureImageIsIdempotentAndReturnsADigest(t *testing.T) {
	ctx := context.Background()
	d := newDriver(t)

	digest, err := d.EnsureImage(ctx, testProject, testImage)
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, want a sha256 reference for deploy pinning", digest)
	}

	again, err := d.EnsureImage(ctx, testProject, testImage)
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if again != digest {
		t.Errorf("digest changed between calls: %q then %q", digest, again)
	}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	// The shim writes the log file; give it a moment to flush after exit.
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, err := os.ReadFile(path)
		if err == nil && len(b) > 0 {
			return string(b)
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("read log %s: %v", path, err)
			}
			return ""
		}
		time.Sleep(50 * time.Millisecond)
	}
}
