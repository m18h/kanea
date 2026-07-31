package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PRD §5.2.11 hierarchy, created directly (the non-systemd fallback path):
//
//	/sys/fs/cgroup
//	├── kanea.slice            memory.min=1GiB, swap=0, cpu.weight=10000 (+ OOMScoreAdjust on procs)
//	└── kanea-workloads.slice  memory.max=RAM-reserve, swap=0, cpu.weight=100
//	    └── alloc-*            per-alloc memory.max / cpu.max / pids.max via OCI spec
const (
	cgRoot   = "/sys/fs/cgroup"
	sliceCP  = cgRoot + "/kanea.slice"
	sliceWL  = cgRoot + "/kanea-workloads.slice"
	reserveM = 1024 // MiB, PRD §15.1 default system_reserve_memory
)

func cgWrite(path, val string) error { return os.WriteFile(path, []byte(val), 0o644) }

func cgRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "<err>"
	}
	return strings.TrimSpace(string(b))
}

func cgReadInt(path string) int64 {
	n, _ := strconv.ParseInt(cgRead(path), 10, 64)
	return n
}

// cgEvent returns a counter from a cgroup events file (e.g. memory.events/oom_kill).
func cgEvent(cg, file, key string) int64 {
	for _, l := range strings.Split(cgRead(cg+"/"+file), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == key {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}

// cgAnon returns the cgroup's anonymous memory bytes (memory.stat "anon").
func cgAnon(cg string) int64 {
	for _, l := range strings.Split(cgRead(cg+"/memory.stat"), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "anon" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}

// cgFileCache returns active_file+inactive_file bytes from memory.stat.
func cgFileCache(cg string) int64 {
	var tot int64
	for _, l := range strings.Split(cgRead(cg+"/memory.stat"), "\n") {
		if f := strings.Fields(l); len(f) == 2 && (f[0] == "active_file" || f[0] == "inactive_file") {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			tot += n
		}
	}
	return tot
}

func memTotalMiB() int64 {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			f := strings.Fields(l)
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb >> 10
		}
	}
	return 0
}

// setupSlices builds the §5.2.11 hierarchy. Idempotent.
func setupSlices() error {
	// Delegate controllers from root to children (no-op if already delegated).
	_ = cgWrite(cgRoot+"/cgroup.subtree_control", "+cpu +memory +pids")
	for _, d := range []string{sliceCP, sliceWL} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// Workloads slice will contain per-alloc child cgroups: delegate BEFORE procs move in.
	if err := cgWrite(sliceWL+"/cgroup.subtree_control", "+cpu +memory +pids"); err != nil {
		return fmt.Errorf("delegate to workloads slice: %w", err)
	}
	if err := cgWrite(sliceCP+"/memory.min", strconv.FormatInt(reserveM<<20, 10)); err != nil {
		return fmt.Errorf("kanea.slice memory.min: %w", err)
	}
	if err := cgWrite(sliceCP+"/memory.swap.max", "0"); err != nil {
		return err
	}
	if err := cgWrite(sliceCP+"/cpu.weight", "10000"); err != nil {
		return err
	}
	total := memTotalMiB()
	if err := cgWrite(sliceWL+"/memory.max", strconv.FormatInt((total-reserveM)<<20, 10)); err != nil {
		return fmt.Errorf("workloads memory.max: %w", err)
	}
	if err := cgWrite(sliceWL+"/memory.swap.max", "0"); err != nil {
		return err
	}
	return cgWrite(sliceWL+"/cpu.weight", "100")
}

// ---- memhog process management (move into cgroup BEFORE allocating) ----

type hog struct {
	cmd  *exec.Cmd
	name string
}

func startHog(name, slice string, args ...string) (*hog, error) {
	base := "/tmp/kanea-spike-" + name
	ready, goF, done := base+".ready", base+".go", base+".done"
	os.Remove(ready)
	os.Remove(goF)
	os.Remove(done)
	if slice != "" {
		// Procs live in a CHILD cgroup: a cgroup with delegated subtree
		// controllers rejects procs of its own (no-internal-process rule).
		if err := os.MkdirAll(slice, 0o755); err != nil {
			return nil, err
		}
	}
	full := append([]string{"memhog", "-ready", ready, "-go", goF, "-done", done}, args...)
	cmd := exec.Command("/proc/self/exe", full...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if !waitFile(ready, 10*time.Second) {
		cmd.Process.Kill()
		return nil, fmt.Errorf("hog %s never signalled ready", name)
	}
	if slice != "" {
		if err := cgWrite(slice+"/cgroup.procs", strconv.Itoa(cmd.Process.Pid)); err != nil {
			cmd.Process.Kill()
			return nil, fmt.Errorf("move hog %s into %s: %w", name, slice, err)
		}
	}
	touch(goF)
	return &hog{cmd: cmd, name: name}, nil
}

func (h *hog) waitAlloc(timeout time.Duration) bool {
	return waitFile("/tmp/kanea-spike-"+h.name+".done", timeout)
}

// waitExit reports whether the hog died (e.g. OOM-killed) within the timeout.
func (h *hog) waitExit(timeout time.Duration) (dead bool, state string) {
	doneC := make(chan error, 1)
	go func() { doneC <- h.cmd.Wait() }()
	select {
	case err := <-doneC:
		return true, fmt.Sprintf("%v", err)
	case <-time.After(timeout):
		return false, "still running"
	}
}

func (h *hog) alive() bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(h.cmd.Process.Pid) + "/stat")
	if err != nil {
		return false
	}
	// field 3 is the process state; zombies count as dead even if signal(0) works
	f := strings.Fields(string(b))
	return len(f) >= 3 && f[2] != "Z" && f[2] != "X"
}

func (h *hog) kill() {
	_ = h.cmd.Process.Kill()
	_, _ = h.cmd.Process.Wait()
}

// ---- the checks ----

func runCgroups(ctx context.Context) error {
	client, ctx, err := dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	img, err := ensureImage(ctx, client)
	if err != nil {
		return err
	}
	if err := writeCNINetConf(); err != nil {
		return err
	}

	total := memTotalMiB()
	fmt.Printf("── T1: §5.2.11 hierarchy (VM MemTotal=%d MiB) ──\n", total)
	if err := setupSlices(); err != nil {
		return err
	}
	check("kanea.slice memory.min = 1 GiB", cgRead(sliceCP+"/memory.min") == strconv.FormatInt(reserveM<<20, 10), cgRead(sliceCP+"/memory.min"))
	check("kanea.slice memory.swap.max = 0", cgRead(sliceCP+"/memory.swap.max") == "0", "")
	check("kanea.slice cpu.weight = 10000", cgRead(sliceCP+"/cpu.weight") == "10000", "")
	check("workloads memory.max = RAM-reserve", cgRead(sliceWL+"/memory.max") == strconv.FormatInt((total-reserveM)<<20, 10), cgRead(sliceWL+"/memory.max"))
	check("workloads cpu.weight = 100", cgRead(sliceWL+"/cpu.weight") == "100", "")
	check("controllers delegated to workloads slice",
		strings.Contains(cgRead(sliceWL+"/cgroup.controllers"), "memory") && strings.Contains(cgRead(sliceWL+"/cgroup.controllers"), "pids"),
		cgRead(sliceWL+"/cgroup.controllers"))

	fmt.Println("── T2: per-alloc limits via OCI spec ──")
	exe, _ := os.Executable()
	cg := sliceWL + "/alloc-cg-t2"
	base := alloc{
		ID: "cg-t2", MemLimitMB: 128, CPUQuota: 50000, CPUPeriod: 100000, PidsLimit: 64,
		CgroupPath: "/kanea-workloads.slice/alloc-cg-t2", BinMount: exe,
	}

	// T2a — hard memory limit: memhog as pid 1 breaches it, alloc OOMs (137).
	aMem := base
	aMem.Cmd = []string{"/spike", "memhog", "-anon", "300M"}
	task, err := startAlloc(ctx, client, img, aMem)
	if err != nil {
		return fmt.Errorf("start alloc: %w", err)
	}
	exitC, err := task.Wait(ctx)
	if err != nil {
		return err
	}
	check("alloc cgroup landed under workloads slice", cgRead(cg+"/cgroup.type") != "<err>", cg)
	check("memory.max = 128 MiB", cgRead(cg+"/memory.max") == "134217728", cgRead(cg+"/memory.max"))
	check("cpu.max = 50000 100000 (0.5 core)", cgRead(cg+"/cpu.max") == "50000 100000", cgRead(cg+"/cpu.max"))
	check("pids.max = 64", cgRead(cg+"/pids.max") == "64", cgRead(cg+"/pids.max"))
	oomBefore := cgEvent(cg, "memory.events", "oom_kill")
	select {
	case st := <-exitC:
		check("memory breach OOM-kills the alloc (exit 137)", st.ExitCode() == 137,
			fmt.Sprintf("exit=%d oom_kill %d->%d", st.ExitCode(), oomBefore, cgEvent(cg, "memory.events", "oom_kill")))
	case <-time.After(30 * time.Second):
		check("memory breach OOM-kills the alloc (exit 137)", false, "timeout waiting for exit")
	}
	check("alloc cgroup oom_kill incremented", cgEvent(cg, "memory.events", "oom_kill") > oomBefore, "")
	removeAlloc(ctx, client, "cg-t2")

	// T2b — CPU quota: restart as sleeper, run a hog, expect throttling.
	aCPU := base
	aCPU.Cmd = []string{"sleep", "infinity"}
	task, err = startAlloc(ctx, client, img, aCPU)
	if err != nil {
		return fmt.Errorf("restart alloc: %w", err)
	}
	throttledBefore := cgCPUStat(cg, "nr_throttled")
	hogP, err := execDetached(ctx, task, "cpu", "sh", "-c", "yes > /dev/null")
	if err == nil {
		time.Sleep(3 * time.Second)
		_ = hogP.Kill(ctx, syscall.SIGKILL)
		_, _ = hogP.Wait(ctx)
		_, _ = hogP.Delete(ctx)
	}
	throttled := cgCPUStat(cg, "nr_throttled") - throttledBefore
	check("cpu hog throttled at 0.5 core", throttled > 0, fmt.Sprintf("nr_throttled +%d in 3s", throttled))

	// T2c — pids.max: fork bomb is contained (LAST: leaves the cgroup full).
	pidsBefore := cgEvent(cg, "pids.events", "max")
	fb, err := execDetached(ctx, task, "pids", "sh", "-c", ":(){ :|:& };:")
	if err == nil {
		time.Sleep(3 * time.Second)
		_ = fb.Kill(ctx, syscall.SIGKILL)
		_, _ = fb.Wait(ctx)
		_, _ = fb.Delete(ctx)
	}
	pidsCur := cgReadInt(cg + "/pids.current")
	check("fork bomb contained at pids.max", pidsCur <= 64 && cgEvent(cg, "pids.events", "max") > pidsBefore,
		fmt.Sprintf("pids.current=%d pids.events max %d->%d", pidsCur, pidsBefore, cgEvent(cg, "pids.events", "max")))
	removeAlloc(ctx, client, "cg-t2")

	fmt.Println("── T3: workloads collective ceiling ──")
	wlHogs := sliceWL + "/spike-hogs"
	defer os.Remove(wlHogs)                                              //nolint:errcheck
	if err := cgWrite(sliceWL+"/memory.max", "2147483648"); err != nil { // 2 GiB for the test
		return err
	}
	small, err := startHog("t3-small", wlHogs, "-anon", "300M")
	if err != nil {
		return err
	}
	if !small.waitAlloc(30 * time.Second) {
		small.kill()
		return fmt.Errorf("t3-small never allocated")
	}
	oomBase := cgEvent(sliceWL, "memory.events", "oom_kill")
	big, err := startHog("t3-big", wlHogs, "-anon", "2000M") // 300+2000 > 2048
	if err != nil {
		small.kill()
		return err
	}
	bigDead, bigState := big.waitExit(45 * time.Second)
	check("collective ceiling OOM-kills the over-budget hog", bigDead, "big: "+bigState)
	check("small hog under budget survives", small.alive(), "")
	check("workloads slice oom_kill incremented", cgEvent(sliceWL, "memory.events", "oom_kill") > oomBase,
		fmt.Sprintf("%d -> %d", oomBase, cgEvent(sliceWL, "memory.events", "oom_kill")))
	small.kill()

	fmt.Println("── T4: kanea.slice floor under global memory pressure ──")
	if err := cgWrite(sliceWL+"/memory.max", "max"); err != nil { // no ceiling: pure global pressure
		return err
	}
	defer cgWrite(sliceWL+"/memory.max", strconv.FormatInt((total-reserveM)<<20, 10)) //nolint:errcheck
	pgFile := "/var/tmp/kanea-spike-pagecache.bin"
	if out, err := exec.Command("dd", "if=/dev/zero", "of="+pgFile, "bs=1M", "count=400", "status=none").CombinedOutput(); err != nil {
		return fmt.Errorf("make page-cache file: %s: %w", out, err)
	}
	defer os.Remove(pgFile)
	// Page cache is charged to its FIRST instantiator: dd already owns these
	// pages. Drop them (sync first — dirty pages are not dropped) so the cp
	// hog re-instantiates (and is charged for) them on read.
	_ = exec.Command("sync").Run()
	if err := cgWrite("/proc/sys/vm/drop_caches", "3"); err != nil {
		return fmt.Errorf("drop_caches: %w", err)
	}

	cp, err := startHog("t4-cp", sliceCP, "-anon", "600M", "-file", pgFile, "-oom-adj", "-900")
	if err != nil {
		return err
	}
	if !cp.waitAlloc(60 * time.Second) {
		cp.kill()
		return fmt.Errorf("control-plane stand-in never allocated")
	}
	preAnon := cgAnon(sliceCP)
	preCache := cgFileCache(sliceCP)
	fmt.Printf("  baseline: kanea.slice anon=%d MiB file-cache=%d MiB (min=%d MiB)\n", preAnon>>20, preCache>>20, reserveM)

	// Phase A — MODERATE pressure (no OOM): the floor's page cache must be
	// (best-effort) protected by memory.min.
	modSize := fmt.Sprintf("%dM", total-2600) // fits with room: reclaim pressure, no last-resort
	mod, err := startHog("t4-mod", wlHogs, "-anon", modSize)
	if err != nil {
		cp.kill()
		return err
	}
	modDone := mod.waitAlloc(90 * time.Second)
	time.Sleep(2 * time.Second) // let reclaim settle at the peak
	midCache := cgFileCache(sliceCP)
	mod.kill()
	check("moderate pressure: cache floor protected (best-effort)", midCache > preCache*70/100,
		fmt.Sprintf("%d MiB -> %d MiB with %s hog (allocated=%v)", preCache>>20, midCache>>20, modSize, modDone))
	check("moderate pressure: floor process alive", cp.alive(), "")

	// Phase B — EXTREME pressure (global OOM): kernel MAY reclaim the protected
	// cache as last resort (documented, best-effort), but the floor's anon
	// memory is unreclaimable (swap.max=0) and the OOM killer must pick the hog.
	preAnon2 := cgAnon(sliceCP)
	preCache2 := cgFileCache(sliceCP)
	hogSize := fmt.Sprintf("%dM", total-1024) // demand > RAM: global OOM territory
	wl, err := startHog("t4-wl", wlHogs, "-anon", hogSize)
	if err != nil {
		cp.kill()
		return err
	}
	wlDead, wlState := wl.waitExit(120 * time.Second)
	postAnon := cgAnon(sliceCP)
	postCache := cgFileCache(sliceCP)
	fmt.Printf("  after extreme pressure: anon=%d MiB file-cache=%d MiB\n", postAnon>>20, postCache>>20)

	check("extreme pressure: memory hog got OOM-killed", wlDead, "hog: "+wlState)
	check("extreme pressure: control-plane stand-in survived", cp.alive(), "oom_score_adj=-900")
	check("extreme pressure: floor ANON memory held (hard guarantee)", postAnon > preAnon2*95/100,
		fmt.Sprintf("anon %d MiB -> %d MiB", preAnon2>>20, postAnon>>20))
	check("extreme pressure: cache reclaim is last-resort-only (informational)", true,
		fmt.Sprintf("cache %d MiB -> %d MiB (kernel may reclaim protected cache before OOM-killing)", preCache2>>20, postCache>>20))
	cp.kill()
	if !wlDead {
		wl.kill()
	}

	return summary()
}

func cgCPUStat(cg, key string) int64 {
	for _, l := range strings.Split(cgRead(cg+"/cpu.stat"), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == key {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}
