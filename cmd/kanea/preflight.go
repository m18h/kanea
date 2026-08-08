package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Node preflight checks, shared by `kanea init` and `kanea doctor` (PRD §16.2).
//
// One implementation, because two would drift — and they would drift into the
// case where `init` says a node is ready and `doctor` says it is not.

// checkResult is one check's outcome.
type checkResult struct {
	Name string
	// OK is false for a failure. Warn marks something that will work but should
	// not be left alone.
	OK   bool
	Warn bool
	// Detail says what was found; Fix says what to do about it. A check that
	// reports a problem without saying how to fix it is a check that sends
	// someone to a search engine.
	Detail string
	Fix    string
}

func pass(name, detail string) checkResult {
	return checkResult{Name: name, OK: true, Detail: detail}
}

func warn(name, detail, fix string) checkResult {
	return checkResult{Name: name, OK: true, Warn: true, Detail: detail, Fix: fix}
}

func fail(name, detail, fix string) checkResult {
	return checkResult{Name: name, Detail: detail, Fix: fix}
}

// preflightOptions is what the checks need to know about this install.
type preflightOptions struct {
	dataDir          string
	containerdSocket string
	ciliumSocket     string
	// networkMode is "cilium" or "none"; the Cilium checks are skipped for the
	// latter, which is a supported single-node configuration.
	networkMode string
}

// preflight runs every check and returns the results in a fixed order.
func preflight(opts preflightOptions) []checkResult {
	results := []checkResult{
		checkPlatform(),
		checkCgroupV2(),
		checkKernel(),
		checkClock(),
		checkDataDir(opts.dataDir),
		checkSocket("containerd", opts.containerdSocket,
			"install containerd and start it: systemctl enable --now containerd"),
	}
	if opts.networkMode != "none" {
		results = append(results, checkSocket("cilium-agent", opts.ciliumSocket,
			"install cilium-agent ≥ 1.18 (pin 1.19.x) and start it, "+
				"or run kanead with --network none"))
	}
	return results
}

// checkPlatform refuses a host Kanea cannot run workloads on.
//
// Not a warning. containerd, cgroups v2, netns and Cilium are Linux, and a
// macOS or Windows host is a development machine — where the CLI is useful and
// the daemon is not.
func checkPlatform() checkResult {
	if runtime.GOOS != "linux" {
		return fail("platform", runtime.GOOS+"/"+runtime.GOARCH,
			"kanead runs workloads on Linux; the CLI works anywhere")
	}
	return pass("platform", runtime.GOOS+"/"+runtime.GOARCH)
}

// checkCgroupV2 verifies the unified hierarchy.
//
// Constraint #11 rests on it: the control plane's memory floor is cgroups v2
// `memory.min`, and there is no v1 equivalent that gives the same guarantee. A
// node on v1 runs, and the floor that keeps kanead alive under memory pressure
// is simply absent — which is the kind of thing to find out now.
func checkCgroupV2() checkResult {
	if runtime.GOOS != "linux" {
		return warn("cgroups v2", "not checked on "+runtime.GOOS, "")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return fail("cgroups v2", "the unified hierarchy is not mounted",
			"boot with systemd.unified_cgroup_hierarchy=1 (cgroups v1 has no "+
				"equivalent of memory.min, so the control-plane memory floor "+
				"in PRD §5.2.11 cannot be enforced)")
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return warn("cgroups v2", "mounted, but the controller list is unreadable", "")
	}
	for _, want := range []string{"memory", "pids", "cpu"} {
		if !strings.Contains(string(controllers), want) {
			return fail("cgroups v2", "the "+want+" controller is not available",
				"enable it in the root cgroup: "+
					"echo +"+want+" > /sys/fs/cgroup/cgroup.subtree_control")
		}
	}
	return pass("cgroups v2", "unified hierarchy with cpu, memory and pids")
}

// minKernel is the oldest kernel Kanea is tested against. Cilium's eBPF
// dataplane needs considerably newer than the distribution minimum, and a node
// below this fails in ways that look like Kanea bugs.
const minKernel = "5.10"

func checkKernel() checkResult {
	if runtime.GOOS != "linux" {
		return warn("kernel", "not checked on "+runtime.GOOS, "")
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return warn("kernel", "version unreadable", "")
	}
	version := strings.TrimSpace(string(release))
	if older, err := kernelOlderThan(version, minKernel); err == nil && older {
		return fail("kernel", version,
			"Cilium's eBPF dataplane needs "+minKernel+" or newer; upgrade the kernel")
	}
	return pass("kernel", version)
}

// kernelOlderThan compares the leading major.minor of two version strings.
func kernelOlderThan(have, want string) (bool, error) {
	haveMajor, haveMinor, err := majorMinor(have)
	if err != nil {
		return false, err
	}
	wantMajor, wantMinor, err := majorMinor(want)
	if err != nil {
		return false, err
	}
	if haveMajor != wantMajor {
		return haveMajor < wantMajor, nil
	}
	return haveMinor < wantMinor, nil
}

func majorMinor(version string) (int, int, error) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("cannot read a version from %q", version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	// The minor can carry a suffix: "10-generic", "10+".
	minor, err := strconv.Atoi(strings.FieldsFunc(parts[1], func(r rune) bool {
		return r < '0' || r > '9'
	})[0])
	if err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

// checkClock warns about an unsynchronised clock.
//
// It matters more here than it looks. ACME nonces, OIDC token expiry, TOTP,
// SigV4 signatures and the audit log's ordering all depend on the clock being
// roughly right; a node an hour out fails all of them in different, confusing
// ways.
func checkClock() checkResult {
	if runtime.GOOS != "linux" {
		return warn("clock", "NTP status not checked on "+runtime.GOOS, "")
	}
	// /run/systemd/timesync is systemd-timesyncd's marker; chrony and ntpd do
	// not leave one, so its absence is not a failure.
	if _, err := os.Stat("/run/systemd/timesync/synchronized"); err == nil {
		return pass("clock", "synchronised (systemd-timesyncd)")
	}
	for _, candidate := range []string{"/var/lib/chrony", "/var/lib/ntp"} {
		if _, err := os.Stat(candidate); err == nil {
			return pass("clock", "an NTP daemon appears to be installed")
		}
	}
	return warn("clock", "no NTP synchronisation detected",
		"install chrony or enable systemd-timesyncd; ACME, OIDC, SigV4 and the "+
			"audit log all depend on the clock being roughly right")
}

// checkDataDir verifies the state directory is usable and private.
func checkDataDir(path string) checkResult {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return warn("data directory", path+" does not exist yet",
			"`kanea init` creates it, or: install -d -m 0750 "+path)
	}
	if err != nil {
		return fail("data directory", err.Error(), "check permissions on "+path)
	}
	if !info.IsDir() {
		return fail("data directory", path+" is not a directory", "move it aside")
	}
	// The master key and the secrets bucket live here. World-readable is not a
	// warning.
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		return fail("data directory", fmt.Sprintf("%s is mode %04o", path, perm),
			"chmod 0750 "+path+" — it holds the master key and every secret")
	}
	return pass("data directory", path)
}

// checkSocket verifies a unix socket is there and answers.
func checkSocket(name, path, fix string) checkResult {
	if _, err := os.Stat(path); err != nil {
		return fail(name, path+" is not present", fix)
	}
	// Dialled rather than stat'ed alone: a socket file left behind by a crashed
	// daemon looks identical to a live one until something connects.
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return fail(name, path+" exists but refuses connections", fix)
	}
	if err := conn.Close(); err != nil {
		return warn(name, path+" answered but the connection would not close", "")
	}
	return pass(name, path)
}

// renderChecks prints the results and reports whether anything failed.
func renderChecks(o *out, results []checkResult) bool {
	ok := true
	for _, r := range results {
		switch {
		case !r.OK:
			ok = false
			o.printf("  FAIL  %-16s %s\n", r.Name, r.Detail)
		case r.Warn:
			o.printf("  WARN  %-16s %s\n", r.Name, r.Detail)
		default:
			o.printf("  ok    %-16s %s\n", r.Name, r.Detail)
		}
		if r.Fix != "" && (!r.OK || r.Warn) {
			o.printf("        %-16s → %s\n", "", r.Fix)
		}
	}
	return ok
}

// confirm reads a line and reports whether it matches want, exactly.
//
// Exactly, and not a y/n prompt: the one place this is used is the key
// ceremony, where the point is to prove the operator actually recorded the key
// rather than that they can press a button.
func confirm(in *bufio.Reader, want string) (bool, error) {
	line, err := in.ReadString('\n')
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(line) == want, nil
}
