package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/provision"
	"github.com/m18h/kanea/internal/reconciler"
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
	// networkMode is "ebpf" or "netns"; the BPF checks are skipped for the
	// latter, which is the development configuration.
	networkMode string
	// buildkitSocket is the rootless build daemon's address; "off" skips it.
	buildkitSocket string
	// layout locates the components `kanea install` placed.
	layout provision.Layout
	// offline suppresses the one check that touches the network.
	offline bool
	// serviceCIDR is the pool kanead allocates service frontends from. Held
	// here only so the subnet overlap can be checked: reconciler and provision
	// never meet anywhere else, which is why nothing checked this before.
	serviceCIDR string
	// serviceCIDR6 is the v6 twin pool (PRD v1.41); empty means v4-only.
	serviceCIDR6 string
}

// The check set is split in two, and the split is the point.
//
// Platform checks are things no installer can supply: a kernel, cgroups v2, a
// clock. They gate `kanea init` before anything is downloaded, because an
// install that proceeds past them produces a node that looks configured and is
// not — the reason init.go refuses rather than warns.
//
// Component checks are things `kanea install` establishes. Since v1.30 they
// run *after* the install rather than before it, so they verify rather than
// admit. Running them first would fail every fresh node on the absence of
// exactly the software this command exists to place.

// platformChecks are the preconditions Kanea cannot install its way out of.
func platformChecks(opts preflightOptions) []checkResult {
	return []checkResult{
		checkPlatform(),
		checkCgroupV2(),
		checkKernel(),
		checkClock(),
		checkSystemd(),
		checkDataDir(opts.dataDir),
	}
}

// componentChecks verify what `kanea install` placed.
func componentChecks(opts preflightOptions) []checkResult {
	results := []checkResult{
		checkSocket("containerd", opts.containerdSocket,
			"run `kanea install` — Kanea installs and supervises its own containerd "+
				"(PRD §5.2.12); or point --containerd at an existing one"),
		checkVersionMatrix(opts.layout),
		checkSubnets(opts.layout, opts.serviceCIDR),
	}
	if opts.layout.NodeCIDR6 != "" || opts.serviceCIDR6 != "" {
		results = append(results, checkSubnets6(opts.layout, opts.serviceCIDR6), checkKernelIPv6())
	}
	if opts.networkMode != networkNetns {
		results = append(results, checkBPF())
		results = append(results, networkEgressChecks()...)
	}
	if opts.buildkitSocket != "off" {
		results = append(results, checkBuildkit(opts.buildkitSocket, opts.layout))
	}
	results = append(results, checkFUSE(), checkWasmShim(opts.layout))
	if !opts.offline {
		results = append(results, checkUpstreamReachable())
	}
	return results
}

// checkWasmShim verifies the functions runtime is reachable (PRD v1.39,
// §5.2.12, §6.2 R25). Always a warning, never a failure: a node running no
// functions is a supported node, and this check exists so the first wasm alloc
// fails here — in front of an operator — rather than at task create.
func checkWasmShim(layout provision.Layout) checkResult {
	const shim = "containerd-shim-wasmtime-v1"
	if layout.ContainerdSocket == "" {
		// Kanea's containerd: the unit puts BinDir on containerd's PATH, so
		// presence in BinDir is resolvability. Drift is the matrix's job.
		if _, err := os.Stat(filepath.Join(layout.BinDir(), shim)); err != nil {
			return warn("wasm shim", shim+" is not installed",
				"functions (PRD §6.2 R25) need it; run `kanea install --only wasmtime-shim`")
		}
		return pass("wasm shim", shim+" installed")
	}
	// An adopted containerd resolves shims on its own PATH, which Kanea does
	// not control and must not edit — a missing shim there is a finding, not
	// something to fix in a unit Kanea did not write (§5.2.11).
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if _, err := os.Stat(filepath.Join(dir, shim)); err == nil {
			return pass("wasm shim", shim+" resolvable at "+dir)
		}
	}
	return warn("wasm shim", shim+" is not on the adopted containerd's likely PATH",
		"functions need "+shim+" resolvable by the containerd at "+layout.ContainerdSocket+
			"; place it on that daemon's PATH (Kanea does not edit a unit it did not write)")
}

// checkUpstreamReachable reports whether component artefacts can be fetched.
//
// The one check here that touches the network, and the reason `--offline`
// exists rather than being decoration. It answers a question an operator
// genuinely has before an upgrade — "can this node fetch components, or do I
// need to carry a bundle in?" — and it is a warning, because a node that
// cannot reach GitHub is a supported node, not a broken one.
func checkUpstreamReachable() checkResult {
	manifest, err := provision.Load()
	if err != nil {
		return fail("upstream", err.Error(), "this is a broken build")
	}
	var probe *provision.Component
	for _, c := range manifest.All() {
		if c.Kind != provision.KindImage {
			probe = c
			break
		}
	}
	if probe == nil {
		return warn("upstream", "no artefact component to probe", "")
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probe.ArtefactURL(provision.HostArch()), nil)
	if err != nil {
		return warn("upstream", err.Error(), "")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return warn("upstream", "component artefacts are not reachable",
			"upgrades on this node need `kanea bundle create` elsewhere and "+
				"`kanea install --bundle` here; pass --offline to skip this check")
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // cleanup path
	if resp.StatusCode >= 400 {
		return warn("upstream", "reachable but returned "+resp.Status, "")
	}
	return pass("upstream", "component artefacts are reachable")
}

// upstreamProbeTimeout is short on purpose: this is a convenience check, and a
// `doctor` that takes thirty seconds on a firewalled node is one people stop
// running.
const upstreamProbeTimeout = 5 * time.Second

// preflight runs every check, in a fixed order.
func preflight(opts preflightOptions) []checkResult {
	return append(platformChecks(opts), componentChecks(opts)...)
}

// checkSystemd reports whether systemd is running this machine.
//
// A warning rather than a failure: §5.2.11 has always said kanead builds the
// cgroup hierarchy itself on a non-systemd host. What changes with v1.30 is
// that the component units cannot be written either, so the operator has more
// to do by hand and should hear it once rather than discover it four commands
// later.
func checkSystemd() checkResult {
	if goruntime.GOOS != "linux" {
		return warn("systemd", "not checked on "+goruntime.GOOS, "")
	}
	if provision.SystemdAvailable() {
		return pass("systemd", "running")
	}
	return warn("systemd", "not running this machine",
		"`kanea install` will place binaries but write no units, and the component "+
			"daemons are yours to supervise (PRD §5.2.11)")
}

// checkVersionMatrix enforces PRD §15.4 and §22 R1.
//
// The manifest is the matrix, so this is a comparison against the same table
// the installer used rather than a second list to keep in step. A component
// installed at a version this build does not pin is a finding: the flag sets
// in §5.2.5 and the file interfaces M0 found are version-specific, and a
// mismatch is how a node develops behaviour nobody can reproduce.
func checkVersionMatrix(layout provision.Layout) checkResult {
	manifest, err := provision.Load()
	if err != nil {
		return fail("version matrix", err.Error(), "this is a broken build")
	}
	installer := &provision.Installer{Layout: layout}

	var missing, drifted []string
	for _, c := range manifest.All() {
		installed, _, ok := installer.Installed(c.Name)
		if !ok {
			missing = append(missing, c.Name)
			continue
		}
		if installed != c.Version {
			drifted = append(drifted, fmt.Sprintf("%s %s (pinned %s)", c.Name, installed, c.Version))
		}
	}
	switch {
	case len(drifted) > 0:
		return fail("version matrix", strings.Join(drifted, ", "),
			"run `kanea install --force` to bring them to the pinned versions")
	case len(missing) == len(manifest.All()):
		return warn("version matrix", "no components have been installed by Kanea",
			"run `kanea install`, or ignore this if you supply them yourself")
	case len(missing) > 0:
		return warn("version matrix", "not installed by Kanea: "+strings.Join(missing, ", "),
			"run `kanea install` to place them, or supply them yourself")
	default:
		return pass("version matrix", fmt.Sprintf("%d components at their pinned versions", len(manifest.All())))
	}
}

// checkSubnets checks the container subnet against the service pool.
//
// Nothing checked this before because internal/reconciler and
// internal/provision never meet: the shipped defaults happen not to collide, so
// the gap was invisible until an operator moved one of them. An overlap gives
// a service frontend an address that is also a pod address, and the symptom is
// traffic that reaches the wrong place intermittently.
func checkSubnets(layout provision.Layout, serviceCIDR string) checkResult {
	const name = "container subnet"
	if err := layout.ValidateNetworking(); err != nil {
		return checkResult{Name: name, Detail: err.Error(),
			Fix: "pass --node-cidr and --cluster-cidr to `kanea install`"}
	}
	node, cluster := layout.Networking()
	if serviceCIDR == "" {
		serviceCIDR = reconciler.DefaultServiceCIDR
	}
	services, err := netip.ParsePrefix(serviceCIDR)
	if err != nil {
		return checkResult{Name: name,
			Detail: fmt.Sprintf("--service-cidr %q is not a CIDR", serviceCIDR),
			Fix:    "pass a CIDR to kanead's --service-cidr"}
	}
	for _, c := range []struct{ flag, value string }{
		{"--node-cidr", node}, {"--cluster-cidr", cluster},
	} {
		prefix, err := netip.ParsePrefix(c.value)
		if err != nil {
			continue // ValidateNetworking already reported it
		}
		if prefix.Overlaps(services) {
			return checkResult{
				Name: name,
				Detail: fmt.Sprintf("%s %s overlaps --service-cidr %s; a service frontend would be "+
					"handed an address that is also a container address", c.flag, c.value, serviceCIDR),
				Fix: "move one of them: --node-cidr/--cluster-cidr at install, --service-cidr on kanead",
			}
		}
	}
	return checkResult{Name: name, OK: true,
		Detail: node + " in " + cluster + ", services " + serviceCIDR}
}

// checkBuildkit verifies the build daemon, which §5.2.11 has always said
// `doctor` does and which it has never done.
func checkBuildkit(socket string, layout provision.Layout) checkResult {
	if _, err := os.Stat(filepath.Join(layout.BinDir(), "buildctl")); err != nil {
		return warn("buildkit", "buildctl is not installed",
			"run `kanea install --only buildkit`, or run kanead with --buildkit off")
	}
	path := strings.TrimPrefix(socket, "unix://")
	if _, err := os.Stat(path); err != nil {
		return warn("buildkit", path+" is not present",
			"systemctl status kanea-buildkit — builds and GitOps will fail until it answers")
	}
	return pass("buildkit", path)
}

// checkFUSE verifies what S3 volumes need (§8).
//
// A warning, not a failure: a node that never mounts an S3 volume is fine
// without it. But it is checked, because the failure it prevents arrives at a
// deploy as an error about a mount option rather than about a config file.
func checkFUSE() checkResult {
	if goruntime.GOOS != "linux" {
		return warn("fuse", "not checked on "+goruntime.GOOS, "")
	}
	raw, err := os.ReadFile(provision.FuseConfPath) // #nosec G304 — a package constant
	if err != nil {
		return warn("fuse", provision.FuseConfPath+" is not present",
			"S3 volumes need user_allow_other there; `kanea install` writes it")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "user_allow_other" {
			return pass("fuse", "user_allow_other is set")
		}
	}
	return warn("fuse", "user_allow_other is not set in "+provision.FuseConfPath,
		"every S3 volume will fail to mount; run `kanea install`")
}

// checkPlatform refuses a host Kanea cannot run workloads on.
//
// Not a warning. containerd, cgroups v2, netns and eBPF are Linux, and a
// macOS or Windows host is a development machine — where the CLI is useful and
// the daemon is not.
func checkPlatform() checkResult {
	if goruntime.GOOS != "linux" {
		return fail("platform", goruntime.GOOS+"/"+goruntime.GOARCH,
			"kanead runs workloads on Linux; the CLI works anywhere")
	}
	return pass("platform", goruntime.GOOS+"/"+goruntime.GOARCH)
}

// checkCgroupV2 verifies the unified hierarchy.
//
// Constraint #11 rests on it: the control plane's memory floor is cgroups v2
// `memory.min`, and there is no v1 equivalent that gives the same guarantee. A
// node on v1 runs, and the floor that keeps kanead alive under memory pressure
// is simply absent — which is the kind of thing to find out now.
func checkCgroupV2() checkResult {
	if goruntime.GOOS != "linux" {
		return warn("cgroups v2", "not checked on "+goruntime.GOOS, "")
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

// minKernel is the oldest kernel Kanea is tested against. Kanea's own eBPF
// datapath (PRD §5.2.5) needs considerably newer than the distribution
// minimum, and a node below this fails in ways that look like Kanea bugs.
const minKernel = "5.10"

func checkKernel() checkResult {
	if goruntime.GOOS != "linux" {
		return warn("kernel", "not checked on "+goruntime.GOOS, "")
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return warn("kernel", "version unreadable", "")
	}
	version := strings.TrimSpace(string(release))
	if older, err := kernelOlderThan(version, minKernel); err == nil && older {
		return fail("kernel", version,
			"Kanea's eBPF datapath (PRD §5.2.5) needs "+minKernel+" or newer; upgrade the kernel")
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
	if goruntime.GOOS != "linux" {
		return warn("clock", "NTP status not checked on "+goruntime.GOOS, "")
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

// checkSubnets6 is checkSubnets' dual-stack half (PRD v1.41): the courtesy
// pre-check of what parseAgentCIDRs will enforce on kanead's own argv.
func checkSubnets6(layout provision.Layout, serviceCIDR6 string) checkResult {
	const name = "container subnet (v6)"
	if layout.NodeCIDR6 == "" || layout.ClusterCIDR6 == "" || serviceCIDR6 == "" {
		return checkResult{Name: name,
			Detail: "--node-cidr6, --cluster-cidr6 and --service-cidr6 come as a trio: all three or none",
			Fix:    "set the missing *6 flags, or none of them"}
	}
	if err := layout.ValidateNetworking(); err != nil {
		return checkResult{Name: name, Detail: err.Error(),
			Fix: "pass --node-cidr6 and --cluster-cidr6 to `kanea install`"}
	}
	services6, err := netip.ParsePrefix(serviceCIDR6)
	if err != nil || !services6.Addr().Is6() || services6.Addr().Is4In6() {
		return checkResult{Name: name,
			Detail: fmt.Sprintf("--service-cidr6 %q is not an IPv6 CIDR", serviceCIDR6),
			Fix:    "pass an IPv6 prefix to kanead's --service-cidr6"}
	}
	for _, c := range []struct{ flag, value string }{
		{"--node-cidr6", layout.NodeCIDR6}, {"--cluster-cidr6", layout.ClusterCIDR6},
	} {
		prefix, err := netip.ParsePrefix(c.value)
		if err != nil {
			continue // ValidateNetworking already reported it
		}
		if prefix.Overlaps(services6) {
			return checkResult{
				Name: name,
				Detail: fmt.Sprintf("%s %s overlaps --service-cidr6 %s; a service frontend would be "+
					"handed an address that is also a container address", c.flag, c.value, serviceCIDR6),
				Fix: "move one of them",
			}
		}
	}
	detail := layout.NodeCIDR6 + " in " + layout.ClusterCIDR6 + ", services " + serviceCIDR6
	// ULA is the recommendation, not a rule: these are internal-only
	// addresses, and GUA would imply a routability nobody provides.
	for _, v := range []string{layout.NodeCIDR6, layout.ClusterCIDR6, serviceCIDR6} {
		if p, err := netip.ParsePrefix(v); err == nil && !isULA(p.Addr()) {
			return checkResult{Name: name, OK: true, Warn: true,
				Detail: detail,
				Fix:    v + " is not ULA (fd00::/8); internal-only addressing is what these ranges carry"}
		}
	}
	return checkResult{Name: name, OK: true, Detail: detail}
}

// isULA reports whether an address is in fc00::/7 (in practice fd00::/8).
func isULA(a netip.Addr) bool {
	return a.Is6() && !a.Is4In6() && (a.As16()[0]&0xFE) == 0xFC
}

// checkKernelIPv6 verifies the kernel has IPv6 at all when the flags ask for
// it: a kernel booted with ipv6.disable=1 has no /proc/sys/net/ipv6, and the
// datapath's v6 half would fail at the first sysctl instead of here.
func checkKernelIPv6() checkResult {
	const name = "kernel IPv6"
	if goruntime.GOOS != "linux" {
		return checkResult{Name: name, OK: true, Detail: "skipped off linux"}
	}
	if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		return checkResult{Name: name,
			Detail: "/proc/sys/net/ipv6 is missing; the kernel has IPv6 disabled",
			Fix:    "remove ipv6.disable=1 from the kernel command line, or drop the *6 flags"}
	}
	return checkResult{Name: name, OK: true, Detail: "/proc/sys/net/ipv6 present"}
}
