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
	ciliumSocket     string
	// networkMode is "cilium" or "none"; the Cilium checks are skipped for the
	// latter, which is a supported single-node configuration.
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
		checkCNIPlugins(opts.layout),
		checkSubnets(opts.layout, opts.serviceCIDR),
	}
	if opts.networkMode != "none" {
		results = append(results,
			checkSocket("cilium-agent", opts.ciliumSocket,
				"systemctl status kanea-cilium — or run kanead with --network none"),
			checkEtcd(),
		)
	}
	if opts.buildkitSocket != "off" {
		results = append(results, checkBuildkit(opts.buildkitSocket, opts.layout))
	}
	results = append(results, checkFUSE())
	if !opts.offline {
		results = append(results, checkUpstreamReachable())
	}
	return results
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

// checkCNIPlugins verifies the plugin binary and the conflist.
//
// Both are checked because they fail differently and at the worst moment: a
// missing conflist surfaces per-alloc as a read error at deploy time, not at
// startup, since internal/network loads it lazily on every call.
func checkCNIPlugins(layout provision.Layout) checkResult {
	plugin := filepath.Join(layout.CNIBinDir(), "cilium-cni")
	if _, err := os.Stat(plugin); err != nil {
		return fail("cni", plugin+" is not present",
			"run `kanea install --only cilium` — containerd execs this on every alloc")
	}
	conflist := filepath.Join(layout.ConfDir, "cni", "net.d", "05-cilium.conflist")
	if _, err := os.Stat(conflist); err != nil {
		return fail("cni", conflist+" is not present",
			"run `kanea install` — without it every deploy fails at network attach, not at startup")
	}
	return pass("cni", "cilium-cni and its conflist are in place")
}

// checkEtcd verifies Cilium's kvstore answers.
//
// Derived state (§18 rule 9), so this is not about data — it is that a Cilium
// agent with no kvstore allocates no identities, and an endpoint with no
// identity is policy-denied in both directions.
func checkEtcd() checkResult {
	conn, err := net.DialTimeout("tcp", provision.EtcdEndpoint, 2*time.Second)
	if err != nil {
		return fail("etcd", provision.EtcdEndpoint+" refuses connections",
			"systemctl status kanea-etcd — Cilium allocates no identities without it")
	}
	if err := conn.Close(); err != nil {
		return warn("etcd", "answered but the connection would not close", "")
	}
	return pass("etcd", provision.EtcdEndpoint)
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
// Not a warning. containerd, cgroups v2, netns and Cilium are Linux, and a
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

// minKernel is the oldest kernel Kanea is tested against. Cilium's eBPF
// dataplane needs considerably newer than the distribution minimum, and a node
// below this fails in ways that look like Kanea bugs.
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
