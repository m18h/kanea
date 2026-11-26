package main

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/provision"
)

func TestUnitsCarryTheCgroupGuarantees(t *testing.T) {
	// Constraint #11 is not something Go can arrange for itself: memory.min and
	// OOMScoreAdjust are systemd's to set, and a Kanea installed without these
	// lines runs until the node is under memory pressure and the OOM killer
	// picks the largest process, which is usually kanead.
	dir := t.TempDir()
	o := newOut()
	if err := writeUnits(o, unitOptions{
		dir: dir, reserve: "2G", binary: "/usr/local/bin/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}

	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304; a test path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(body)
	}

	slice := read("kanea.slice")
	if !strings.Contains(slice, "MemoryMin=2G") {
		t.Errorf("the control-plane slice has no memory floor:\n%s", slice)
	}

	service := read("kanead.service")
	for _, want := range []string{
		"OOMScoreAdjust=-900",
		"Slice=kanea.slice",
		"ExecStart=/usr/local/bin/kanea agent",
		// A control-plane restart must not take the workloads with it.
		"KillMode=process",
		// Not Type=notify: nothing in kanead sends sd_notify, and systemd would
		// wait for a readiness message that never arrives and then kill it.
		"Type=exec",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("kanead.service is missing %q:\n%s", want, service)
		}
	}
	// The datapath is kanead's own (PRD v1.36): there is no network unit to
	// order after, and the After=cilium.service this used to carry named a
	// unit that never existed.
	for _, line := range strings.Split(service, "\n") {
		if strings.HasPrefix(line, "After=") && strings.Contains(line, "cilium") {
			t.Errorf("kanead.service orders itself after a network unit (%q); "+
				"the datapath is kanead's own", line)
		}
	}

	// The edge is a separate process from day one (§18 rule 8), and must not
	// wait on the control plane: that separation is the whole reason it exists.
	edge := read("kanea-edge.service")
	for _, line := range strings.Split(edge, "\n") {
		// A directive, not the comment that explains why there isn't one.
		if strings.HasPrefix(line, "After=kanead") || strings.HasPrefix(line, "Requires=kanead") {
			t.Errorf("the edge unit orders itself after kanead (%q); north-south "+
				"traffic would then depend on the control plane being up", line)
		}
	}
	if !strings.Contains(edge, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Error("the edge unit does not grant the one capability it needs")
	}
	if !strings.Contains(edge, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE") {
		t.Error("the edge unit does not drop the capabilities it does not need")
	}
	// The process split is a boundary only if the edge is not root: as uid 0
	// it would match the owner of every root-owned file (the master key, the
	// containerd socket) without needing one capability.
	if !strings.Contains(edge, "User=kanea-edge") || !strings.Contains(edge, "Group=kanea-edge") {
		t.Error("the edge unit does not run as its own user; the §5.2.6 boundary is void without it")
	}
	// The bundle's group is no longer on kanead's argv (it has none, v1.115):
	// `kanea init` writes edge.certs_group into the node config instead, and
	// TestWriteNodeConfigOnAFreshNode pins that it does.
	// Checked as directives rather than as substrings: both units *mention*
	// Type=notify in the comment explaining why they do not use it.
	for _, unit := range []string{service, edge} {
		for _, line := range strings.Split(unit, "\n") {
			if strings.HasPrefix(line, "Type=notify") {
				t.Error("a unit uses Type=notify, but nothing here sends sd_notify; " +
					"systemd would time out waiting and kill the service")
			}
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "kanea-workloads.slice")); err != nil {
		t.Errorf("the workload slice was not written: %v", err)
	}
}

// TestKaneadUnitCreatesNoMountNamespace pins PRD v1.53: kanead is the node's
// mount manager; the netns bind mounts runc joins and the volume mounts
// containerd binds into containers must be made in the host mount namespace.
// Every directive below gives the unit a private mount namespace with slave
// propagation, where a mount kanead makes is invisible to its consumer: runc
// setns()es an empty file (EINVAL on every task create) and a mounted volume
// reads as an empty directory inside the workload; the silent one. Found on
// the first real systemd-managed node to reach task-create.
func TestKaneadUnitCreatesNoMountNamespace(t *testing.T) {
	dir := t.TempDir()
	if err := writeUnits(newOut(), unitOptions{
		dir: dir, reserve: "2G", binary: "/usr/local/bin/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "kanead.service")) // #nosec G304; a test path
	if err != nil {
		t.Fatal(err)
	}

	// Directives that imply a file system namespace (systemd.exec(5)). Checked
	// as line prefixes, not substrings: the unit's own comment names them while
	// explaining why they must not appear.
	mountNS := []string{
		"ProtectSystem=", "ProtectHome=", "PrivateTmp=", "PrivateMounts=",
		"ReadWritePaths=", "ReadOnlyPaths=", "InaccessiblePaths=", "ExecPaths=",
		"NoExecPaths=", "ProtectKernelTunables=", "ProtectKernelModules=",
		"ProtectKernelLogs=", "ProtectControlGroups=", "ProtectProc=",
		"ProcSubset=", "PrivateDevices=", "MountFlags=", "TemporaryFileSystem=",
		"BindPaths=", "BindReadOnlyPaths=", "RootDirectory=", "RootImage=",
		"MountAPIVFS=",
	}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, directive := range mountNS {
			if strings.HasPrefix(trimmed, directive) {
				t.Errorf("kanead.service carries %q, which gives it a private mount "+
					"namespace; its netns and volume mounts would be invisible to "+
					"runc and containerd (PRD v1.53)", trimmed)
			}
		}
	}
	if !strings.Contains(string(body), "NoNewPrivileges=yes") {
		t.Error("kanead.service lost NoNewPrivileges; that one implies no mount namespace and stays")
	}

	// The edge keeps the full sandbox: it mounts nothing and writes nothing,
	// so the reasoning above does not apply to it.
	edge, err := os.ReadFile(filepath.Join(dir, "kanea-edge.service")) // #nosec G304: a test path
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ProtectSystem=strict", "PrivateTmp=yes"} {
		if !strings.Contains(string(edge), want) {
			t.Errorf("kanea-edge.service lost its sandbox directive %q", want)
		}
	}
}

// TestKaneadUnitPutsTheComponentBinDirOnPATH pins the fix for a node whose
// components are installed and healthy and whose builds still fail with
// `exec: "buildctl": executable file not found in $PATH`.
//
// kanead resolves buildctl by name, and systemd's default PATH does not
// include Kanea's bin dir, so the daemon could not find a binary sitting
// right there. Found on a real node; invisible in dev, where the operator's
// own PATH is inherited.
func TestKaneadUnitPutsTheComponentBinDirOnPATH(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		want   string
	}{
		{"default prefix", "", provision.DefaultPrefix + "/bin"},
		{"custom prefix", "/opt/kanea", "/opt/kanea/bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeUnits(newOut(), unitOptions{
				dir: dir, reserve: "256M", binary: "/usr/local/bin/kanea", prefix: tc.prefix,
			}); err != nil {
				t.Fatalf("write units: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "kanead.service")) // #nosec G304; a test path
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			want := "Environment=PATH=" + tc.want + ":"
			if !strings.Contains(string(body), want) {
				t.Errorf("kanead.service does not put %s on PATH; builds would fail:\n%s", tc.want, body)
			}
			// The system directories must survive: kanead also execs mount
			// helpers (mount.cifs, s3fs) and nvidia-smi, which live there.
			for _, sys := range []string{"/usr/bin", "/sbin"} {
				if !strings.Contains(string(body), sys) {
					t.Errorf("PATH dropped %s, which kanead needs for mount helpers:\n%s", sys, body)
				}
			}
		})
	}
}

func TestUnitsHaveNoLeadingTabs(t *testing.T) {
	// The unit bodies are indented Go string literals. systemd tolerates
	// leading whitespace in some places and not others, and a file that is
	// subtly wrong fails at `systemctl daemon-reload` rather than here.
	dir := t.TempDir()
	if err := writeUnits(newOut(), unitOptions{
		dir: dir, reserve: "1G", binary: "/usr/local/bin/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name())) // #nosec G304; a test path
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ") {
				t.Errorf("%s:%d is indented: %q", entry.Name(), i+1, line)
			}
		}
	}
}

// TestUnitsStartTheDaemonsWithNoArguments pins PRD v1.115: the two ExecStart
// lines are the binary and the subcommand, nothing else. Everything a daemon
// is configured with is /etc/kanea/kanea.hcl, which is what makes the units
// files an upgrade may rewrite without losing an operator's decision.
//
// Exact equality, not a substring: the predecessor of this test existed
// because kanea-edge.service once shipped passing a flag its subcommand never
// defined, and restart-looped under Restart=always without serving a request.
// A flag that crept back in would do the same on every node, since both
// daemons now refuse any argument.
func TestUnitsStartTheDaemonsWithNoArguments(t *testing.T) {
	dir := t.TempDir()
	if err := writeUnits(newOut(), unitOptions{
		dir: dir, reserve: "1G", binary: "/usr/local/bin/kanea", prefix: "/opt/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}
	for unit, want := range map[string]string{
		"kanead.service":     "ExecStart=/usr/local/bin/kanea agent",
		"kanea-edge.service": "ExecStart=/usr/local/bin/kanea edge",
	} {
		body, err := os.ReadFile(filepath.Join(dir, unit)) // #nosec G304; a test path
		if err != nil {
			t.Fatalf("read %s: %v", unit, err)
		}
		var got []string
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "ExecStart=") {
				got = append(got, line)
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: ExecStart lines = %q, want exactly %q", unit, got, want)
		}
	}
}

// kanead is the IPAM now (PRD v1.36), so the subnet trio is refused at
// startup rather than presenting as a datapath handing out unroutable
// addresses. `kanea doctor` runs the same shape of check, but only this one
// gates: GitOps and systemd reach kanead without ever passing through doctor.
func TestParseAgentCIDRsRefusesWhatTheDatapathCannotRun(t *testing.T) {
	cases := map[string]struct {
		node, cluster, service    string
		node6, cluster6, service6 string
		ok                        bool
	}{
		"the defaults": {node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16", ok: true},
		"not a CIDR":   {node: "10.244.0.0", cluster: "10.244.0.0/16", service: "172.20.0.0/16"},
		"an IPv6 node": {node: "fd00::/64", cluster: "10.244.0.0/16", service: "172.20.0.0/16"},
		"node outside cluster": {
			node: "10.9.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16"},
		"node wider than cluster": {
			node: "10.0.0.0/8", cluster: "10.244.0.0/16", service: "172.20.0.0/16"},
		"cluster overlaps services": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "10.244.128.0/17"},
		"node overlaps services": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "10.244.0.0/24"},

		// The dual-stack trio (PRD v1.41): all three or none, mirrored rules.
		"a full v6 trio": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16",
			node6: "fd10:244::/64", cluster6: "fd10:244::/56", service6: "fd10:245::/64", ok: true},
		"one v6 flag alone": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16",
			node6: "fd10:244::/64"},
		"two v6 flags": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16",
			node6: "fd10:244::/64", service6: "fd10:245::/64"},
		"a v4 prefix in a *6 flag": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16",
			node6: "10.9.0.0/24", cluster6: "fd10:244::/56", service6: "fd10:245::/64"},
		"node6 outside cluster6": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16",
			node6: "fd99::/64", cluster6: "fd10:244::/56", service6: "fd10:245::/64"},
		"node6 overlaps services6": {
			node: "10.244.0.0/24", cluster: "10.244.0.0/16", service: "172.20.0.0/16",
			node6: "fd10:244::/64", cluster6: "fd10:244::/56", service6: "fd10:244::/64"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseAgentCIDRs(tc.node, tc.cluster, tc.service, tc.node6, tc.cluster6, tc.service6, configLabel)
			if tc.ok && err != nil {
				t.Fatalf("parseAgentCIDRs(%s, %s, %s, %s, %s, %s): %v",
					tc.node, tc.cluster, tc.service, tc.node6, tc.cluster6, tc.service6, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("parseAgentCIDRs accepted a bad set: %+v", tc)
			}
		})
	}
}

func TestKernelComparison(t *testing.T) {
	// The parser has to cope with what /proc/sys/kernel/osrelease actually
	// contains, which is rarely a bare "6.1".
	cases := []struct {
		have  string
		older bool
	}{
		{"6.8.0-generic", false},
		{"5.10.0", false},
		{"5.4.0-190-generic", true},
		{"4.19.0", true},
		{"6.1", false},
	}
	for _, tc := range cases {
		older, err := kernelOlderThan(tc.have, minKernel)
		if err != nil {
			t.Errorf("%s: %v", tc.have, err)
			continue
		}
		if older != tc.older {
			t.Errorf("%s older than %s = %v, want %v", tc.have, minKernel, older, tc.older)
		}
	}
}

func TestKeyCeremoryRefusesWhenTheKeyIsNotTypedBack(t *testing.T) {
	// The whole ceremony rests on this: an operator who cannot type the key
	// back does not have it, and writing it anyway produces exactly the
	// situation the ceremony exists to prevent.
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	reader := bufio.NewReader(strings.NewReader("not the key\n"))
	if err := keyCeremony(newOut(), path, reader); err == nil {
		t.Fatal("the ceremony accepted a wrong confirmation")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a key was written despite the confirmation failing")
	}
}

func TestDashboardURLIsSomethingABrowserCanUse(t *testing.T) {
	// A wildcard bind is not an address anyone can visit, and printing it is
	// how `kanea ui` becomes a command whose output does not work.
	cases := map[string]struct {
		listen string
		secure bool
		want   string
	}{
		"wildcard port only": {":8600", false, "http://localhost:8600"},
		"all interfaces":     {"0.0.0.0:8600", false, "http://localhost:8600"},
		"all v6 interfaces":  {"[::]:8600", true, "https://localhost:8600"},
		"a real address":     {"10.0.0.5:8600", true, "https://10.0.0.5:8600"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := dashboardURL(tc.listen, tc.secure); got != tc.want {
				t.Errorf("dashboardURL(%q, %v) = %q, want %q", tc.listen, tc.secure, got, tc.want)
			}
		})
	}
}

func TestExecArgumentsRequireTheSeparator(t *testing.T) {
	// Without `--`, `kanea exec web ls -la` is ambiguous: -la could be one of
	// kanea's flags. Guessing produces the failure where a flag meant for the
	// remote command is silently eaten here.
	if _, _, err := splitExecArgs([]string{"web", "ls", "-la"}); err == nil {
		t.Error("a command without `--` was accepted")
	} else if !strings.Contains(err.Error(), "--") {
		t.Errorf("the error does not show the fix: %v", err)
	}

	service, command, err := splitExecArgs([]string{"web", "--", "ls", "-la"})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if service != "web" {
		t.Errorf("service = %q", service)
	}
	// The remote flags survive intact; that is the whole point of the
	// separator.
	if len(command) != 2 || command[1] != "-la" {
		t.Errorf("command = %q, want [ls -la]", command)
	}

	for _, args := range [][]string{{}, {"web"}, {"web", "--"}} {
		if _, _, err := splitExecArgs(args); err == nil {
			t.Errorf("accepted %q", args)
		}
	}
}

func TestExecQueryRoundTrips(t *testing.T) {
	// The command is repeated parameters rather than one joined string:
	// joining means the server has to split, and every splitting rule is wrong
	// for some argument someone will eventually pass.
	query := api.ExecQuery("shop", "shop-web-0",
		[]string{"/bin/sh", "-c", "echo hello world & true"}, true, "1000")
	values, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := values["command"]; len(got) != 3 || got[2] != "echo hello world & true" {
		t.Errorf("command = %q, want the argument array intact including the ampersand", got)
	}
	if values.Get("tty") != "true" || values.Get("user") != "1000" {
		t.Errorf("query lost its options: %s", query)
	}
}
