package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLayout(t *testing.T) Layout {
	t.Helper()
	base := t.TempDir()
	return Layout{
		Prefix:  filepath.Join(base, "lib"),
		ConfDir: filepath.Join(base, "etc"),
		DataDir: filepath.Join(base, "data"),
		RunDir:  filepath.Join(base, "run"),
		UnitDir: filepath.Join(base, "units"),
	}
}

func renderAllUnits(t *testing.T) map[string]string {
	t.Helper()
	l := testLayout(t)
	files := l.Files(MustLoad().All(), "/usr/local/bin/kanea", "1G")
	out := make(map[string]string, len(files))
	for _, f := range files {
		out[filepath.Base(f.Path)] = f.Body
	}
	return out
}

// Constraint #11: the control plane's memory floor is a property of
// kanea.slice, and it only reaches a component if that component's unit joins
// the slice. Since v1.30 these units are ours, so this is the check that
// replaces the drop-ins §5.2.11 used to describe.
func TestEveryUnitJoinsKaneaSlice(t *testing.T) {
	for name, body := range renderAllUnits(t) {
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		if !strings.Contains(body, "Slice=kanea.slice") {
			t.Errorf("%s does not declare Slice=kanea.slice; the memory floor would not reach it", name)
		}
	}
}

// The dataplane carries traffic and must not depend on the control plane's
// lifecycle — the same rule cmd/kanea/units.go protects for kanea-edge.
func TestCiliumDoesNotDependOnKanead(t *testing.T) {
	units := renderAllUnits(t)
	body, ok := units["kanea-cilium.service"]
	if !ok {
		t.Fatal("no cilium unit was rendered")
	}
	for _, forbidden := range []string{"After=kanead.service", "Requires=kanead.service", "BindsTo=kanead.service"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("kanea-cilium.service declares %q; a kanead restart would take the dataplane with it", forbidden)
		}
	}
}

// The socket must not be the distribution's. A node that ran Docker yesterday
// runs it tomorrow.
func TestContainerdUsesKaneasOwnPaths(t *testing.T) {
	l := testLayout(t)
	cfg := l.containerdConfig()
	if strings.Contains(cfg, "/run/containerd/containerd.sock") {
		t.Error("containerd config points at the distribution's socket")
	}
	if !strings.Contains(cfg, l.SocketPath()) {
		t.Errorf("containerd config does not use %s", l.SocketPath())
	}
	if strings.Contains(cfg, "/opt/cni/bin") {
		t.Error("containerd config points at /opt/cni/bin, which belongs to whatever else uses CNI")
	}
	if !strings.Contains(cfg, l.CNIBinDir()) {
		t.Errorf("containerd config does not use %s", l.CNIBinDir())
	}
}

// M0 spike ④: rootlesskit copy-ups /run into a namespace-private tmpfs, so a
// socket there is invisible to every client outside the namespace.
func TestBuildkitSocketIsNotUnderRun(t *testing.T) {
	l := testLayout(t)
	body := l.buildkitUnit()
	if !strings.Contains(body, "--addr unix://") {
		t.Fatal("buildkit unit sets no socket address")
	}
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "--addr unix://") {
			continue
		}
		addr := strings.TrimSpace(strings.SplitN(line, "unix://", 2)[1])
		if strings.HasPrefix(addr, "/run/") {
			t.Errorf("buildkitd socket %s is under a copy-up'd /run and would be invisible to clients", addr)
		}
	}
	if !strings.Contains(body, "User="+BuildkitUser) {
		t.Error("buildkitd does not run as the unprivileged build user")
	}
}

// A unit for a component that was not installed is a unit systemd fails to
// start on every boot.
func TestFilesOnlyCoverSelectedComponents(t *testing.T) {
	l := testLayout(t)
	only, err := MustLoad().Select([]string{"containerd"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range l.Files(only, "/usr/local/bin/kanea", "1G") {
		name := filepath.Base(f.Path)
		if strings.Contains(name, "cilium") && strings.HasSuffix(name, ".service") {
			t.Errorf("installing containerd alone rendered %s", name)
		}
		if strings.Contains(name, "etcd") || strings.Contains(name, "buildkit") {
			t.Errorf("installing containerd alone rendered %s", name)
		}
	}
}

func TestWriteFilesInstallsWithTheRightModes(t *testing.T) {
	l := testLayout(t)
	files := l.Files(MustLoad().All(), "/usr/local/bin/kanea", "1G")
	if err := WriteFiles(files); err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	for _, f := range files {
		info, err := os.Stat(f.Path)
		if err != nil {
			t.Errorf("%s: %v", f.Path, err)
			continue
		}
		if info.Mode().Perm() != f.Mode.Perm() {
			t.Errorf("%s is mode %04o, want %04o", f.Path, info.Mode().Perm(), f.Mode.Perm())
		}
	}
}

// etcd is Cilium's kvstore and holds its identities; it is also derived state
// that is never backed up, so the only thing protecting it is the filesystem
// and a loopback bind.
func TestSensitiveDirectoriesAreNotWorldReadable(t *testing.T) {
	l := testLayout(t)
	if err := l.CreateDirectories(); err != nil {
		t.Fatalf("CreateDirectories: %v", err)
	}
	for _, d := range l.Directories() {
		info, err := os.Stat(d.Path)
		if err != nil {
			t.Errorf("%s: %v", d.Path, err)
			continue
		}
		if info.Mode().Perm() != d.Mode.Perm() {
			t.Errorf("%s is mode %04o, want %04o", d.Path, info.Mode().Perm(), d.Mode.Perm())
		}
	}
	etcd := filepath.Join(l.DataDir, "etcd")
	info, err := os.Stat(etcd)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("%s is mode %04o; it holds Cilium's identities", etcd, info.Mode().Perm())
	}
}

func TestEtcdBindsToLoopbackOnly(t *testing.T) {
	body := testLayout(t).etcdUnit()
	if strings.Contains(body, "0.0.0.0") || strings.Contains(body, "://[::]") {
		t.Error("etcd binds beyond loopback; it has no authentication because it does not need any")
	}
	if !strings.Contains(body, EtcdEndpoint) {
		t.Errorf("etcd does not listen on %s", EtcdEndpoint)
	}
}

// systemd tolerates leading whitespace in some places and not others, and a
// unit that is subtly wrong fails at daemon-reload rather than anywhere useful.
func TestUnitsCarryNoLeadingTabs(t *testing.T) {
	for name, body := range renderAllUnits(t) {
		for n, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "\t") {
				t.Errorf("%s:%d has a leading tab: %q", name, n+1, line)
			}
		}
	}
}

// The subnet has to reach the agent's argv. The flags `kanea supervise cilium`
// accepts were unreachable before v1.33 because the unit invoked it bare, so
// moving the subnet meant hand-editing a generated file the next install
// overwrites.
func TestCiliumUnitCarriesTheSubnet(t *testing.T) {
	layout := Layout{
		Prefix: "/usr/local/lib/kanea", ConfDir: "/etc/kanea",
		DataDir: "/var/lib/kanea", RunDir: "/run/kanea", UnitDir: "/etc/systemd/system",
		NodeCIDR: "10.90.0.0/24", ClusterCIDR: "10.90.0.0/16",
	}
	unit := findUnit(t, layout, "kanea-cilium.service")
	for _, want := range []string{"--node-cidr 10.90.0.0/24", "--cluster-cidr 10.90.0.0/16"} {
		if !strings.Contains(unit, want) {
			t.Errorf("the cilium unit does not pass %s:\n%s", want, unit)
		}
	}

	// And the default still appears, so a node that says nothing gets the
	// compiled subnet explicitly rather than by omission.
	bare := findUnit(t, Layout{UnitDir: "/etc/systemd/system"}, "kanea-cilium.service")
	if !strings.Contains(bare, "--node-cidr "+DefaultNodeCIDR) {
		t.Errorf("the default subnet is not in the unit:\n%s", bare)
	}
}

func TestValidateNetworking(t *testing.T) {
	tests := []struct {
		name, node, cluster, want string
	}{
		{"the defaults", "", "", ""},
		{"a moved subnet", "10.90.0.0/24", "10.90.0.0/16", ""},
		{"not a CIDR", "10.90.0/24", "10.90.0.0/16", "not a CIDR"},
		{"host bits set", "10.90.0.5/24", "10.90.0.0/16", "host bits"},
		{"IPv6", "fd00::/64", "fd00::/48", "IPv4 only"},
		// cilium's own rule: --ipv4-native-routing-cidr must cover
		// --ipv4-range, so a node CIDR outside it cannot route.
		{"node outside cluster", "10.90.0.0/24", "10.244.0.0/16", "not inside"},
		{"node wider than cluster", "10.0.0.0/8", "10.244.0.0/16", "not inside"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Layout{NodeCIDR: tc.node, ClusterCIDR: tc.cluster}.ValidateNetworking()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateNetworking: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// findUnit returns one generated unit's body.
func findUnit(t *testing.T, layout Layout, name string) string {
	t.Helper()
	for _, f := range layout.Files([]*Component{{Name: "cilium"}}, "/usr/local/bin/kanea", "") {
		if strings.HasSuffix(f.Path, name) {
			return f.Body
		}
	}
	t.Fatalf("no %s among the generated files", name)
	return ""
}
