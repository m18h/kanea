package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// buildSpec applies the driver's spec options to a bare OCI spec, the way
// containerd does at container creation. Nothing here needs a running daemon,
// which is the point: the hardening and limit guarantees are testable.
func buildSpec(t *testing.T, alloc AllocSpec) *oci.Spec {
	t.Helper()
	s := &oci.Spec{
		Version: specs.Version,
		Process: &specs.Process{Args: []string{"/bin/sh"}},
		Root:    &specs.Root{Path: "rootfs"},
		Linux:   &specs.Linux{},
	}
	for i, opt := range specOpts(alloc) {
		if err := opt(context.Background(), nil, nil, s); err != nil {
			t.Fatalf("spec option %d: %v", i, err)
		}
	}
	return s
}

func validAlloc() AllocSpec {
	return AllocSpec{
		ID:      "shop-web-1",
		Project: "shop",
		Service: "web",
		Image:   "nginx:1.27-alpine",
		Resources: Resources{
			CPUMillis:   500,
			MemoryBytes: 512 << 20,
		},
	}
}

func TestHardeningDefaultsAreApplied(t *testing.T) {
	// AGENTS.md constraint #6 / PRD §14 A05. These are not configurable, so the
	// test asserts them unconditionally.
	s := buildSpec(t, validAlloc())

	caps := s.Process.Capabilities
	if caps == nil {
		t.Fatal("no capability set: the container would inherit containerd's defaults")
	}
	for name, set := range map[string][]string{
		"bounding": caps.Bounding, "effective": caps.Effective,
		"permitted": caps.Permitted, "inheritable": caps.Inheritable,
	} {
		if len(set) != 0 {
			t.Errorf("%s capabilities = %v, want empty (drop ALL)", name, set)
		}
	}
	if !s.Process.NoNewPrivileges {
		t.Error("NoNewPrivileges = false; a setuid binary in the image could escalate")
	}

	wantNS := map[specs.LinuxNamespaceType]bool{
		specs.PIDNamespace: false, specs.IPCNamespace: false,
		specs.UTSNamespace: false, specs.MountNamespace: false,
		specs.CgroupNamespace: false,
	}
	for _, ns := range s.Linux.Namespaces {
		if _, want := wantNS[ns.Type]; want {
			wantNS[ns.Type] = true
		}
	}
	for ns, present := range wantNS {
		if !present {
			t.Errorf("missing %s namespace: allocs must not share it", ns)
		}
	}

	if len(s.Linux.MaskedPaths) == 0 {
		t.Error("no masked paths: /proc/kcore and friends would be readable")
	}
	if len(s.Linux.ReadonlyPaths) == 0 {
		t.Error("no read-only paths: /proc/sys would be writable")
	}

	// containerd's default spec has no cgroup mount, so a workload cannot read
	// its own limits. We add one, and it must be read-only.
	var cgroup *specs.Mount
	for i := range s.Mounts {
		if s.Mounts[i].Destination == "/sys/fs/cgroup" {
			cgroup = &s.Mounts[i]
		}
	}
	if cgroup == nil {
		t.Fatal("no /sys/fs/cgroup mount: the workload cannot read its own limits")
	}
	if !hasOption(cgroup.Options, "ro") {
		t.Errorf("cgroup mount options = %v, want read-only", cgroup.Options)
	}
}

func TestResourceLimitsAreAlwaysSet(t *testing.T) {
	// AGENTS.md constraint #11: no container ever runs unlimited.
	alloc := validAlloc()
	alloc.CgroupPath = CgroupPath(WorkloadSlice, alloc.ID)
	s := buildSpec(t, alloc)

	res := s.Linux.Resources
	if res == nil || res.Memory == nil || res.Memory.Limit == nil {
		t.Fatal("no memory limit")
	}
	if *res.Memory.Limit != 512<<20 {
		t.Errorf("memory limit = %d, want %d", *res.Memory.Limit, 512<<20)
	}
	// Swap pinned to the limit means zero swap headroom: the §5.2.11 reserve is
	// RAM, so an alloc must not exceed its ceiling by swapping.
	if res.Memory.Swap == nil || *res.Memory.Swap != *res.Memory.Limit {
		t.Errorf("swap = %v, want it pinned to the memory limit", res.Memory.Swap)
	}

	if res.CPU == nil || res.CPU.Quota == nil || res.CPU.Period == nil {
		t.Fatal("no CPU quota")
	}
	// 500 millicores of a 100ms period is 50ms.
	if *res.CPU.Quota != 50_000 || *res.CPU.Period != 100_000 {
		t.Errorf("cpu quota/period = %d/%d, want 50000/100000", *res.CPU.Quota, *res.CPU.Period)
	}

	if res.Pids == nil || res.Pids.Limit == nil {
		t.Fatal("no pids limit: a fork bomb would be uncontained")
	}
	if *res.Pids.Limit != DefaultPidsLimit {
		t.Errorf("pids limit = %d, want the default %d", *res.Pids.Limit, DefaultPidsLimit)
	}

	if s.Linux.CgroupsPath != "/kanea-workloads.slice/shop-web-1" {
		t.Errorf("cgroup path = %q", s.Linux.CgroupsPath)
	}
}

func TestExplicitPidsLimitIsHonoured(t *testing.T) {
	alloc := validAlloc()
	alloc.Resources.PidsLimit = 32
	s := buildSpec(t, alloc)

	if got := *s.Linux.Resources.Pids.Limit; got != 32 {
		t.Errorf("pids limit = %d, want 32", got)
	}
}

func TestCPUQuotaConversion(t *testing.T) {
	tests := []struct {
		millis    int
		wantQuota int64
	}{
		{100, 10_000},   // 0.1 core
		{500, 50_000},   // half a core
		{1000, 100_000}, // one core
		{2500, 250_000}, // 2.5 cores
	}
	for _, tc := range tests {
		alloc := validAlloc()
		alloc.Resources.CPUMillis = tc.millis
		s := buildSpec(t, alloc)
		if got := *s.Linux.Resources.CPU.Quota; got != tc.wantQuota {
			t.Errorf("%d millicores -> quota %d, want %d", tc.millis, got, tc.wantQuota)
		}
	}
}

func TestNetnsIsJoinedByPath(t *testing.T) {
	// The netns is created and wired up before the task starts, so the spec
	// must join an existing one rather than ask for a fresh namespace.
	alloc := validAlloc()
	alloc.NetnsPath = "/run/netns/shop-web-1"
	s := buildSpec(t, alloc)

	var found bool
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace {
			found = true
			if ns.Path != alloc.NetnsPath {
				t.Errorf("netns path = %q, want %q", ns.Path, alloc.NetnsPath)
			}
		}
	}
	if !found {
		t.Error("no network namespace in the spec")
	}
}

func TestNoNetnsPathMeansNoJoinedNamespace(t *testing.T) {
	s := buildSpec(t, validAlloc())
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path != "" {
			t.Errorf("unexpected joined netns %q", ns.Path)
		}
	}
}

func TestEnvIsSortedForStableDiffs(t *testing.T) {
	alloc := validAlloc()
	alloc.Env = map[string]string{"ZED": "1", "ALPHA": "2", "MID": "3"}
	s := buildSpec(t, alloc)

	var kanea []string
	for _, e := range s.Process.Env {
		if strings.HasPrefix(e, "ZED=") || strings.HasPrefix(e, "ALPHA=") || strings.HasPrefix(e, "MID=") {
			kanea = append(kanea, e)
		}
	}
	want := []string{"ALPHA=2", "MID=3", "ZED=1"}
	if len(kanea) != len(want) {
		t.Fatalf("env = %v, want %v", kanea, want)
	}
	for i := range want {
		if kanea[i] != want[i] {
			t.Fatalf("env = %v, want %v (unsorted env churns plan diffs)", kanea, want)
		}
	}
}

func TestMountsBecomeBindMounts(t *testing.T) {
	alloc := validAlloc()
	alloc.Mounts = []Mount{
		{Source: "/srv/data", Destination: "/var/lib/data"},
		{Source: "/srv/media", Destination: "/media", ReadOnly: true},
	}
	s := buildSpec(t, alloc)

	var rw, ro *specs.Mount
	for i := range s.Mounts {
		switch s.Mounts[i].Destination {
		case "/var/lib/data":
			rw = &s.Mounts[i]
		case "/media":
			ro = &s.Mounts[i]
		}
	}
	if rw == nil || ro == nil {
		t.Fatalf("mounts missing: %+v", s.Mounts)
	}
	if !hasOption(rw.Options, "rw") || hasOption(rw.Options, "ro") {
		t.Errorf("read-write mount options = %v", rw.Options)
	}
	if !hasOption(ro.Options, "ro") {
		t.Errorf("read-only mount options = %v", ro.Options)
	}
	for _, m := range []*specs.Mount{rw, ro} {
		if m.Type != "bind" || !hasOption(m.Options, "rbind") {
			t.Errorf("mount %s is not an rbind: %+v", m.Destination, m)
		}
	}
}

func hasOption(options []string, want string) bool {
	for _, o := range options {
		if o == want {
			return true
		}
	}
	return false
}

func TestReadOnlyRootfs(t *testing.T) {
	alloc := validAlloc()
	alloc.ReadOnlyRootfs = true
	s := buildSpec(t, alloc)

	if s.Root == nil || !s.Root.Readonly {
		t.Error("rootfs is writable despite ReadOnlyRootfs")
	}
	if s.Root.Path != "rootfs" {
		t.Errorf("root path = %q, want the existing path preserved", s.Root.Path)
	}
}

func TestCommandOverridesEntrypoint(t *testing.T) {
	alloc := validAlloc()
	alloc.Command = []string{"/bin/echo", "hello"}
	s := buildSpec(t, alloc)

	if len(s.Process.Args) != 2 || s.Process.Args[0] != "/bin/echo" {
		t.Errorf("args = %v, want the command override", s.Process.Args)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AllocSpec)
		wantErr string
	}{
		{"valid", func(*AllocSpec) {}, ""},
		{"empty id", func(a *AllocSpec) { a.ID = "" }, "empty alloc id"},
		{"short id", func(a *AllocSpec) { a.ID = "web" }, "at least 5"},
		{"no project", func(a *AllocSpec) { a.Project = "" }, "no project"},
		{"no image", func(a *AllocSpec) { a.Image = "" }, "no image"},
		{"no cpu limit", func(a *AllocSpec) { a.Resources.CPUMillis = 0 }, "no CPU limit"},
		{"no memory limit", func(a *AllocSpec) { a.Resources.MemoryBytes = 0 }, "no memory limit"},
		{
			"relative mount source",
			func(a *AllocSpec) { a.Mounts = []Mount{{Source: "data", Destination: "/data"}} },
			"must be absolute",
		},
		{
			"relative mount destination",
			func(a *AllocSpec) { a.Mounts = []Mount{{Source: "/srv/data", Destination: "data"}} },
			"must be absolute",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alloc := validAlloc()
			tc.mutate(&alloc)
			err := alloc.Validate()

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("error does not wrap ErrInvalidSpec: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want mention of %q", err, tc.wantErr)
			}
		})
	}
}

func TestShortIDErrorExplainsWhy(t *testing.T) {
	// The 5-character floor comes from Cilium's interface-name derivation
	// (M0 spike ①); an operator hitting it deserves to know that.
	alloc := validAlloc()
	alloc.ID = "web"
	err := alloc.Validate()
	if err == nil || !strings.Contains(err.Error(), "interface name") {
		t.Errorf("error = %v, want an explanation mentioning the interface name", err)
	}
}

func TestCgroupPath(t *testing.T) {
	tests := []struct {
		parent, id, want string
	}{
		{"kanea-workloads.slice", "shop-web-1", "/kanea-workloads.slice/shop-web-1"},
		{"/kanea-workloads.slice/", "shop-web-1", "/kanea-workloads.slice/shop-web-1"},
		{"", "shop-web-1", "/kanea-workloads.slice/shop-web-1"},
	}
	for _, tc := range tests {
		if got := CgroupPath(tc.parent, tc.id); got != tc.want {
			t.Errorf("CgroupPath(%q, %q) = %q, want %q", tc.parent, tc.id, got, tc.want)
		}
	}
}

func TestNamespaceIsPerProject(t *testing.T) {
	// One containerd namespace per project gives free isolation of images and
	// containers (PRD §5.2.4).
	if got := Namespace("shop"); got != "kanea-shop" {
		t.Errorf("Namespace(shop) = %q, want kanea-shop", got)
	}
	if Namespace("shop") == Namespace("bank") {
		t.Error("projects share a containerd namespace")
	}
}

func TestNetnsPath(t *testing.T) {
	if got := NetnsPath("shop-web-1"); got != "/run/netns/shop-web-1" {
		t.Errorf("NetnsPath = %q", got)
	}
}

func TestDeleteNetnsIsIdempotentForMissingNamespace(t *testing.T) {
	// Teardown runs on paths where the namespace may already be gone.
	if err := DeleteNetns("kanea-does-not-exist-" + t.Name()); err != nil {
		t.Errorf("deleting a missing netns must succeed, got %v", err)
	}
	if err := DeleteNetns(""); err != nil {
		t.Errorf("deleting an empty alloc id must be a no-op, got %v", err)
	}
}

func TestRequestedCapabilitiesAreGranted(t *testing.T) {
	// R13: the allowlist on top of the drop-ALL default. nginx needs CAP_CHOWN
	// to chown its cache dir; redis needs SETUID/SETGID to drop privileges.
	alloc := validAlloc()
	alloc.Capabilities = []string{"CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"}
	s := buildSpec(t, alloc)

	caps := s.Process.Capabilities
	if caps == nil {
		t.Fatal("no capability set")
	}
	for name, set := range map[string][]string{
		"bounding": caps.Bounding, "effective": caps.Effective, "permitted": caps.Permitted,
	} {
		if len(set) != 3 {
			t.Errorf("%s = %v, want the three requested capabilities", name, set)
		}
	}
	// Never inheritable or ambient: a granted capability must not survive into
	// a child that re-execs.
	if len(caps.Inheritable) != 0 {
		t.Errorf("inheritable = %v, want empty", caps.Inheritable)
	}
	if len(caps.Ambient) != 0 {
		t.Errorf("ambient = %v, want empty", caps.Ambient)
	}
}

func TestNoRequestedCapabilitiesStillDropsAll(t *testing.T) {
	// The default must not change: no request means no capabilities.
	s := buildSpec(t, validAlloc())
	caps := s.Process.Capabilities
	if len(caps.Bounding)+len(caps.Effective)+len(caps.Permitted)+len(caps.Inheritable) != 0 {
		t.Errorf("capabilities granted without a request: %+v", caps)
	}
}

// A UTS namespace carrying the host's hostname is the worst of both worlds:
// isolated, but every log line inside the container claims to be the node.
func TestSpecSetsAllocHostname(t *testing.T) {
	alloc := validAlloc()
	s := buildSpec(t, alloc)
	if s.Hostname != alloc.ID {
		t.Errorf("Hostname = %q, want the alloc id %q", s.Hostname, alloc.ID)
	}
}
