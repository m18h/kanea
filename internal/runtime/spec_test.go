package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
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
		Linux: &specs.Linux{
			// containerd's default spec denies every device, and withResources
			// preserves that list rather than replacing it. Seeding it here is
			// not decoration: without it a device test would assert on an allow
			// rule that has nothing to override, and would pass on a spec that
			// containerd would not have run.
			Resources: &specs.LinuxResources{
				Devices: []specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}},
			},
		},
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

func TestDeclaredResourceLimitsAreSet(t *testing.T) {
	// R11: a declared limit is enforced exactly.
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

// R11 (v1.58): a zero limit is unbounded (no memory.max, no cpu.max) but the
// pids cap stays on every alloc, because a fork bomb is not a resource to
// serve to capacity.
func TestUnboundedResourcesSetNoQuotaButKeepThePidsCap(t *testing.T) {
	alloc := validAlloc()
	alloc.Resources.CPUMillis = 0
	alloc.Resources.MemoryBytes = 0
	s := buildSpec(t, alloc)

	res := s.Linux.Resources
	if res == nil {
		t.Fatal("no resources at all; the pids cap must survive unbounded cpu/memory")
	}
	if res.Memory != nil {
		t.Errorf("memory = %+v, want none for an unbounded alloc", res.Memory)
	}
	if res.CPU != nil {
		t.Errorf("cpu = %+v, want no quota for an unbounded alloc", res.CPU)
	}
	if res.Pids == nil || res.Pids.Limit == nil || *res.Pids.Limit != DefaultPidsLimit {
		t.Fatal("pids cap missing on an unbounded alloc")
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

// A granted socket carries the options a socket should never be without. The
// mount is a bind like any other, so the caller's options have to survive the
// rbind and rw/ro this package always sets.
func TestCallerMountOptionsSurvive(t *testing.T) {
	alloc := validAlloc()
	alloc.Mounts = []Mount{{
		Source:      "/run/kanea/containerd.sock",
		Destination: "/var/run/docker.sock",
		Options:     []string{"nosuid", "noexec", "nodev"},
	}}
	s := buildSpec(t, alloc)

	var sock *specs.Mount
	for i := range s.Mounts {
		if s.Mounts[i].Destination == "/var/run/docker.sock" {
			sock = &s.Mounts[i]
		}
	}
	if sock == nil {
		t.Fatalf("socket mount missing: %+v", s.Mounts)
	}
	for _, want := range []string{"rbind", "rw", "nosuid", "noexec", "nodev"} {
		if !hasOption(sock.Options, want) {
			t.Errorf("options %v are missing %q", sock.Options, want)
		}
	}
}

// A device needs two things, and the one that is easy to forget is the second:
// containerd's default spec denies every device, so a node without a matching
// allow rule is visible in /dev and cannot be opened.
func TestGrantedDeviceGetsANodeAndACgroupAllowRule(t *testing.T) {
	alloc := validAlloc()
	alloc.Devices = []Device{{Path: "/dev/null", Perms: "rw"}}
	s := buildSpec(t, alloc)

	var node *specs.LinuxDevice
	for i := range s.Linux.Devices {
		if s.Linux.Devices[i].Path == "/dev/null" {
			node = &s.Linux.Devices[i]
		}
	}
	if node == nil {
		t.Fatalf("no device node in the spec: %+v", s.Linux.Devices)
	}

	if s.Linux.Resources == nil {
		t.Fatal("the spec carries no resources, so it carries no device rules")
	}
	rules := s.Linux.Resources.Devices
	if len(rules) == 0 {
		t.Fatal("no device cgroup rules at all")
	}
	// The inherited deny-all must still be there, and the allow must come after
	// it: rules are evaluated in order, so an allow placed first means nothing.
	if rules[0].Allow {
		t.Errorf("the first rule is an allow; the deny-all default was replaced: %+v", rules)
	}
	var allowed bool
	for _, r := range rules[1:] {
		if r.Allow && r.Major != nil && *r.Major == node.Major &&
			r.Minor != nil && *r.Minor == node.Minor {
			allowed = true
		}
	}
	if !allowed {
		t.Errorf("no allow rule for the granted device; it would be visible and unopenable: %+v", rules)
	}
}

// No devices means no change to the inherited deny-all. A service that never
// asked for one must not acquire a device rule.
func TestNoDevicesLeavesTheDenyAllAlone(t *testing.T) {
	s := buildSpec(t, validAlloc())

	for _, r := range s.Linux.Resources.Devices {
		if r.Allow {
			t.Errorf("an alloc with no device grants has an allow rule: %+v", r)
		}
	}
	if len(s.Linux.Devices) != 0 {
		t.Errorf("an alloc with no device grants has device nodes: %+v", s.Linux.Devices)
	}
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
		// Zero limits are unbounded (R11, v1.58), not malformed.
		{"unbounded cpu", func(a *AllocSpec) { a.Resources.CPUMillis = 0 }, ""},
		{"unbounded memory", func(a *AllocSpec) { a.Resources.MemoryBytes = 0 }, ""},
		{"negative cpu limit", func(a *AllocSpec) { a.Resources.CPUMillis = -1 }, "negative CPU limit"},
		{"negative memory limit", func(a *AllocSpec) { a.Resources.MemoryBytes = -1 }, "negative memory limit"},
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
		{
			"relative device path",
			func(a *AllocSpec) { a.Devices = []Device{{Path: "dri/renderD128", Perms: "rw"}} },
			"must be absolute",
		},
		// A device with no permissions is a node the container can see and
		// cannot open, which is a caller that dropped the field rather than an
		// operator who meant it.
		{
			"device with no permissions",
			func(a *AllocSpec) { a.Devices = []Device{{Path: "/dev/dri/renderD128"}} },
			"no cgroup permissions",
		},
		// The runtime set is closed: a runtime name is a binary containerd
		// executes as root, so it is validated against a list, never passed
		// through (PRD §6.2 R25).
		{"wasmtime runtime", func(a *AllocSpec) { a.Runtime = RuntimeWasmtime }, ""},
		{"unknown runtime", func(a *AllocSpec) { a.Runtime = "io.containerd.kata.v2" }, "only"},
		{
			"runc spelled out",
			func(a *AllocSpec) { a.Runtime = "io.containerd.runc.v2" },
			"only",
		},
		// runc refuses an unknown capability name at task create, failing every
		// alloc of the service with an error nobody can attribute. The spec-level
		// "none" token must be resolved by the reconciler's projection before the
		// spec reaches this driver: a leaked one is a caller bug, refused here
		// by name (R13, v1.56).
		{"granted capability", func(a *AllocSpec) { a.Capabilities = []string{"CAP_CHOWN"} }, ""},
		{
			"unprojected capability token",
			func(a *AllocSpec) { a.Capabilities = []string{"none"} },
			"not a capability name",
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

// The wasm runtime reaches containerd as a container-level runtime selection.
// Applying the option the way the client does at NewContainer proves the name
// lands on the container record without needing a daemon.
func TestRuntimeOptsSelectTheWasmtimeShim(t *testing.T) {
	alloc := validAlloc()
	alloc.Runtime = RuntimeWasmtime

	opts := runtimeOpts(alloc)
	if len(opts) != 1 {
		t.Fatalf("runtimeOpts returned %d options, want 1", len(opts))
	}
	var c containers.Container
	if err := opts[0](context.Background(), nil, &c); err != nil {
		t.Fatalf("apply runtime option: %v", err)
	}
	if c.Runtime.Name != RuntimeWasmtime {
		t.Fatalf("container runtime = %q, want %q", c.Runtime.Name, RuntimeWasmtime)
	}
}

// An empty Runtime must produce NO option at all, not the runc name spelled
// out. The default is containerd's to own, and every pre-v1.39 alloc relies on
// that meaning staying put.
func TestNoRuntimeMeansContainerdsDefault(t *testing.T) {
	if got := runtimeOpts(validAlloc()); len(got) != 0 {
		t.Fatalf("an empty Runtime produced %d container options; the default must stay containerd's", len(got))
	}
}

func TestShortIDErrorExplainsWhy(t *testing.T) {
	// The 5-character floor keeps alloc ids long enough for the datapath's
	// veth-name derivation; an operator hitting it deserves to know that.
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
	// The DRIVER's default must not change: an empty list means no
	// capabilities, full stop. The R13 baseline is the reconciler's
	// projection (effectiveCapabilities): by the time a spec reaches this
	// package the union has already happened, so an empty list here is a
	// service that opted out, or a function.
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

// PRD §6.2 R23: the declared uid/gid is what the workload runs as.

func TestUserOverridesTheImage(t *testing.T) {
	alloc := validAlloc()
	alloc.User = &User{UID: 999, GID: 998, AdditionalGIDs: []uint32{1000, 2000}}

	// Stand in for what oci.WithImageConfig leaves behind: this option list is
	// appended after it at container creation, so the image's USER is already
	// in Process.User by the time these run. Overriding it is the whole point,
	// and a test starting from a zero User would pass without the override.
	s := &oci.Spec{
		Version: specs.Version,
		Process: &specs.Process{
			Args: []string{"/bin/sh"},
			User: specs.User{UID: 101, GID: 101},
		},
		Root:  &specs.Root{Path: "rootfs"},
		Linux: &specs.Linux{},
	}
	for i, opt := range specOpts(alloc) {
		if err := opt(context.Background(), nil, nil, s); err != nil {
			t.Fatalf("spec option %d: %v", i, err)
		}
	}

	if s.Process.User.UID != 999 || s.Process.User.GID != 998 {
		t.Errorf("user = %d:%d, want 999:998: the image's own USER won",
			s.Process.User.UID, s.Process.User.GID)
	}
	if len(s.Process.User.AdditionalGids) != 2 ||
		s.Process.User.AdditionalGids[0] != 1000 || s.Process.User.AdditionalGids[1] != 2000 {
		t.Errorf("additional gids = %v, want [1000 2000]", s.Process.User.AdditionalGids)
	}
}

// A nil user is not a request to run as root. Every spec written before R23
// means "the image decides", and reading it as 0:0 would silently promote every
// workload on the node to root on upgrade.
func TestNoUserLeavesTheImagesChoiceAlone(t *testing.T) {
	s := &oci.Spec{
		Version: specs.Version,
		Process: &specs.Process{
			Args: []string{"/bin/sh"},
			User: specs.User{UID: 101, GID: 101},
		},
		Root:  &specs.Root{Path: "rootfs"},
		Linux: &specs.Linux{},
	}
	for i, opt := range specOpts(validAlloc()) {
		if err := opt(context.Background(), nil, nil, s); err != nil {
			t.Fatalf("spec option %d: %v", i, err)
		}
	}
	if s.Process.User.UID != 101 || s.Process.User.GID != 101 {
		t.Errorf("user = %d:%d, want the image's 101:101 untouched",
			s.Process.User.UID, s.Process.User.GID)
	}
}

// A non-root user does not weaken the R13 defaults. It is what makes most of
// them unnecessary, which is a different claim.
func TestUserKeepsTheHardeningDefaults(t *testing.T) {
	alloc := validAlloc()
	alloc.User = &User{UID: 999, GID: 999}
	s := buildSpec(t, alloc)

	if !s.Process.NoNewPrivileges {
		t.Error("no-new-privileges is off for a non-root workload")
	}
	caps := s.Process.Capabilities
	if caps == nil || len(caps.Bounding) != 0 || len(caps.Effective) != 0 {
		t.Errorf("capabilities = %+v, want everything still dropped", caps)
	}
}

func TestUserRejectsTheUnchangedSentinel(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *User
	}{
		{"uid", &User{UID: invalidID, GID: 999}},
		{"gid", &User{UID: 999, GID: invalidID}},
		{"supplementary group", &User{UID: 999, GID: 999, AdditionalGIDs: []uint32{invalidID}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alloc := validAlloc()
			alloc.User = tc.user
			err := alloc.Validate()
			if err == nil || !strings.Contains(err.Error(), "unchanged") {
				t.Errorf("Validate() = %v, want a complaint about the sentinel", err)
			}
		})
	}
}
