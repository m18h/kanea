package passthrough

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parse is the common harness: parse one config and require success.
func parse(t *testing.T, src string) *Policy {
	t.Helper()
	policy, err := Parse("passthrough.hcl", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return policy
}

// parseErr requires failure and returns the message.
func parseErr(t *testing.T, src string) string {
	t.Helper()
	if _, err := Parse("passthrough.hcl", []byte(src)); err != nil {
		return err.Error()
	}
	t.Fatal("expected an error, got none")
	return ""
}

// deviceGrantSrc and socketGrantSrc build config the way an operator writes it.
//
// Multi-line deliberately: HCL refuses two attributes on one line, and a test
// fixture that is not shaped like the real file tests the wrong grammar.
func deviceGrantSrc(name, nodes, allow, mode string) string {
	src := "device \"" + name + "\" {\n  nodes = " + nodes + "\n  allow = " + allow + "\n"
	if mode != "" {
		src += "  mode  = \"" + mode + "\"\n"
	}
	return src + "}\n"
}

func socketGrantSrc(name, path, allow string) string {
	return "socket \"" + name + "\" {\n  path  = \"" + path + "\"\n  allow = " + allow + "\n}\n"
}

// shortDir gives a directory whose paths fit in a sockaddr_un, which t.TempDir
// does not reliably do once the test name is appended.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pt")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// listenUnix creates a real socket, since "is this a socket" is checked with a
// stat and a fake would test nothing.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a device"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// The feature does not exist until an operator writes a file. A nil policy and
// a zero policy behave the same, because the daemon runs without the config and
// a nil check the caller forgot must not become an open door.
func TestPolicyIsClosedByDefault(t *testing.T) {
	for name, policy := range map[string]*Policy{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if policy.Enabled() {
				t.Error("policy reports itself as enabled")
			}
			if _, err := policy.ResolveDevice("shop", "gpu"); !errors.Is(err, ErrNotAllowed) {
				t.Fatalf("ResolveDevice = %v, want ErrNotAllowed", err)
			}
			_, err := policy.ResolveSocket("shop", "containerd")
			if !errors.Is(err, ErrNotAllowed) {
				t.Fatalf("ResolveSocket = %v, want ErrNotAllowed", err)
			}
			if !strings.Contains(err.Error(), "--passthrough-config") {
				t.Errorf("error %v does not say how to enable it", err)
			}
		})
	}
}

// An empty path is the default, not a misconfiguration.
func TestLoadWithNoFileConfiguredPermitsNothing(t *testing.T) {
	policy, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") = %v, want nil", err)
	}
	if policy.Enabled() {
		t.Error("an unconfigured policy reports itself as enabled")
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(shortDir(t), "absent.hcl")); err == nil {
		t.Fatal("a named-but-missing config file was accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a device grant",
			src:  deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, ""),
		},
		{
			name: "a socket grant",
			src:  socketGrantSrc("containerd", "/run/kanea/containerd.sock", `["ops"]`),
		},
		{
			name: "explicit mode",
			src:  deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, "rwm"),
		},
		// An empty allow list is the difference between "not filled in yet" and
		// "anyone may have this", and it is not resolved permissively.
		{
			name: "device grant allowing nobody",
			src:  deviceGrantSrc("gpu", `["/dev/null"]`, `[]`, ""),
			want: "names no projects",
		},
		{
			name: "socket grant allowing nobody",
			src:  socketGrantSrc("containerd", "/run/k.sock", `[]`),
			want: "names no projects",
		},
		{
			name: "device grant with no nodes",
			src:  deviceGrantSrc("gpu", `[]`, `["media"]`, ""),
			want: "lists no nodes",
		},
		{
			name: "relative device path",
			src:  deviceGrantSrc("gpu", `["dev/null"]`, `["media"]`, ""),
			want: "must be absolute",
		},
		{
			name: "traversal in a device path",
			src:  deviceGrantSrc("gpu", `["/dev/../etc/shadow"]`, `["media"]`, ""),
			want: "must not contain",
		},
		{
			name: "the root filesystem",
			src:  socketGrantSrc("everything", "/", `["ops"]`),
			want: "not a device or a socket",
		},
		{
			name: "grant name no spec could reference",
			src:  deviceGrantSrc("Not_A_Label", `["/dev/null"]`, `["media"]`, ""),
			want: "DNS-1123 label",
		},
		{
			name: "project name that is not one",
			src:  deviceGrantSrc("gpu", `["/dev/null"]`, `["Not A Project"]`, ""),
			want: "not a project name",
		},
		{
			name: "nonsense mode",
			src:  deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, "rwx"),
			want: "combination of r, w and m",
		},
		{
			name: "duplicate device grant",
			src: deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, "") +
				deviceGrantSrc("gpu", `["/dev/zero"]`, `["ml"]`, ""),
			want: "defined twice",
		},
		{
			name: "duplicate socket grant",
			src: socketGrantSrc("rt", "/run/a.sock", `["ops"]`) +
				socketGrantSrc("rt", "/run/b.sock", `["ops"]`),
			want: "defined twice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == "" {
				parse(t, tc.src)
				return
			}
			if got := parseErr(t, tc.src); !strings.Contains(got, tc.want) {
				t.Fatalf("error %q, want a mention of %q", got, tc.want)
			}
		})
	}
}

// The default is read-and-write but never mknod: `m` lets a container create
// other nodes of the same major, which is a larger grant than the operator
// writing a single node path is making.
func TestDeviceModeDefaultsToReadWriteWithoutMknod(t *testing.T) {
	policy := parse(t, deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, ""))

	devices, err := policy.ResolveDevice("media", "gpu")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	if devices[0].Perms != "rw" {
		t.Errorf("perms = %q, want %q", devices[0].Perms, DefaultDeviceMode)
	}
}

func TestResolveDeviceReturnsEveryNode(t *testing.T) {
	policy := parse(t, deviceGrantSrc("gpu", `["/dev/null", "/dev/zero"]`, `["media"]`, ""))

	devices, err := policy.ResolveDevice("media", "gpu")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(devices))
	}
}

// The scoping that `storage.allowed_host_paths` does not have. A grant belongs
// to the projects it names and to no others.
func TestGrantsAreProjectScoped(t *testing.T) {
	policy := parse(t, deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, "")+
		socketGrantSrc("containerd", "/dev/null", `["ops"]`))

	_, err := policy.ResolveDevice("shop", "gpu")
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an unlisted project got a device grant: %v", err)
	}
	if !strings.Contains(err.Error(), `"shop"`) {
		t.Errorf("error %v does not name the project that was refused", err)
	}

	if _, err := policy.ResolveSocket("shop", "containerd"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an unlisted project got a socket grant: %v", err)
	}
}

func TestUnknownGrantNamesWhatExists(t *testing.T) {
	policy := parse(t, deviceGrantSrc("gpu", `["/dev/null"]`, `["media"]`, ""))

	_, err := policy.ResolveDevice("media", "tpu")
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("ResolveDevice = %v, want ErrNotAllowed", err)
	}
	// A typo should report what was meant rather than only what was wrong.
	if !strings.Contains(err.Error(), "gpu") {
		t.Errorf("error %v does not list the grants that do exist", err)
	}
}

func TestResolveSocketAcceptsARealSocket(t *testing.T) {
	sock := filepath.Join(shortDir(t), "c.sock")
	listenUnix(t, sock)

	policy := parse(t, socketGrantSrc("containerd", sock, `["ops"]`))

	resolved, err := policy.ResolveSocket("ops", "containerd")
	if err != nil {
		t.Fatalf("ResolveSocket: %v", err)
	}
	if resolved == "" {
		t.Error("ResolveSocket returned an empty path")
	}
}

// The check that matters is taken when the path is handed to a container, not
// when the daemon booted: a grant whose target has become a regular file is the
// swap this exists to catch.
func TestAGrantWhoseTargetIsTheWrongKindIsRefused(t *testing.T) {
	regular := filepath.Join(shortDir(t), "plain")
	writeFile(t, regular)

	t.Run("socket grant pointing at a file", func(t *testing.T) {
		policy := parse(t, socketGrantSrc("rt", regular, `["ops"]`))
		_, err := policy.ResolveSocket("ops", "rt")
		if !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("ResolveSocket = %v, want ErrNotAllowed", err)
		}
		if !strings.Contains(err.Error(), "not a socket") {
			t.Errorf("error %v does not say what was wrong", err)
		}
	})

	t.Run("device grant pointing at a file", func(t *testing.T) {
		policy := parse(t, deviceGrantSrc("gpu", `["`+regular+`"]`, `["media"]`, ""))
		_, err := policy.ResolveDevice("media", "gpu")
		if !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("ResolveDevice = %v, want ErrNotAllowed", err)
		}
		if !strings.Contains(err.Error(), "not a device") {
			t.Errorf("error %v does not say what was wrong", err)
		}
	})
}

// A device that is unplugged must fail the alloc that wants it, and only that
// alloc — it must not have stopped the daemon from loading its config.
func TestAMissingNodeIsALoadTimeSuccessAndAResolveTimeRefusal(t *testing.T) {
	absent := filepath.Join(shortDir(t), "renderD128")

	policy := parse(t, deviceGrantSrc("gpu", `["`+absent+`"]`, `["media"]`, ""))
	if !policy.Enabled() {
		t.Fatal("the grant was dropped at load time")
	}

	_, err := policy.ResolveDevice("media", "gpu")
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("ResolveDevice = %v, want ErrNotAllowed", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error %v does not explain that the device is absent", err)
	}
}

// A symlinked grant resolves to what it points at now, and the resolved path is
// what gets mounted — never the spelling.
func TestSymlinksAreResolvedAtUse(t *testing.T) {
	link := filepath.Join(shortDir(t), "dri")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	policy := parse(t, deviceGrantSrc("gpu", `["`+link+`"]`, `["media"]`, ""))

	devices, err := policy.ResolveDevice("media", "gpu")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if devices[0].Path == link {
		t.Errorf("path %q is the symlink, not what it resolves to", devices[0].Path)
	}
}
