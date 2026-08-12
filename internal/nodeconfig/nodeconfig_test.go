package nodeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/provision"
)

func writeConfig(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode is subject to umask; make the test mean what it says.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProbeWithNoFileIsTheFeatureBeingOff(t *testing.T) {
	cfg, err := Probe(filepath.Join(t.TempDir(), "kanea.hcl"))
	if err != nil {
		t.Fatalf("a missing probed file must not be an error, got %v", err)
	}
	if cfg.AllowedHostPaths != nil || cfg.Path != "" || len(cfg.Ignored) != 0 {
		t.Fatalf("a missing probed file must yield the zero config, got %+v", cfg)
	}
}

func TestProbeReadsAPresentFile(t *testing.T) {
	path := writeConfig(t, `storage { allowed_host_paths = ["/srv/kanea", "/dev/shm"] }`, 0o644)
	cfg, err := Probe(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/srv/kanea", "/dev/shm"}
	if len(cfg.AllowedHostPaths) != len(want) {
		t.Fatalf("got %v, want %v", cfg.AllowedHostPaths, want)
	}
	for i, p := range want {
		if cfg.AllowedHostPaths[i] != p {
			t.Fatalf("got %v, want %v", cfg.AllowedHostPaths, want)
		}
	}
	if cfg.Path != path {
		t.Fatalf("Path = %q, want %q", cfg.Path, path)
	}
}

func TestProbeAnUnreadableDirectoryIsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "kanea.hcl")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := Probe(path); err == nil {
		t.Fatal("a stat failure that is not ErrNotExist must be an error, not \"off\"")
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "kanea.hcl")); err == nil {
		t.Fatal("an explicitly named missing file must be an error")
	}
}

func TestLoadRefusesAnEmptyPath(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("Load with no path must be an error; Probe is the absent-tolerant door")
	}
}

func TestParseRefusesMalformedHCL(t *testing.T) {
	if _, err := Parse("kanea.hcl", []byte(`storage {`)); err == nil {
		t.Fatal("malformed HCL must be an error")
	}
}

func TestParseRefusesAnUnknownAttributeInsideStorage(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(`storage { allowed_host_pathz = ["/srv"] }`))
	if err == nil {
		t.Fatal("a typo inside a read stanza must be an error, not a warning")
	}
}

func TestParseRefusesANestedBlockInsideStorage(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(`storage { nfs { server = "x" } }`))
	if err == nil {
		t.Fatal("an unknown nested block inside a read stanza must be an error")
	}
}

func TestParseRefusesDuplicateStorageBlocks(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(
		`storage { allowed_host_paths = ["/a"] }
storage { allowed_host_paths = ["/b"] }`))
	if err == nil {
		t.Fatal("two storage stanzas must be an error")
	}
}

func TestParseAnEmptyFileIsAnEmptyConfig(t *testing.T) {
	cfg, err := Parse("kanea.hcl", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowedHostPaths != nil || len(cfg.Ignored) != 0 {
		t.Fatalf("got %+v, want the zero config", cfg)
	}
}

// TestParseWarnsUnreadStanzasByName pins the middle road between the two
// failure modes: PRD §15.1's own sketch must load (an operator writing ahead
// of the implementation is not typoing), and what is not read must be named
// (a stanza that vanishes silently is the jobspec-root trap).
func TestParseWarnsUnreadStanzasByName(t *testing.T) {
	src := `
cluster_id  = ""
tls_default = "acme"

bind { api_addr = "127.0.0.1:8600" }
acme { email = "ops@example.com" }

storage { allowed_host_paths = ["/srv/kanea"] }

device "gpu" {
  nodes = ["/dev/dri/renderD128"]
  allow = ["media"]
}

socket "containerd" {
  path  = "/run/kanea/containerd.sock"
  allow = ["ops"]
}
`
	cfg, err := Parse("kanea.hcl", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"acme", "bind", "cluster_id", "tls_default"}
	if len(cfg.Ignored) != len(want) {
		t.Fatalf("Ignored = %v, want %v", cfg.Ignored, want)
	}
	for i, name := range want {
		if cfg.Ignored[i] != name {
			t.Fatalf("Ignored = %v, want %v", cfg.Ignored, want)
		}
	}
	// device and socket are read — by internal/passthrough, over the same
	// bytes — and must never show up as ignored.
	for _, name := range cfg.Ignored {
		if name == "device" || name == "socket" || name == "storage" {
			t.Fatalf("%q is a read stanza and must not be reported ignored", name)
		}
	}
	if len(cfg.AllowedHostPaths) != 1 || cfg.AllowedHostPaths[0] != "/srv/kanea" {
		t.Fatalf("AllowedHostPaths = %v", cfg.AllowedHostPaths)
	}
}

func TestCheckTrustedAcceptsARootStyleFile(t *testing.T) {
	path := writeConfig(t, "", 0o644)
	if err := CheckTrusted(path); err != nil {
		t.Fatalf("a 0644 self-owned file must pass: %v", err)
	}
}

func TestCheckTrustedRefusesWritableFiles(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		path := writeConfig(t, "", mode)
		err := CheckTrusted(path)
		if err == nil {
			t.Fatalf("mode %04o must be refused", mode)
		}
		if !strings.Contains(err.Error(), "writable") {
			t.Fatalf("the refusal must say why: %v", err)
		}
	}
}

func TestCheckTrustedRefusesADirectory(t *testing.T) {
	if err := CheckTrusted(t.TempDir()); err == nil {
		t.Fatal("a directory must be refused")
	}
}

func TestCheckTrustedRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.hcl")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "kanea.hcl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrusted(link); err == nil {
		t.Fatal("a symlink must be refused; this check cannot vouch for the target's directory")
	}
}

func TestCheckTrustedRefusesAForeignOwner(t *testing.T) {
	// Exercised on the unexported core: making a file owned by another uid
	// needs root, and the rule is arithmetic on three values either way.
	if err := checkTrustedInfo(0o644, 12345, 1000); err == nil {
		t.Fatal("a file owned by neither root nor the daemon's uid must be refused")
	}
	if err := checkTrustedInfo(0o644, 0, 1000); err != nil {
		t.Fatalf("root-owned must pass: %v", err)
	}
	if err := checkTrustedInfo(0o644, 1000, 1000); err != nil {
		t.Fatalf("self-owned must pass: %v", err)
	}
}

// TestDefaultPathAgreesWithProvision pins the literal against the layout
// package: the config directory has one authority, and this constant must
// never drift from it.
func TestDefaultPathAgreesWithProvision(t *testing.T) {
	if want := provision.DefaultConfDir + "/kanea.hcl"; DefaultPath != want {
		t.Fatalf("DefaultPath = %q, want %q", DefaultPath, want)
	}
}
