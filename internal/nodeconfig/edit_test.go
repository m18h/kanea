package nodeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func mustEditor(t *testing.T, src string) *Editor {
	t.Helper()
	e, err := NewEditor("kanea.hcl", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEditorSetCreatesNestedBlocks(t *testing.T) {
	e := mustEditor(t, "")
	e.Set(cty.StringVal("/var/lib/kanea"), "data_dir")
	e.Set(cty.StringVal("10.244.0.0/24"), "network", "node_cidr")
	e.Set(cty.StringVal("s3://bucket/prefix"), "backup", "s3", "url")
	e.Set(cty.True, "backup", "restore_if_empty")
	e.Set(cty.ListVal([]cty.Value{cty.StringVal("1.1.1.1")}), "dns", "upstreams")

	cfg, err := Parse("kanea.hcl", e.Bytes())
	if err != nil {
		t.Fatalf("an edited document must still load: %v\n%s", err, e.Bytes())
	}
	if cfg.DataDir != "/var/lib/kanea" || cfg.Network.NodeCIDR != "10.244.0.0/24" ||
		cfg.Backup.S3.URL != "s3://bucket/prefix" || cfg.Backup.RestoreIfEmpty == nil ||
		!*cfg.Backup.RestoreIfEmpty || len(cfg.DNSUpstreams) != 1 {
		t.Fatalf("got %+v\n%s", cfg, e.Bytes())
	}
	// One backup block, not one per Set.
	if n := strings.Count(string(e.Bytes()), "backup {"); n != 1 {
		t.Fatalf("%d backup blocks:\n%s", n, e.Bytes())
	}
	if !e.Has("backup", "s3", "url") || e.Has("backup", "s3", "region") || e.Has("acme", "email") {
		t.Fatal("Has must report exactly what is written")
	}
}

func TestEditorEditsInPlaceAndKeepsComments(t *testing.T) {
	const src = `# The node's subnets. Do not renumber.
network {
  bpf_dir   = "/sys/fs/bpf/kanea" # the pin root
  node_cidr = "10.244.0.0/24"
}

# why this address: the LAN side
bind {
  api_addr = "192.168.1.10:8600"
}
`
	e := mustEditor(t, src)
	e.Set(cty.StringVal("10.9.0.0/24"), "network", "node_cidr")
	e.Unset("bind", "api_addr")
	e.Unset("bind", "api_cert") // absent: a no-op
	e.Unset("acme", "email")    // absent block: a no-op

	got := string(e.Bytes())
	for _, want := range []string{
		"# The node's subnets. Do not renumber.",
		`bpf_dir   = "/sys/fs/bpf/kanea" # the pin root`,
		`node_cidr = "10.9.0.0/24"`,
		"# why this address: the LAN side",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "192.168.1.10") || strings.Contains(got, "10.244.0.0/24") {
		t.Errorf("the old values survived:\n%s", got)
	}
	if strings.Contains(got, "acme") {
		t.Errorf("Unset must not create a block:\n%s", got)
	}
}

// An untouched document renders byte-identically, which is what lets a caller
// compare bytes to decide whether to write at all (steady state writes
// nothing).
func TestEditorLeavesACanonicalDocumentAlone(t *testing.T) {
	const src = `data_dir = "/var/lib/kanea"

network {
  bpf_dir = "/sys/fs/bpf/kanea"
}
`
	e := mustEditor(t, src)
	e.Set(cty.StringVal("/var/lib/kanea"), "data_dir")
	e.Set(cty.StringVal("/sys/fs/bpf/kanea"), "network", "bpf_dir")
	if got := string(e.Bytes()); got != src {
		t.Fatalf("got:\n%q\nwant:\n%q", got, src)
	}
}

func TestEditorMovesLabelledBlocksVerbatim(t *testing.T) {
	const side = `# grants for the media box
device "gpu" {
  nodes = ["/dev/dri/renderD128"] # the iGPU
  allow = ["media"]
}

socket "containerd" {
  path  = "/run/kanea/containerd.sock"
  allow = ["ops"]
}

provider "vault" "infra" {
  address    = "https://vault.internal:8200"
  token_file = "/etc/kanea/secrets/vault.token"
  allow      = ["media"]
  sync {
    path  = "apps/media"
    field = "s3_secret_key"
    to    = "media/s3-secret"
  }
}
`
	e := mustEditor(t, `data_dir = "/var/lib/kanea"`+"\n"+`device "old" {`+"\n"+`  nodes = ["/dev/null"]`+"\n"+`  allow = ["x"]`+"\n}\n")
	e.RemoveBlocks("device")
	if err := e.AppendBlocksFrom("side.hcl", []byte(side), "device", "provider"); err != nil {
		t.Fatal(err)
	}
	got := string(e.Bytes())
	for _, want := range []string{
		`device "gpu" {`, `nodes = ["/dev/dri/renderD128"] # the iGPU`,
		`provider "vault" "infra" {`, `to    = "media/s3-secret"`, "sync {",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, `device "old"`) {
		t.Errorf("RemoveBlocks left the old grant:\n%s", got)
	}
	if strings.Contains(got, "socket") {
		t.Errorf("a block type that was not asked for was copied:\n%s", got)
	}
	if _, err := Parse("kanea.hcl", e.Bytes()); err != nil {
		t.Fatalf("the result must load: %v\n%s", err, got)
	}

	if err := e.AppendBlocksFrom("bad.hcl", []byte(`device "x" {`), "device"); err == nil {
		t.Fatal("a side file that does not parse must be an error")
	}
}

func TestWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	const good = `base_domain = "home.lan"` + "\n"
	if err := WriteFile(path, []byte(good)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %04o, want 0644: the edge's user must be able to read it", info.Mode().Perm())
	}
	// What it wrote, the daemons accept, trust check included.
	if cfg, err := Load(path); err != nil || cfg.BaseDomain != "home.lan" {
		t.Fatalf("Load = %+v, %v", cfg, err)
	}

	// A document the daemons would refuse is never written, and the file
	// that was there is untouched.
	for _, bad := range []string{`base_domain = `, `network { node_cdir = "x" }`, `audit { retention = "x" }`} {
		if err := WriteFile(path, []byte(bad)); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != good {
		t.Fatalf("the old file must survive a refused write: %q, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("a refused write left something behind: %v", entries)
	}
}
