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

func TestParseReadsTheBindStanza(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`
bind {
  api_addr = " 192.168.1.10:8600 "
  api_cert = "/etc/kanea/dash.crt"
  api_key  = "/etc/kanea/dash.key"
}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bind == nil {
		t.Fatal("Bind = nil, want the stanza")
	}
	if cfg.Bind.APIAddr != "192.168.1.10:8600" ||
		cfg.Bind.APICert != "/etc/kanea/dash.crt" || cfg.Bind.APIKey != "/etc/kanea/dash.key" {
		t.Fatalf("Bind = %+v", cfg.Bind)
	}
	if len(cfg.Ignored) != 0 {
		t.Fatalf("a fully read bind stanza must warn nothing, got %v", cfg.Ignored)
	}
}

func TestParseRefusesACertWithoutAKeyInBind(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(bindHCL(`api_addr = "192.168.1.10:8600"`, `api_cert = "/c"`)))
	if err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("bind.api_cert without bind.api_key must be refused by name, got %v", err)
	}
}

func TestParseRefusesATLSPairWithNoAddrInBind(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(bindHCL(`api_cert = "/c"`, `api_key = "/k"`)))
	if err == nil || !strings.Contains(err.Error(), "no api_addr") {
		t.Fatalf("a TLS pair with no api_addr to serve it on must be refused by name, got %v", err)
	}
}

// bindHCL renders a bind stanza one attribute per line: HCL's single-line
// block form takes at most one attribute, so a compact literal would fail on
// syntax and vacuously "pass" a refusal test for the wrong reason.
func bindHCL(attrs ...string) string {
	return "bind {\n  " + strings.Join(attrs, "\n  ") + "\n}\n"
}

// Every bind contradiction parse can see is refused with the file named
// (PRD v1.61). What resolution decides (an unset mode on a non-loopback
// address) deliberately parses clean; the daemon refuses that one.
func TestParseRefusesBindContradictions(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // a fragment the error must carry, so a syntax slip cannot pass as a refusal
	}{
		{"an unknown mode",
			bindHCL(`api_addr = "127.0.0.1:8600"`, `api_tls = "letsencrypt"`),
			"api_tls"},
		{"acme without a domain",
			bindHCL(`api_addr = ":8600"`, `api_tls = "acme"`),
			"api_domain"},
		{"acme beside a pair",
			bindHCL(`api_addr = ":8600"`, `api_tls = "acme"`, `api_domain = "d.example"`, `api_cert = "/c"`, `api_key = "/k"`),
			"issues its own certificate"},
		{"self-signed beside a pair",
			bindHCL(`api_addr = "127.0.0.1:8600"`, `api_tls = "self-signed"`, `api_cert = "/c"`, `api_key = "/k"`),
			"issues its own certificate"},
		{"self-signed on every interface with no name",
			bindHCL(`api_addr = "0.0.0.0:8600"`, `api_tls = "self-signed"`),
			"every interface"},
		{"self-signed on an empty host with no name",
			bindHCL(`api_addr = ":8600"`, `api_tls = "self-signed"`),
			"every interface"},
		{"plaintext beside a pair",
			bindHCL(`api_addr = "127.0.0.1:8600"`, `api_tls = "plaintext"`, `api_cert = "/c"`, `api_key = "/k"`),
			"drops the pair"},
		{"provided without a pair",
			bindHCL(`api_addr = "127.0.0.1:8600"`, `api_tls = "provided"`),
			"needs bind.api_cert"},
		{"a mode with no address",
			bindHCL(`api_tls = "self-signed"`),
			"no api_addr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("kanea.hcl", []byte(tt.src))
			if err == nil {
				t.Fatalf("%s must be refused", tt.src)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, tt.want)
			}
		})
	}
}

func TestParseAcceptsEveryCoherentBindMode(t *testing.T) {
	tests := []struct {
		name, src string
	}{
		{"acme with a domain",
			bindHCL(`api_addr = ":8600"`, `api_tls = "acme"`, `api_domain = "kanea.example.com"`)},
		{"self-signed on a concrete address",
			bindHCL(`api_addr = "192.168.1.10:8600"`, `api_tls = "self-signed"`)},
		{"self-signed on every interface with a name",
			bindHCL(`api_addr = ":8600"`, `api_tls = "self-signed"`, `api_domain = "kanea.home.arpa"`)},
		{"plaintext beyond loopback",
			bindHCL(`api_addr = "192.168.1.10:8600"`, `api_tls = "plaintext"`)},
		{"provided with its pair",
			bindHCL(`api_addr = ":8600"`, `api_tls = "provided"`, `api_cert = "/c"`, `api_key = "/k"`)},
		{"an unset mode beyond loopback parses; the daemon resolves it",
			bindHCL(`api_addr = "192.168.1.10:8600"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse("kanea.hcl", []byte(tt.src)); err != nil {
				t.Fatalf("%s: %v", tt.src, err)
			}
		})
	}
}

func TestParseRefusesAnUnknownAttributeInsideBind(t *testing.T) {
	if _, err := Parse("kanea.hcl", []byte(`bind { api_adr = "127.0.0.1:8600" }`)); err == nil {
		t.Fatal("a typo inside a read stanza must be an error, not a warning")
	}
}

// The sketch halves of a read stanza: edge_http/edge_https are §15.1's own
// example, so they load, and land in Ignored by their dotted names, because
// accepted-but-unread without a warning is exactly the silently-swallowed trap.
func TestParseNamesTheBindSketchHalvesAsIgnored(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`
bind {
  api_addr   = "127.0.0.1:8600"
  edge_http  = ":80"
  edge_https = ":443"
}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bind.edge_http", "bind.edge_https"}
	if len(cfg.Ignored) != len(want) || cfg.Ignored[0] != want[0] || cfg.Ignored[1] != want[1] {
		t.Fatalf("Ignored = %v, want %v", cfg.Ignored, want)
	}
	if cfg.Bind == nil || cfg.Bind.APIAddr != "127.0.0.1:8600" {
		t.Fatalf("the read half must still load: %+v", cfg.Bind)
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
	// bind left this list in v1.61: its api half is read now, so the sample's
	// api_addr-only block is consumed rather than warned.
	want := []string{"acme", "cluster_id", "tls_default"}
	if len(cfg.Ignored) != len(want) {
		t.Fatalf("Ignored = %v, want %v", cfg.Ignored, want)
	}
	for i, name := range want {
		if cfg.Ignored[i] != name {
			t.Fatalf("Ignored = %v, want %v", cfg.Ignored, want)
		}
	}
	// device and socket are read (by internal/passthrough, over the same
	// bytes) and must never show up as ignored.
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

func TestParseReadsTheVariablesStanza(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`
variables {
  domain   = "home.lan"
  replicas = 3
  debug    = true
}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]string{"domain": "home.lan", "replicas": "3", "debug": "true"}
	for k, v := range want {
		if cfg.Variables[k] != v {
			t.Errorf("Variables[%q] = %q, want %q", k, cfg.Variables[k], v)
		}
	}
	for _, name := range cfg.Ignored {
		if name == "variables" {
			t.Error("a read stanza must not be reported ignored")
		}
	}
}

func TestParseVariablesRefusals(t *testing.T) {
	cases := []struct{ name, src string }{
		{"reserved built-in", `variables { GIT_SHA_SHORT = "x" }`},
		{"reserved service", `variables { service = "x" }`},
		{"list value", `variables { domains = ["a"] }`},
		{"null value", `variables { domain = null }`},
		{"expression needing context", `variables { domain = "${other}" }`},
		{"two stanzas", "variables { a = \"1\" }\nvariables { b = \"2\" }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse("kanea.hcl", []byte(tc.src)); err == nil {
				t.Fatal("expected an error (present-but-malformed is fatal)")
			}
		})
	}
}

func TestParseAbsentVariablesStanzaIsNil(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`storage { allowed_host_paths = ["/srv"] }`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Variables != nil {
		t.Errorf("Variables = %v, want nil for an absent stanza", cfg.Variables)
	}
}

// ---- the dns stanza (v1.66) ----

func TestParseReadsTheDNSStanza(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`
dns {
  upstreams = ["1.1.1.1", "10.0.0.53:5353", " 9.9.9.9 "]
}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"1.1.1.1", "10.0.0.53:5353", "9.9.9.9"}
	if len(cfg.DNSUpstreams) != len(want) {
		t.Fatalf("upstreams = %v, want %v", cfg.DNSUpstreams, want)
	}
	for i, u := range want {
		if cfg.DNSUpstreams[i] != u {
			t.Fatalf("upstreams = %v, want %v", cfg.DNSUpstreams, want)
		}
	}
}

func TestParseWithoutADNSStanzaMeansTheHostsResolvers(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`storage { allowed_host_paths = ["/srv"] }`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.DNSUpstreams != nil {
		t.Fatalf("upstreams = %v, want nil when the stanza is absent", cfg.DNSUpstreams)
	}
}

func TestParseRefusesADNSUpstreamThatIsNotAnAddress(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(`dns { upstreams = ["not an address"] }`))
	if err == nil {
		t.Fatal("a non-address upstream must be an error at parse, not at the daemon")
	}
}

// An empty list configures nothing: a stanza that meant "no upstreams" would
// silently turn external resolution into SERVFAIL; the R21 dropped control.
func TestParseRefusesAnEmptyDNSUpstreamList(t *testing.T) {
	for _, src := range []string{
		`dns { upstreams = [] }`,
		`dns { upstreams = ["", "  "] }`,
		`dns { }`,
	} {
		if _, err := Parse("kanea.hcl", []byte(src)); err == nil {
			t.Fatalf("%s: an upstreams list that names nothing must be refused", src)
		}
	}
}

func TestParseRefusesAnUnknownAttributeInsideDNS(t *testing.T) {
	_, err := Parse("kanea.hcl", []byte(`dns { upstream = ["1.1.1.1"] }`))
	if err == nil {
		t.Fatal("a typo inside a read stanza must be an error, not a warning")
	}
}
