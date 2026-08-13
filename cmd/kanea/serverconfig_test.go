package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/m18h/kanea/internal/nodeconfig"
)

func writeServerConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerConfigProbesTheWellKnownPath(t *testing.T) {
	path := writeServerConfig(t, `storage { allowed_host_paths = ["/srv"] }`)
	cfg, err := serverConfigForRun("", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedHostPaths) != 1 || cfg.AllowedHostPaths[0] != "/srv" {
		t.Fatalf("AllowedHostPaths = %v", cfg.AllowedHostPaths)
	}
}

func TestServerConfigAbsentIsOff(t *testing.T) {
	cfg, err := serverConfigForRun("", filepath.Join(t.TempDir(), "kanea.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != "" || cfg.AllowedHostPaths != nil {
		t.Fatalf("an absent well-known file must be off, got %+v", cfg)
	}
}

func TestServerConfigOffIgnoresAPresentFile(t *testing.T) {
	path := writeServerConfig(t, `this is not hcl at all {{{`)
	cfg, err := serverConfigForRun("off", path)
	if err != nil {
		t.Fatalf("--config off must not read the file: %v", err)
	}
	if cfg.Path != "" {
		t.Fatalf("got %+v, want the zero config", cfg)
	}
}

func TestServerConfigExplicitPathMustExist(t *testing.T) {
	if _, err := serverConfigForRun(filepath.Join(t.TempDir(), "x.hcl"), ""); err == nil {
		t.Fatal("--config naming a missing file must be fatal")
	}
}

func TestServerConfigMalformedProbedFileIsFatal(t *testing.T) {
	path := writeServerConfig(t, `storage {`)
	if _, err := serverConfigForRun("", path); err == nil {
		t.Fatal("a malformed probed file must refuse startup, not half-load")
	}
}

// The v1.51/v1.61 all-halves probe-skip is retired (v1.63): the variables
// stanza is a file-only half with no flag, so the file is probed whenever
// --config does not say off — flags or no flags. A node that never wanted the
// file read says --config off, the whole-file switch it has always been.
func TestServerConfigProbesTheFileEvenWhenEveryFlaggedHalfIsFlagged(t *testing.T) {
	path := writeServerConfig(t, `variables { domain = "home.lan" }`)
	cfg, err := serverConfigForRun("", path)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if cfg.Variables["domain"] != "home.lan" {
		t.Fatalf("the variables stanza was not read: %+v", cfg)
	}
	// A malformed file is fatal on the probe — there is no flag set that
	// makes it unread short of --config off.
	bad := writeServerConfig(t, `garbage {{{`)
	if _, err := serverConfigForRun("", bad); err == nil {
		t.Fatal("a malformed probed file must refuse startup")
	}
	if cfg, err := serverConfigForRun("off", bad); err != nil || cfg.Path != "" {
		t.Fatalf("--config off must skip the file entirely: %+v %v", cfg, err)
	}
}

func TestResolveAPIListenPrecedence(t *testing.T) {
	fileCfg := &nodeconfig.Config{
		Path: "/etc/kanea/kanea.hcl",
		Bind: &nodeconfig.BindConfig{
			APIAddr: "192.168.1.10:8600",
			APICert: "/etc/kanea/dash.crt", APIKey: "/etc/kanea/dash.key",
		},
	}
	tests := []struct {
		name                    string
		flag, certFlag, keyFlag string
		cfg                     *nodeconfig.Config
		want                    apiListener
	}{
		{"a set flag wins, pair and all", "10.0.0.1:9000", "/c", "/k", fileCfg,
			apiListener{addr: "10.0.0.1:9000", mode: nodeconfig.TLSProvided,
				cert: "/c", key: "/k", source: "--listen"}},
		{"a set flag with no pair keeps the flags' vocabulary", "127.0.0.1:8600", "", "", fileCfg,
			apiListener{addr: "127.0.0.1:8600", source: "--listen"}},
		{"none is the explicit socket-only", "none", "", "", fileCfg,
			apiListener{source: "none"}},
		{"unset flag reads the file, atomically", "", "/ignored-cert", "/ignored-key", fileCfg,
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSProvided,
				cert: "/etc/kanea/dash.crt", key: "/etc/kanea/dash.key", source: fileCfg.Path}},
		{"no flag and no stanza is socket-only", "", "", "", &nodeconfig.Config{},
			apiListener{}},
		{"a bind block with no api_addr supplies nothing", "", "", "",
			&nodeconfig.Config{Path: "/etc/kanea/kanea.hcl", Bind: &nodeconfig.BindConfig{}},
			apiListener{}},
		{"self-signed names api_domain when given", "", "", "",
			&nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
				APIAddr: "192.168.1.10:8600", APITLS: nodeconfig.TLSSelfSigned,
				APIDomain: "kanea.home.arpa"}},
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSSelfSigned,
				domain: "kanea.home.arpa", source: "kanea.hcl"}},
		{"self-signed falls back to the address's host", "", "", "",
			&nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
				APIAddr: "192.168.1.10:8600", APITLS: nodeconfig.TLSSelfSigned}},
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSSelfSigned,
				domain: "192.168.1.10", source: "kanea.hcl"}},
		{"acme carries its domain", "", "", "",
			&nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
				APIAddr: ":8600", APITLS: nodeconfig.TLSAcme,
				APIDomain: "kanea.example.com"}},
			apiListener{addr: ":8600", mode: nodeconfig.TLSAcme,
				domain: "kanea.example.com", source: "kanea.hcl"}},
		{"plaintext is carried, not resolved away", "", "", "",
			&nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
				APIAddr: "192.168.1.10:8600", APITLS: nodeconfig.TLSPlaintext}},
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSPlaintext,
				source: "kanea.hcl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveAPIListen(tt.flag, tt.certFlag, tt.keyFlag, tt.cfg); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// tlsEnabled feeds the Settings page's read-only view: every mode that
// carries a certificate reads true, plaintext and the bare-loopback default
// read false.
func TestAPIListenerTLSEnabled(t *testing.T) {
	if (apiListener{mode: nodeconfig.TLSPlaintext}).tlsEnabled() {
		t.Fatal("plaintext must not claim TLS")
	}
	if (apiListener{}).tlsEnabled() {
		t.Fatal("the socket-only zero value must not claim TLS")
	}
	for _, l := range []apiListener{
		{mode: nodeconfig.TLSAcme, domain: "d"},
		{mode: nodeconfig.TLSSelfSigned, domain: "d"},
		{mode: nodeconfig.TLSProvided, cert: "/c", key: "/k"},
	} {
		if !l.tlsEnabled() {
			t.Fatalf("%+v must claim TLS", l)
		}
	}
}

// The init-side half of the same precedence (v1.61): a file-declared listener
// skips the prompt and renders no listen flags — and meets the same
// beyond-loopback refusal the flags meet, at the file's coordinates.
func TestListenFromServerConfig(t *testing.T) {
	tls := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
		APIAddr: "192.168.1.10:8600", APICert: "/c", APIKey: "/k"}}
	plain := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
		APIAddr: "192.168.1.10:8600"}}
	loopback := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
		APIAddr: "127.0.0.1:8600"}}

	if addr, owned, err := listenFromServerConfig(tls, false); err != nil || !owned || addr != "192.168.1.10:8600" {
		t.Fatalf("a declared bind with its pair must own the listener: %q %v %v", addr, owned, err)
	}
	if addr, owned, err := listenFromServerConfig(loopback, false); err != nil || !owned || addr != "127.0.0.1:8600" {
		t.Fatalf("loopback needs no pair: %q %v %v", addr, owned, err)
	}
	if _, _, err := listenFromServerConfig(plain, false); err == nil {
		t.Fatal("beyond loopback without a pair must be refused, file or flag alike")
	}
	// A declared mode is a TLS story (or a typed plaintext decision), so the
	// beyond-loopback refusal does not apply (v1.61).
	for _, mode := range []string{
		nodeconfig.TLSSelfSigned, nodeconfig.TLSPlaintext,
	} {
		cfg := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
			APIAddr: "192.168.1.10:8600", APITLS: mode}}
		if _, owned, err := listenFromServerConfig(cfg, false); err != nil || !owned {
			t.Fatalf("api_tls %q must own the listener: %v %v", mode, owned, err)
		}
	}
	if _, owned, err := listenFromServerConfig(tls, true); err != nil || owned {
		t.Fatalf("an explicit --listen must win over the file: %v %v", owned, err)
	}
	if _, owned, err := listenFromServerConfig(&nodeconfig.Config{}, false); err != nil || owned {
		t.Fatalf("no file must mean the prompt flow: %v %v", owned, err)
	}
}

func TestResolveHostPathsPrecedence(t *testing.T) {
	cfg := &nodeconfig.Config{AllowedHostPaths: []string{"/from-file"}, Path: "/etc/kanea/kanea.hcl"}

	paths, source := resolveHostPaths("", cfg)
	if len(paths) != 1 || paths[0] != "/from-file" || source != cfg.Path {
		t.Fatalf("unset flag must read the file: %v %q", paths, source)
	}

	paths, source = resolveHostPaths("/a,/b", cfg)
	if len(paths) != 2 || paths[0] != "/a" || source != "--allowed-host-paths" {
		t.Fatalf("a set flag must win: %v %q", paths, source)
	}

	paths, source = resolveHostPaths("off", cfg)
	if paths != nil || source != "off" {
		t.Fatalf("off must disable regardless of the file: %v %q", paths, source)
	}
}

func TestResolvePassthroughPathPrecedence(t *testing.T) {
	grantFile := writeServerConfig(t, ``)
	cfg := &nodeconfig.Config{HasGrants: true, Path: "/etc/kanea/kanea.hcl"}

	path, source, err := resolvePassthroughPath("", cfg)
	if err != nil || path != cfg.Path || source != cfg.Path {
		t.Fatalf("unset flag must read grants from the server config: %q %q %v", path, source, err)
	}

	path, source, err = resolvePassthroughPath("", &nodeconfig.Config{})
	if err != nil || path != "" || source != "" {
		t.Fatalf("no file and no flag must mean no grants: %q %q %v", path, source, err)
	}

	path, source, err = resolvePassthroughPath(grantFile, cfg)
	if err != nil || path != grantFile || source != "--passthrough-config" {
		t.Fatalf("a set flag must win: %q %q %v", path, source, err)
	}

	path, source, err = resolvePassthroughPath("off", cfg)
	if err != nil || path != "" || source != "off" {
		t.Fatalf("off must disable regardless of the file: %q %q %v", path, source, err)
	}
}

// The trust check does not weaken because the path arrived by argv: a
// group-writable grants file is the same hole flagged or probed.
func TestResolvePassthroughPathRefusesAnUntrustedFlaggedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pt.hcl")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolvePassthroughPath(path, &nodeconfig.Config{}); err == nil {
		t.Fatal("a world-writable grants file must be refused")
	}
}

// createLayout gained the config directory in v1.51: the probed kanea.hcl
// needs somewhere to be created, and init is what makes the directories.
func TestCreateLayoutMakesTheConfDir(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	logDir := filepath.Join(base, "logs")
	confDir := filepath.Join(base, "etc", "kanea")
	if err := createLayout(newOut(), dataDir, logDir, confDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(confDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("conf dir mode = %04o, want 0755", perm)
	}
}
