package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// The listener comes from the bind stanza alone (v1.115). What this pins is
// the resolution kanead does on top of the parse: an unset api_tls with a
// pair means provided, and a self-signed certificate is named for the
// address's host when api_domain is absent.
func TestAPIListenFromConfig(t *testing.T) {
	bind := func(b nodeconfig.BindConfig) *nodeconfig.Config {
		return &nodeconfig.Config{Path: "/etc/kanea/kanea.hcl", Bind: &b}
	}
	tests := []struct {
		name string
		cfg  *nodeconfig.Config
		want apiListener
	}{
		{"no stanza is socket-only", &nodeconfig.Config{}, apiListener{}},
		{"a bind block with no api_addr supplies nothing",
			bind(nodeconfig.BindConfig{EdgeHTTP: ":8080"}), apiListener{}},
		{"a pair with no mode means provided",
			bind(nodeconfig.BindConfig{APIAddr: "192.168.1.10:8600",
				APICert: "/etc/kanea/dash.crt", APIKey: "/etc/kanea/dash.key"}),
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSProvided,
				cert: "/etc/kanea/dash.crt", key: "/etc/kanea/dash.key"}},
		{"loopback with no mode stays unresolved, for the listener's own rule",
			bind(nodeconfig.BindConfig{APIAddr: "127.0.0.1:8600"}),
			apiListener{addr: "127.0.0.1:8600"}},
		{"self-signed names api_domain when given",
			bind(nodeconfig.BindConfig{APIAddr: "192.168.1.10:8600",
				APITLS: nodeconfig.TLSSelfSigned, APIDomain: "kanea.home.arpa"}),
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSSelfSigned,
				domain: "kanea.home.arpa"}},
		{"self-signed falls back to the address's host",
			bind(nodeconfig.BindConfig{APIAddr: "192.168.1.10:8600", APITLS: nodeconfig.TLSSelfSigned}),
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSSelfSigned,
				domain: "192.168.1.10"}},
		{"acme carries its domain",
			bind(nodeconfig.BindConfig{APIAddr: ":8600", APITLS: nodeconfig.TLSAcme,
				APIDomain: "kanea.example.com"}),
			apiListener{addr: ":8600", mode: nodeconfig.TLSAcme, domain: "kanea.example.com"}},
		{"plaintext is carried, not resolved away",
			bind(nodeconfig.BindConfig{APIAddr: "192.168.1.10:8600", APITLS: nodeconfig.TLSPlaintext}),
			apiListener{addr: "192.168.1.10:8600", mode: nodeconfig.TLSPlaintext}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiListenFromConfig(tt.cfg); got != tt.want {
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

// The init side (v1.61): a listener already in the file skips the prompt and
// is left as written, and it meets the same beyond-loopback refusal a typed
// address meets, at the file's coordinates.
func TestListenFromNodeConfig(t *testing.T) {
	tls := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
		APIAddr: "192.168.1.10:8600", APICert: "/c", APIKey: "/k"}}
	plain := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
		APIAddr: "192.168.1.10:8600"}}
	loopback := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
		APIAddr: "127.0.0.1:8600"}}

	if addr, owned, err := listenFromNodeConfig(tls, false); err != nil || !owned || addr != "192.168.1.10:8600" {
		t.Fatalf("a declared bind with its pair must own the listener: %q %v %v", addr, owned, err)
	}
	if addr, owned, err := listenFromNodeConfig(loopback, false); err != nil || !owned || addr != "127.0.0.1:8600" {
		t.Fatalf("loopback needs no pair: %q %v %v", addr, owned, err)
	}
	if _, _, err := listenFromNodeConfig(plain, false); err == nil {
		t.Fatal("beyond loopback without a pair must be refused")
	}
	// A declared mode is a TLS story (or a typed plaintext decision), so the
	// beyond-loopback refusal does not apply (v1.61).
	for _, mode := range []string{
		nodeconfig.TLSSelfSigned, nodeconfig.TLSPlaintext,
	} {
		cfg := &nodeconfig.Config{Path: "kanea.hcl", Bind: &nodeconfig.BindConfig{
			APIAddr: "192.168.1.10:8600", APITLS: mode}}
		if _, owned, err := listenFromNodeConfig(cfg, false); err != nil || !owned {
			t.Fatalf("api_tls %q must own the listener: %v %v", mode, owned, err)
		}
	}
	if _, owned, err := listenFromNodeConfig(tls, true); err != nil || owned {
		t.Fatalf("an explicit --listen must replace the file's listener: %v %v", owned, err)
	}
	if _, owned, err := listenFromNodeConfig(&nodeconfig.Config{}, false); err != nil || owned {
		t.Fatalf("no file must mean the prompt flow: %v %v", owned, err)
	}
}

// createLayout gained the config directory in v1.51: kanea.hcl needs
// somewhere to be created, and init is what makes the directories. 0755,
// because the edge's unprivileged user reads the file inside it.
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
