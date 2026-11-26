package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// initWrite is what `kanea init` hands writeNodeConfig on a node given no
// flags: every effective value is the default.
func initWrite(path string, source []byte) nodeConfigWrite {
	return nodeConfigWrite{
		path: path, source: source, explicit: map[string]bool{},
		dataDir: "/var/lib/kanea", logDir: "/var/log/kanea/allocs",
		network: "ebpf", nodeCIDR: "10.244.0.0/24", clusterCIDR: "10.244.0.0/16",
		listener: &listenDecision{addr: "127.0.0.1:8600"},
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304; a test path
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// The file a fresh node gets. Compared whole: this is the first thing an
// operator opens, and what it pins is what the unit's ExecStart used to pin,
// so a release that changes a default cannot renumber a running node.
func TestWriteNodeConfigOnAFreshNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := writeNodeConfig(newOut(), initWrite(path, nil)); err != nil {
		t.Fatal(err)
	}
	const want = `data_dir      = "/var/lib/kanea"
alloc_log_dir = "/var/log/kanea/allocs"

network {
  driver       = "ebpf"
  node_cidr    = "10.244.0.0/24"
  cluster_cidr = "10.244.0.0/16"
}

edge {
  certs_group = "kanea-edge"
}

bind {
  api_addr = "127.0.0.1:8600"
}
`
	if got := string(mustRead(t, path)); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// And it is a file both daemons accept, with nothing in it unread.
	cfg, err := nodeconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ignored) != 0 {
		t.Fatalf("init wrote something nothing reads: %v", cfg.Ignored)
	}
	// The bundle's group, which the unit used to pass: without it the edge's
	// own user cannot read the certificates it serves.
	if resolveAgentSettings(cfg).edgeGroup != "kanea-edge" {
		t.Fatal("a fresh node's config does not name the edge's group for the certificate bundle")
	}
}

// Steady state writes nothing: a second init with no flags must not touch
// the file, whoever owns the listener by then.
func TestWriteNodeConfigRerunWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := writeNodeConfig(newOut(), initWrite(path, nil)); err != nil {
		t.Fatal(err)
	}
	first := mustRead(t, path)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// The second run finds bind.api_addr in the file, so the file owns the
	// listener and init passes no decision.
	again := initWrite(path, first)
	again.listener = nil
	if err := writeNodeConfig(newOut(), again); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(mustRead(t, path)) != string(first) {
		t.Fatal("a re-run with no flags changed the file")
	}
	// The write is a rename, so an untouched file keeps its inode's mtime.
	if !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) {
		t.Fatal("a re-run with no flags rewrote an identical file")
	}
}

func TestWriteNodeConfigChangesOnlyWhatWasTyped(t *testing.T) {
	const existing = `# This node's identity. Renumbering needs every alloc restarted.
data_dir      = "/srv/kanea"
alloc_log_dir = "/srv/kanea/logs"

network {
  driver       = "ebpf"
  node_cidr    = "10.50.0.0/24" # was the lab range
  cluster_cidr = "10.50.0.0/16"
}

bind {
  api_addr   = "192.168.1.10:8600"
  api_tls    = "self-signed"
  api_domain = "kanea.home.arpa"
  edge_http  = ":8080"
}

edge {
  certs_group = "www-data"
}

base_domain = "home.arpa"
`
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	// `kanea init --node-cidr 10.50.9.0/24`: the effective values are the
	// file's own, except the one flag.
	w := nodeConfigWrite{
		path: path, source: []byte(existing),
		explicit: map[string]bool{"node-cidr": true},
		dataDir:  "/srv/kanea", logDir: "/srv/kanea/logs",
		network: "ebpf", nodeCIDR: "10.50.9.0/24", clusterCIDR: "10.50.0.0/16",
		// The file owns the listener: no --listen was typed.
		listener: nil,
	}
	if err := writeNodeConfig(newOut(), w); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(existing,
		`node_cidr    = "10.50.0.0/24" # was the lab range`,
		`node_cidr    = "10.50.9.0/24" # was the lab range`, 1)
	if got := string(mustRead(t, path)); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// An explicit --listen replaces the API half of bind whole: an api_tls that
// described the old address must not outlive it. The edge half is not init's
// to touch.
func TestWriteNodeConfigReplacesTheListenerWhole(t *testing.T) {
	const existing = `bind {
  api_addr   = "192.168.1.10:8600"
  api_tls    = "acme"
  api_domain = "kanea.example.com"
  edge_http  = ":8080"
}
`
	for _, tc := range []struct {
		name     string
		listener listenDecision
		want     []string
		gone     []string
	}{
		{"a new address with its pair",
			listenDecision{addr: "10.0.0.5:8600", cert: "/etc/kanea/api.crt", key: "/etc/kanea/api.key"},
			[]string{`api_addr = "10.0.0.5:8600"`, `api_cert = "/etc/kanea/api.crt"`, `api_key = "/etc/kanea/api.key"`, `edge_http = ":8080"`},
			[]string{"api_tls", "api_domain", "192.168.1.10"}},
		{"none retires the listener",
			listenDecision{},
			[]string{`edge_http = ":8080"`},
			[]string{"api_addr", "api_tls", "api_domain", "api_cert"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kanea.hcl")
			w := initWrite(path, []byte(existing))
			w.explicit = map[string]bool{"listen": true}
			w.listener = &tc.listener
			if err := writeNodeConfig(newOut(), w); err != nil {
				t.Fatal(err)
			}
			// Alignment whitespace is the formatter's; compare without it.
			got := strings.Join(strings.Fields(string(mustRead(t, path))), " ")
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in: %s", want, got)
				}
			}
			for _, gone := range tc.gone {
				if strings.Contains(got, gone) {
					t.Errorf("%q survived in: %s", gone, got)
				}
			}
			if _, err := nodeconfig.Load(path); err != nil {
				t.Fatalf("the result must load: %v", err)
			}
		})
	}
}

// The dual-stack trio has no defaults: it is written when asked for and
// never as three empty strings, which kanead would refuse as half a trio.
func TestWriteNodeConfigWritesTheV6TrioOnlyWhenTyped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := writeNodeConfig(newOut(), initWrite(path, nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustRead(t, path)), "cidr6") {
		t.Fatalf("a v4-only node's config mentions a v6 subnet:\n%s", mustRead(t, path))
	}

	w := initWrite(path, mustRead(t, path))
	w.listener = nil
	w.explicit = map[string]bool{"node-cidr6": true, "cluster-cidr6": true, "service-cidr6": true}
	w.nodeCIDR6, w.clusterCIDR6, w.serviceCIDR6 = "fd10:244::/64", "fd10:244::/56", "fd10:245::/64"
	if err := writeNodeConfig(newOut(), w); err != nil {
		t.Fatal(err)
	}
	cfg, err := nodeconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.NodeCIDR6 != "fd10:244::/64" || cfg.Network.ClusterCIDR6 != "fd10:244::/56" ||
		cfg.Network.ServiceCIDR6 != "fd10:245::/64" {
		t.Fatalf("network = %+v", cfg.Network)
	}
}
