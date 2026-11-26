package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// TestSettingsDefaultsAreTheFormerFlagDefaults pins the promise v1.115 makes
// to a node that upgrades with no kanea.hcl: nothing changes. Every value
// below is what the removed flag defaulted to, written as a literal on
// purpose. A table built from the same constants settings.go reads would
// pass whatever those constants became; this one fails when a default moves,
// which is the moment somebody has to decide whether running nodes may move
// with it.
func TestSettingsDefaultsAreTheFormerFlagDefaults(t *testing.T) {
	got := resolveAgentSettings(&nodeconfig.Config{})
	want := agentSettings{
		dataDir:  "/var/lib/kanea",
		logDir:   "/var/log/kanea/allocs",
		logLevel: "info",

		socket:           "/run/kanea/kanead.sock",
		containerdSocket: "/run/kanea/containerd.sock",

		networkMode: "ebpf",
		bpfDir:      "/sys/fs/bpf/kanea",
		nodeCIDR:    "10.244.0.0/24",
		clusterCIDR: "10.244.0.0/16",
		serviceCIDR: "10.201.0.0/16",

		edgeRoutes:   "/run/kanea-edge/routes.json",
		edgeCerts:    "/run/kanea-edge/certs.json",
		publishPorts: "1024-65535",

		tlsDefault: "acme",

		acmeDirectory:    "production",
		acmeVerifyURL:    "http://127.0.0.1:80",
		acmeDNSAlgorithm: "hmac-sha256.",

		serveDashboard: true,
		auditRetention: 90 * 24 * time.Hour,

		oidcScopes:    []string{"profile", "email"},
		oidcRoleClaim: "groups",

		ldapUserFilter: "(uid=%s)",

		metricsInterval:   5 * time.Second,
		containerdMetrics: "http://127.0.0.1:1338/v1/metrics",
		edgeMetrics:       "http://127.0.0.1:8601/metrics",
		autoscale:         true,

		buildkit:     "unix:///var/lib/kanea/buildkit/run/buildkitd.sock",
		registryAddr: "127.0.0.1:5100",
		syncInterval: 2 * time.Minute,

		secretsSyncInterval: 5 * time.Minute,

		eventRetention: 500,

		backupS3PathStyle:     true,
		backupInterval:        6 * time.Hour,
		backupSegmentInterval: time.Minute,
		backupRetention:       7,

		// The two former environment variables: unset meant the project's
		// own repository and no signature requirement.
		upgradeRepo: "m18h/kanea",
	}
	if !reflect.DeepEqual(got, want) {
		diffSettings(t, got, want)
	}

	gotEdge := resolveEdgeSettings(&nodeconfig.EdgeFile{})
	wantEdge := edgeSettings{
		snapshot:          "/run/kanea-edge/routes.json",
		httpAddr:          ":80",
		httpsAddr:         ":443",
		certs:             "/run/kanea-edge/certs.json",
		statusAddr:        "127.0.0.1:8601",
		poll:              time.Second,
		drain:             15 * time.Second,
		maxPublishedConns: 1024,
		bodyTimeout:       5 * time.Minute,
		upstreamTimeout:   60 * time.Second,
		securityHeaders:   true,
		limiterCap:        1 << 16,
		logLevel:          "info",
	}
	if !reflect.DeepEqual(gotEdge, wantEdge) {
		diffSettings(t, gotEdge, wantEdge)
	}
}

// diffSettings names the fields that differ, because a %+v of two ninety-field
// structs is not something a person can read a regression out of.
func diffSettings(t *testing.T, got, want any) {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range g.NumField() {
		gf, wf := g.Field(i), w.Field(i)
		if !reflect.DeepEqual(valueOf(gf), valueOf(wf)) {
			t.Errorf("%s = %v, want %v", g.Type().Field(i).Name, valueOf(gf), valueOf(wf))
		}
	}
}

// valueOf reads an unexported field's value without Interface(), which
// reflect refuses for fields it did not obtain through an exported path.
func valueOf(v reflect.Value) any {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int64:
		return v.Int()
	case reflect.Slice:
		out := make([]string, v.Len())
		for i := range out {
			out[i] = v.Index(i).String()
		}
		return out
	default:
		return v.String()
	}
}

// What the file says wins over every default, and a written zero is a value:
// the pointer-typed attributes exist so "false", "0" and "0s" are not read
// as "not written".
func TestSettingsTakeTheFilesValues(t *testing.T) {
	cfg, err := nodeconfig.Parse("kanea.hcl", []byte(`
data_dir = "/srv/kanea"

bind {
  api_socket = "/run/kanea/alt.sock"
  edge_http  = ":8080"
}

dashboard {
  enabled = false
}

audit {
  retention = "0"
}

scaling {
  enabled = false
}

auth {
  oidc {
    scopes = []
  }
}

backup {
  retention = 30

  s3 {
    path_style = false
  }
}

upgrade {
  repo              = "someone/fork"
  require_signature = true
}
`))
	if err != nil {
		t.Fatal(err)
	}
	s := resolveAgentSettings(cfg)
	if s.dataDir != "/srv/kanea" || s.socket != "/run/kanea/alt.sock" {
		t.Errorf("dataDir = %q, socket = %q", s.dataDir, s.socket)
	}
	if s.serveDashboard || s.autoscale || s.backupS3PathStyle {
		t.Errorf("a written false must stay false: dashboard=%v autoscale=%v pathStyle=%v",
			s.serveDashboard, s.autoscale, s.backupS3PathStyle)
	}
	if s.auditRetention != 0 {
		t.Errorf("audit.retention = \"0\" must mean keep forever, got %s", s.auditRetention)
	}
	if s.oidcScopes == nil || len(s.oidcScopes) != 0 {
		t.Errorf("auth.oidc.scopes = [] must mean no extra scopes, got %v", s.oidcScopes)
	}
	if s.backupRetention != 30 || s.upgradeRepo != "someone/fork" || !s.upgradeRequireSignature {
		t.Errorf("retention = %d, repo = %q, requireSig = %v",
			s.backupRetention, s.upgradeRepo, s.upgradeRequireSignature)
	}
	// Untouched attributes keep their defaults beside the written ones.
	if s.backupInterval != 6*time.Hour || s.logDir != "/var/log/kanea/allocs" {
		t.Errorf("an unwritten attribute lost its default: %s %q", s.backupInterval, s.logDir)
	}

	edgeFile, err := nodeconfig.ParseEdge("kanea.hcl", []byte("bind {\n  edge_http = \":8080\"\n}\n"+
		"edge {\n  security_headers = false\n  routes_file = \"/run/x/routes.json\"\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := resolveEdgeSettings(edgeFile)
	if e.httpAddr != ":8080" || e.httpsAddr != ":443" || e.securityHeaders || e.snapshot != "/run/x/routes.json" {
		t.Errorf("edge settings = %+v", e)
	}
}

// kanead publishes the two projections and the edge reads them. They are one
// attribute each, resolved by two functions: this is what stops the pair
// from drifting, which a unit that spelled both paths out used to do.
func TestBothDaemonsAgreeOnTheProjectionPaths(t *testing.T) {
	for _, src := range []string{
		``,
		"edge {\n  routes_file = \"/srv/r.json\"\n  certs_file = \"/srv/c.json\"\n}\n",
	} {
		cfg, err := nodeconfig.Parse("kanea.hcl", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		file, err := nodeconfig.ParseEdge("kanea.hcl", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		agent, edge := resolveAgentSettings(cfg), resolveEdgeSettings(file)
		if agent.edgeRoutes != edge.snapshot || agent.edgeCerts != edge.certs {
			t.Errorf("%q: kanead writes %s and %s, the edge reads %s and %s",
				src, agent.edgeRoutes, agent.edgeCerts, edge.snapshot, edge.certs)
		}
	}
}
