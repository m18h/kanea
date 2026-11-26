package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// The units `kanea init` wrote before v1.115, trimmed of nothing that the
// migration could trip on: comments, an Environment= line, the other
// directives. %s is the ExecStart line.
const legacyKaneadUnitFmt = `[Unit]
Description=Kanea control plane (kanead)
Documentation=https://github.com/m18h/kanea
After=network-online.target containerd.service
Wants=network-online.target
# Not a hard dependency: kanead retries containerd and reports it, which
# is more useful than refusing to start.

[Service]
# Type=exec, not notify: kanead sends no sd_notify readiness message.
Type=exec
Environment=PATH=/usr/local/lib/kanea/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
%s
Restart=always
RestartSec=5s
Slice=kanea.slice
OOMScoreAdjust=-900
NoNewPrivileges=yes
KillMode=process
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
`

const legacyEdgeUnitFmt = `[Unit]
Description=Kanea edge proxy (kanea-edge)
After=network-online.target
Wants=network-online.target

[Service]
# See kanead.service: no sd_notify, so no Type=notify.
Type=exec
%s
Restart=always
RestartSec=2s
Slice=kanea.slice
OOMScoreAdjust=-800
User=kanea-edge
Group=kanea-edge

[Install]
WantedBy=multi-user.target
`

const (
	legacyKaneadExec = "ExecStart=/usr/local/bin/kanea agent --data-dir /var/lib/kanea --log-dir /var/log/kanea/allocs" +
		" --network ebpf --node-cidr 10.244.0.0/24 --cluster-cidr 10.244.0.0/16 --edge-group kanea-edge"
	legacyEdgeExec = "ExecStart=/usr/local/bin/kanea edge --routes /run/kanea-edge/routes.json --certs /run/kanea-edge/certs.json"

	migratedKaneadExec = "ExecStart=/usr/local/bin/kanea agent"
	migratedEdgeExec   = "ExecStart=/usr/local/bin/kanea edge"

	// What the stock units convert to.
	stockMigratedConfig = `data_dir      = "/var/lib/kanea"
alloc_log_dir = "/var/log/kanea/allocs"

network {
  driver       = "ebpf"
  node_cidr    = "10.244.0.0/24"
  cluster_cidr = "10.244.0.0/16"
}

edge {
  certs_group = "kanea-edge"
  routes_file = "/run/kanea-edge/routes.json"
  certs_file  = "/run/kanea-edge/certs.json"
}
`
)

func kaneadUnitWith(exec string) string { return strings.Replace(legacyKaneadUnitFmt, "%s", exec, 1) }
func edgeUnitWith(exec string) string   { return strings.Replace(legacyEdgeUnitFmt, "%s", exec, 1) }

// migrateNodeDir lays out a node: units under <root>/units, the node config
// at <root>/etc/kanea.hcl. files are relative to root; the two stock units
// are written unless files names them.
func migrateNodeDir(t *testing.T, files map[string]string) (string, migrateOptions) {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{
		"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec),
		"units/" + edgeUnit:   edgeUnitWith(legacyEdgeExec),
	}
	for name, content := range files {
		all[name] = content
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range all {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(content, "$ROOT", root)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, migrateOptions{
		unitDir:  filepath.Join(root, "units"),
		confPath: filepath.Join(root, "etc", "kanea.hcl"),
	}
}

type fileState struct {
	content string
	modTime time.Time
}

// treeState is every file under root, by relative path.
func treeState(t *testing.T, root string) map[string]fileState {
	t.Helper()
	state := map[string]fileState{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		state[filepath.ToSlash(rel)] = fileState{string(raw), info.ModTime()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func requireUntouched(t *testing.T, root string, before map[string]fileState) {
	t.Helper()
	after := treeState(t, root)
	if len(after) != len(before) {
		t.Errorf("files changed: before %d, after %d", len(before), len(after))
	}
	for name, was := range before {
		now, ok := after[name]
		switch {
		case !ok:
			t.Errorf("%s was removed", name)
		case now != was:
			t.Errorf("%s was rewritten", name)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("%s was created", name)
		}
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestMigrateNodeStockUnits(t *testing.T) {
	root, opts := migrateNodeDir(t, nil)
	report, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !report.migrated {
		t.Fatal("migrated = false for units that carry flags")
	}
	if got := readTestFile(t, opts.confPath); got != stockMigratedConfig {
		t.Errorf("kanea.hcl:\n%s\nwant:\n%s", got, stockMigratedConfig)
	}
	if string(report.config) != stockMigratedConfig {
		t.Errorf("report.config:\n%s", report.config)
	}
	if report.agentExecStart != migratedKaneadExec || report.edgeExecStart != migratedEdgeExec {
		t.Errorf("ExecStart lines = %q, %q", report.agentExecStart, report.edgeExecStart)
	}
	// Only the ExecStart line moved: every other byte of both units is as
	// `kanea init` wrote it.
	if got, want := readTestFile(t, filepath.Join(opts.unitDir, kaneadUnit)), kaneadUnitWith(migratedKaneadExec); got != want {
		t.Errorf("kanead.service:\n%s\nwant:\n%s", got, want)
	}
	if got, want := readTestFile(t, filepath.Join(opts.unitDir, edgeUnit)), edgeUnitWith(migratedEdgeExec); got != want {
		t.Errorf("kanea-edge.service:\n%s\nwant:\n%s", got, want)
	}
	if report.backup != "" || len(report.renamedDropIns) != 0 || len(report.sideFiles) != 0 {
		t.Errorf("report = %+v, want no backup, drop-in or side file", report)
	}
	cfg, err := nodeconfig.Parse(opts.confPath, report.config)
	if err != nil || len(cfg.Ignored) != 0 {
		t.Errorf("Parse: err %v, ignored %v", err, cfg.Ignored)
	}

	// A second run finds flagless units: nothing to do, nothing written.
	before := treeState(t, root)
	again, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	if again.migrated {
		t.Error("second run: migrated = true")
	}
	requireUntouched(t, root, before)
}

// An interruption between writing the node config and rewriting the units
// leaves the flags in place; converting them again must give the same file.
func TestMigrateNodeIsIdempotentOverItsOwnOutput(t *testing.T) {
	_, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec +
			" --secrets-providers-config $ROOT/providers.hcl --oidc-scopes groups"),
		"providers.hcl": "provider \"doppler\" \"ci\" {\n  token_file = \"/etc/kanea/doppler.token\"\n  allow      = [\"shop\"]\n}\n",
	})
	first, err := migrateNode(migrateOptions{unitDir: opts.unitDir, confPath: opts.confPath, dryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.confPath, first.config, 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !second.migrated {
		t.Fatal("the units still carried flags: migrated = false")
	}
	if string(second.config) != string(first.config) {
		t.Errorf("second pass changed the file:\n%s\nfirst:\n%s", second.config, first.config)
	}
	if second.backup != "" {
		t.Errorf("backup %q taken of a file the migration itself wrote", second.backup)
	}
	if strings.Count(string(second.config), `provider "doppler" "ci"`) != 1 {
		t.Errorf("provider block duplicated:\n%s", second.config)
	}
}

func TestMigrateNodeDropIn(t *testing.T) {
	const dropIn = `[Service]
Environment=FOO=bar
ExecStart=
ExecStart=/usr/local/bin/kanea agent --data-dir /var/lib/kanea \
    --base-domain home.lan --tls-default self-signed \
    --acme-email a@b.c
`
	root, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit + ".d/override.conf": dropIn,
		// No ExecStart: stays where it is.
		"units/" + kaneadUnit + ".d/limits.conf": "[Service]\nLimitNOFILE=65536\n",
	})
	report, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The drop-in's ExecStart replaced the unit's own, flags and all: only
	// what it named is carried over, plus the edge's.
	const want = `data_dir    = "/var/lib/kanea"
base_domain = "home.lan"

tls {
  default_mode = "self-signed"
}

acme {
  email = "a@b.c"
}

edge {
  routes_file = "/run/kanea-edge/routes.json"
  certs_file  = "/run/kanea-edge/certs.json"
}
`
	if got := readTestFile(t, opts.confPath); got != want {
		t.Errorf("kanea.hcl:\n%s\nwant:\n%s", got, want)
	}
	override := filepath.Join(opts.unitDir, kaneadUnit+".d", "override.conf")
	if !slices.Equal(report.renamedDropIns, []string{override}) {
		t.Errorf("renamedDropIns = %v, want [%s]", report.renamedDropIns, override)
	}
	state := treeState(t, root)
	if _, ok := state["units/"+kaneadUnit+".d/override.conf"]; ok {
		t.Error("override.conf still in place")
	}
	if got := state["units/"+kaneadUnit+".d/override.conf.migrated"].content; got != dropIn {
		t.Errorf("override.conf.migrated:\n%s", got)
	}
	if _, ok := state["units/"+kaneadUnit+".d/limits.conf"]; !ok {
		t.Error("limits.conf, which has no ExecStart, was moved")
	}
	if got, want := state["units/"+kaneadUnit].content, kaneadUnitWith(migratedKaneadExec); got != want {
		t.Errorf("kanead.service:\n%s", got)
	}
}

func TestMigrateNodeListenReplacesTheAPIHalfOfBind(t *testing.T) {
	const existing = `# the operator's own note
bind {
  api_addr   = "0.0.0.0:8600" # was everywhere
  api_tls    = "self-signed"
  api_domain = "kanea.home.lan"
  edge_http  = ":8080"
}
`
	tests := []struct {
		name  string
		flags string
		want  string
	}{
		{
			name:  "address and pair",
			flags: " --listen 10.0.0.1:8600 --listen-cert /c --listen-key /k",
			want: `# the operator's own note
bind {
  edge_http = ":8080"
  api_addr  = "10.0.0.1:8600"
  api_cert  = "/c"
  api_key   = "/k"
}
`,
		},
		{
			name:  "none",
			flags: " --listen none",
			want: `# the operator's own note
bind {
  edge_http = ":8080"
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, opts := migrateNodeDir(t, map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith("ExecStart=/usr/local/bin/kanea agent" + tt.flags),
				"units/" + edgeUnit:   edgeUnitWith(migratedEdgeExec),
				"etc/kanea.hcl":       existing,
			})
			report, err := migrateNode(opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := readTestFile(t, opts.confPath); got != tt.want {
				t.Errorf("kanea.hcl:\n%s\nwant:\n%s", got, tt.want)
			}
			if report.backup != opts.confPath+preMigrateSuffix {
				t.Errorf("backup = %q", report.backup)
			}
			if got := readTestFile(t, opts.confPath+preMigrateSuffix); got != existing {
				t.Errorf("pre-migrate copy:\n%s", got)
			}
		})
	}
}

func TestMigrateNodeKeepsAnEarlierBackup(t *testing.T) {
	_, opts := migrateNodeDir(t, map[string]string{
		"etc/kanea.hcl":             "base_domain = \"home.lan\"\n",
		"etc/kanea.hcl.pre-migrate": "the original\n",
	})
	report, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	if report.backup != "" {
		t.Errorf("backup = %q, want none: the name was taken", report.backup)
	}
	if got := readTestFile(t, opts.confPath+preMigrateSuffix); got != "the original\n" {
		t.Errorf("earlier backup overwritten: %q", got)
	}
}

func TestMigrateNodeFoldsSideFiles(t *testing.T) {
	root, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit: kaneadUnitWith("ExecStart=/usr/local/bin/kanea agent" +
			" --passthrough-config $ROOT/passthrough.hcl" +
			" --secrets-providers-config $ROOT/providers.hcl" +
			" --tls-certs-config $ROOT/certs.hcl"),
		"etc/kanea.hcl": `device "stale" {
  nodes = ["/dev/null"]
  allow = ["demo"]
}

storage {
  allowed_host_paths = ["/srv/kanea"]
}
`,
		"passthrough.hcl": `# grants
device "gpu" {
  nodes = ["/dev/dri/renderD128"] # resolved per alloc
  allow = ["media"]
  mode  = "rw"
}

socket "containerd" {
  path  = "/run/kanea/containerd.sock"
  allow = ["ops"]
}
`,
		"providers.hcl": `provider "doppler" "ci" {
  token_file = "/etc/kanea/secrets/doppler.token"
  project    = "backend"
  config     = "prd"
  allow      = ["shop", "shared"]
  sync {
    name = "DATABASE_URL"
    to   = "shop/db-url"
  }
}
`,
		"certs.hcl": `certificate "shop" {
  cert  = "/etc/kanea/tls/shop.crt"
  key   = "/etc/kanea/tls/shop.key"
  allow = ["shop"]
}
`,
	})
	report, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	got := readTestFile(t, opts.confPath)
	for _, want := range []string{
		`device "gpu" {`,
		`nodes = ["/dev/dri/renderD128"] # resolved per alloc`,
		`socket "containerd" {`,
		`provider "doppler" "ci" {`,
		`to   = "shop/db-url"`,
		`certificate "shop" {`,
		`allowed_host_paths = ["/srv/kanea"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("kanea.hcl lacks %q:\n%s", want, got)
		}
	}
	// The side file replaced the node config's own grants.
	if strings.Contains(got, `device "stale"`) {
		t.Errorf("the file's own device block survived --passthrough-config:\n%s", got)
	}
	cfg, err := nodeconfig.Parse(opts.confPath, []byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ignored) != 0 {
		t.Errorf("Ignored = %v", cfg.Ignored)
	}
	wantSide := []string{
		filepath.Join(root, "passthrough.hcl"),
		filepath.Join(root, "providers.hcl"),
		filepath.Join(root, "certs.hcl"),
	}
	if !slices.Equal(report.sideFiles, wantSide) {
		t.Errorf("sideFiles = %v, want %v", report.sideFiles, wantSide)
	}
	for _, path := range wantSide {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("side file removed: %v", err)
		}
	}
}

func TestMigrateNodeOffValues(t *testing.T) {
	const existing = `base_domain = "home.lan"

storage {
  allowed_host_paths = ["/srv/kanea"]
}

device "gpu" {
  nodes = ["/dev/dri/renderD128"]
  allow = ["media"]
}

socket "containerd" {
  path  = "/run/kanea/containerd.sock"
  allow = ["ops"]
}
`
	tests := []struct {
		name  string
		flags string
		want  string
	}{
		{
			name:  "host paths off",
			flags: " --allowed-host-paths off",
			want:  strings.Replace(existing, `["/srv/kanea"]`, `[]`, 1),
		},
		{
			name:  "host paths listed",
			flags: " --allowed-host-paths /a,/b",
			want:  strings.Replace(existing, `["/srv/kanea"]`, `["/a", "/b"]`, 1),
		},
		{
			name:  "passthrough off",
			flags: " --passthrough-config off",
			want:  "base_domain = \"home.lan\"\n\nstorage {\n  allowed_host_paths = [\"/srv/kanea\"]\n}\n",
		},
		{
			name:  "config off",
			flags: " --config off --image-gc off",
			want:  "images {\n  gc {\n    enabled = false\n  }\n}\n",
		},
		{
			name:  "config elsewhere",
			flags: " --config $ROOT/other.hcl --image-gc on",
			want:  "base_domain = \"apps.example.com\"\n\nimages {\n  gc {\n    enabled = true\n  }\n}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, opts := migrateNodeDir(t, map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith("ExecStart=/usr/local/bin/kanea agent" + tt.flags),
				"units/" + edgeUnit:   edgeUnitWith(migratedEdgeExec),
				"etc/kanea.hcl":       existing,
				"other.hcl":           "base_domain = \"apps.example.com\"\n",
			})
			if _, err := migrateNode(opts); err != nil {
				t.Fatal(err)
			}
			if got := readTestFile(t, opts.confPath); got != tt.want {
				t.Errorf("kanea.hcl:\n%q\nwant:\n%q", got, tt.want)
			}
			if got := readTestFile(t, opts.confPath+preMigrateSuffix); got != existing {
				t.Errorf("pre-migrate copy:\n%s", got)
			}
			_ = root
		})
	}
}

func TestMigrateNodeRefusesAndWritesNothing(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		wantInErr []string
	}{
		{
			name: "routes disagree",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec + " --edge-routes /run/a/routes.json"),
			},
			wantInErr: []string{"/run/a/routes.json", "/run/kanea-edge/routes.json", "--edge-routes", "--routes"},
		},
		{
			name: "certs disagree",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec + " --edge-certs /run/a/certs.json"),
			},
			wantInErr: []string{"/run/a/certs.json", "/run/kanea-edge/certs.json"},
		},
		{
			name: "unknown agent flag",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec + " --no-such-flag 1"),
			},
			wantInErr: []string{"no-such-flag", kaneadUnit},
		},
		{
			name: "unknown edge flag",
			files: map[string]string{
				"units/" + edgeUnit: edgeUnitWith(legacyEdgeExec + " --data-dir /x"),
			},
			wantInErr: []string{"data-dir", edgeUnit},
		},
		{
			name: "bad duration",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec + " --backup-interval soon"),
			},
			wantInErr: []string{"backup-interval"},
		},
		{
			name: "side file missing",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec + " --tls-certs-config /no/such/certs.hcl"),
			},
			wantInErr: []string{"--tls-certs-config", "/no/such/certs.hcl"},
		},
		{
			name: "existing config malformed",
			files: map[string]string{
				"etc/kanea.hcl": "bind {\n",
			},
			wantInErr: []string{"kanea.hcl"},
		},
		{
			name: "result does not load",
			files: map[string]string{
				"etc/kanea.hcl": "network {\n  no_such_attribute = true\n}\n",
			},
			wantInErr: []string{"no_such_attribute"},
		},
		{
			name: "not a kanea unit",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith("ExecStart=/usr/bin/env kanea agent --data-dir /x"),
			},
			wantInErr: []string{kaneadUnit, "kanea agent"},
		},
		{
			name: "unterminated quote",
			files: map[string]string{
				"units/" + kaneadUnit: kaneadUnitWith(`ExecStart=/usr/local/bin/kanea agent --base-domain "home.lan`),
			},
			wantInErr: []string{"unterminated"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, opts := migrateNodeDir(t, tt.files)
			before := treeState(t, root)
			report, err := migrateNode(opts)
			if err == nil {
				t.Fatalf("no error; report %+v", report)
			}
			for _, want := range tt.wantInErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
			requireUntouched(t, root, before)
		})
	}
}

func TestMigrateNodeWithoutAKaneadUnit(t *testing.T) {
	dir := t.TempDir()
	_, err := migrateNode(migrateOptions{unitDir: dir, confPath: filepath.Join(dir, "kanea.hcl")})
	want := "no kanead.service in " + dir + ": nothing to migrate"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

func TestMigrateNodeEnvironment(t *testing.T) {
	const envLines = "Environment=KANEA_REPO=someone/fork\nEnvironment=\"KANEA_REQUIRE_SIGNATURE=1\" OTHER=x\n"
	unit := kaneadUnitWith(envLines + migratedKaneadExec)
	const want = `upgrade {
  repo              = "someone/fork"
  require_signature = true
}
`
	root, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit: unit,
		"units/" + edgeUnit:   edgeUnitWith(migratedEdgeExec),
	})
	report, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !report.migrated {
		t.Fatal("migrated = false")
	}
	if got := readTestFile(t, opts.confPath); got != want {
		t.Errorf("kanea.hcl:\n%s\nwant:\n%s", got, want)
	}
	// The unit had no flags: it is left byte for byte, environment included.
	if got := readTestFile(t, filepath.Join(opts.unitDir, kaneadUnit)); got != unit {
		t.Errorf("kanead.service was rewritten:\n%s", got)
	}

	// The environment is still in the unit, so the next run sees it again:
	// it must find the file already says so, and leave a later edit alone.
	edited := strings.Replace(want, "someone/fork", "m18h/kanea", 1)
	if err := os.WriteFile(opts.confPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	before := treeState(t, root)
	again, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	if again.migrated {
		t.Error("second run: migrated = true")
	}
	requireUntouched(t, root, before)
}

func TestMigrateNodeDryRun(t *testing.T) {
	root, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit + ".d/override.conf": "[Service]\nExecStart=\n" + legacyKaneadExec + "\n",
		"etc/kanea.hcl": "base_domain = \"home.lan\"\n",
	})
	opts.dryRun = true
	before := treeState(t, root)
	report, err := migrateNode(opts)
	if err != nil {
		t.Fatal(err)
	}
	requireUntouched(t, root, before)
	if !report.migrated {
		t.Fatal("migrated = false")
	}
	if want := "base_domain   = \"home.lan\"\n" + stockMigratedConfig; string(report.config) != want {
		t.Errorf("report.config:\n%s\nwant:\n%s", report.config, want)
	}
	if report.agentExecStart != migratedKaneadExec || report.edgeExecStart != migratedEdgeExec {
		t.Errorf("ExecStart lines = %q, %q", report.agentExecStart, report.edgeExecStart)
	}
	if len(report.renamedDropIns) != 1 || report.backup != "" {
		t.Errorf("report = %+v, want one drop-in named and no backup", report)
	}
}

func TestMigrateNodeTypedAndEdgeFlags(t *testing.T) {
	_, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit: kaneadUnitWith(`ExecStart=/usr/local/bin/kanea agent --log-level debug` +
			` --backup-interval 6h --backup-retention=3 --dashboard=false --restore-if-empty` +
			` --dns-upstream "1.1.1.1, 9.9.9.9:53" --oidc-scopes '' --ldap-user-filter '(sAMAccountName=%s)'` +
			` --audit-retention 0 --publish-ports off`),
		"units/" + edgeUnit: edgeUnitWith(`ExecStart=/usr/local/bin/kanea edge --http :8080 --https off` +
			` --log-level warn --drain 30s --publish-drain 1m --max-published-conns 64 --security-headers=false`),
	})
	if _, err := migrateNode(opts); err != nil {
		t.Fatal(err)
	}
	const want = `log_level = "debug"

backup {
  snapshot_interval = "6h0m0s"
  retention         = 3
  restore_if_empty  = true
}

dns {
  upstreams = ["1.1.1.1", "9.9.9.9:53"]
}

edge {
  publish {
    ports         = "off"
    drain_timeout = "1m0s"
    max_conns     = 64
  }
  drain_timeout    = "30s"
  security_headers = false
  log_level        = "warn"
}

dashboard {
  enabled = false
}

audit {
  retention = "0s"
}

auth {
  oidc {
    scopes = []
  }
  ldap {
    user_filter = "(sAMAccountName=%s)"
  }
}

bind {
  edge_http  = ":8080"
  edge_https = "off"
}
`
	if got := readTestFile(t, opts.confPath); got != want {
		t.Errorf("kanea.hcl:\n%s\nwant:\n%s", got, want)
	}
}

func TestLegacyFlagTables(t *testing.T) {
	special := []string{
		"config", "allowed-host-paths", "passthrough-config", "secrets-providers-config",
		"tls-certs-config", "listen", "listen-cert", "listen-key", "image-gc",
	}
	tables := []struct {
		name        string
		table       []legacyFlag
		rows        int
		wantSpecial []string
	}{
		{"agent", legacyAgentFlags, 88, special},
		{"edge", legacyEdgeFlags, 16, nil},
	}
	for _, tt := range tables {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.table) != tt.rows {
				t.Errorf("%d rows, want %d: one per flag the daemon took", len(tt.table), tt.rows)
			}
			seen := map[string]bool{}
			var gotSpecial []string
			for _, f := range tt.table {
				if seen[f.name] {
					t.Errorf("--%s listed twice", f.name)
				}
				seen[f.name] = true
				if f.path == nil {
					gotSpecial = append(gotSpecial, f.name)
					continue
				}
				// The attribute must be one nodeconfig reads: a mistyped
				// path is an unknown attribute or an ignored stanza.
				var v cty.Value
				switch f.kind {
				case kindBool:
					v = cty.True
				case kindInt:
					v = cty.NumberIntVal(7)
				case kindDuration:
					v = cty.StringVal((90 * time.Minute).String())
				case kindList:
					v = cty.ListVal([]cty.Value{cty.StringVal("1.1.1.1")})
				default:
					v = cty.StringVal("x")
					if f.name == "image-pull-policy" {
						v = cty.StringVal("never")
					}
				}
				ed, err := nodeconfig.NewEditor("kanea.hcl", nil)
				if err != nil {
					t.Fatal(err)
				}
				ed.Set(v, f.path...)
				cfg, err := nodeconfig.Parse("kanea.hcl", ed.Bytes())
				if err != nil {
					t.Errorf("--%s -> %s: %v", f.name, strings.Join(f.path, "."), err)
					continue
				}
				if len(cfg.Ignored) != 0 {
					t.Errorf("--%s -> %s: not read (ignored %v)", f.name, strings.Join(f.path, "."), cfg.Ignored)
				}
			}
			slices.Sort(gotSpecial)
			want := slices.Clone(tt.wantSpecial)
			slices.Sort(want)
			if !slices.Equal(gotSpecial, want) {
				t.Errorf("flags with no path = %v, want %v", gotSpecial, want)
			}
		})
	}
}

func TestLegacySplitArgv(t *testing.T) {
	tests := []struct {
		line    string
		want    []string
		wantErr bool
	}{
		{line: "", want: nil},
		{line: "  /bin/kanea   agent\t--x  y ", want: []string{"/bin/kanea", "agent", "--x", "y"}},
		{line: `a "b c" 'd "e"' f\ g`, want: []string{"a", "b c", `d "e"`, "f g"}},
		{line: `--x="a \"b\"" ''`, want: []string{`--x=a "b"`, ""}},
		{line: `a "b`, wantErr: true},
		{line: `a 'b`, wantErr: true},
	}
	for _, tt := range tests {
		got, err := splitArgv(tt.line)
		if (err != nil) != tt.wantErr {
			t.Errorf("splitArgv(%q) err = %v, wantErr %v", tt.line, err, tt.wantErr)
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("splitArgv(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// stubMigration points a self-migrating daemon at dir and records what it
// asks systemd for instead of asking.
func stubMigration(t *testing.T, opts migrateOptions, fail map[string]error) *[]string {
	t.Helper()
	prevOpts, prevCtl := migrateDefaults, migrateSystemctl
	t.Cleanup(func() { migrateDefaults, migrateSystemctl = prevOpts, prevCtl })
	var calls []string
	migrateDefaults = opts
	migrateSystemctl = func(_ context.Context, _ time.Duration, args ...string) error {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		return fail[call]
	}
	return &calls
}

const daemonRefusalFmt = "kanea %s takes no arguments: node configuration lives in /etc/kanea/kanea.hcl. " +
	"To convert an older unit's flags: sudo kanea config migrate"

func TestDaemonArgsRefusal(t *testing.T) {
	tests := []struct {
		name         string
		daemon       string
		args         []string
		underSystemd bool
		wantHelp     bool
	}{
		{name: "agent by hand", daemon: "agent", args: []string{"--data-dir", "/tmp/x"}},
		{name: "edge by hand", daemon: "edge", args: []string{"--http", ":8080"}},
		// The edge is not root and never migrates, even with flags to convert.
		{name: "edge under systemd", daemon: "edge", args: []string{"--http", ":8080"}, underSystemd: true},
		{name: "agent -h", daemon: "agent", args: []string{"-h"}, wantHelp: true},
		{name: "agent -help", daemon: "agent", args: []string{"-help"}, wantHelp: true},
		{name: "edge --help", daemon: "edge", args: []string{"--help"}, underSystemd: true, wantHelp: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, opts := migrateNodeDir(t, nil)
			calls := stubMigration(t, opts, nil)
			if tt.underSystemd {
				t.Setenv("INVOCATION_ID", "x")
			} else {
				t.Setenv("INVOCATION_ID", "")
			}
			before := treeState(t, root)
			err := daemonArgs(tt.daemon, tt.args)
			if tt.wantHelp {
				if !errors.Is(err, flag.ErrHelp) {
					t.Errorf("err = %v, want flag.ErrHelp", err)
				}
			} else if want := strings.Replace(daemonRefusalFmt, "%s", tt.daemon, 1); err == nil || err.Error() != want {
				t.Errorf("err = %v\nwant  %s", err, want)
			}
			requireUntouched(t, root, before)
			if len(*calls) != 0 {
				t.Errorf("systemctl called: %v", *calls)
			}
		})
	}
}

func TestDaemonArgsMigratesUnderSystemd(t *testing.T) {
	tests := []struct {
		name string
		fail map[string]error
	}{
		{name: "clean"},
		// Neither is a reason to stay down: the unit is already rewritten.
		{name: "reset-failed and edge restart fail", fail: map[string]error{
			"reset-failed kanea-edge": errors.New("not loaded"),
			"restart kanea-edge":      errors.New("start limit"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, opts := migrateNodeDir(t, nil)
			calls := stubMigration(t, opts, tt.fail)
			t.Setenv("INVOCATION_ID", "x")

			err := daemonArgs("agent", []string{"--data-dir", "/var/lib/kanea"})
			const want = "node configuration migrated to /etc/kanea/kanea.hcl; restarting under the rewritten unit"
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
			wantCalls := []string{"daemon-reload", "reset-failed kanea-edge", "restart kanea-edge"}
			if !slices.Equal(*calls, wantCalls) {
				t.Errorf("systemctl calls = %v, want %v", *calls, wantCalls)
			}
			if got := readTestFile(t, opts.confPath); got != stockMigratedConfig {
				t.Errorf("kanea.hcl:\n%s", got)
			}
			if got := readTestFile(t, filepath.Join(opts.unitDir, kaneadUnit)); !strings.Contains(got, migratedKaneadExec+"\n") {
				t.Errorf("kanead.service not rewritten:\n%s", got)
			}

			// Restarted with arguments all the same (a wrapper, a stale
			// daemon-reload): the units now carry nothing to convert, so
			// this is the refusal and not another restart.
			*calls = nil
			err = daemonArgs("agent", []string{"--data-dir", "/var/lib/kanea"})
			if refusal := strings.Replace(daemonRefusalFmt, "%s", "agent", 1); err == nil || err.Error() != refusal {
				t.Errorf("second call: err = %v, want the refusal", err)
			}
			if len(*calls) != 0 {
				t.Errorf("second call reached systemctl: %v", *calls)
			}
		})
	}
}

func TestDaemonArgsMigrationFailure(t *testing.T) {
	root, opts := migrateNodeDir(t, map[string]string{
		"units/" + kaneadUnit: kaneadUnitWith(legacyKaneadExec + " --no-such-flag"),
	})
	calls := stubMigration(t, opts, nil)
	t.Setenv("INVOCATION_ID", "x")
	before := treeState(t, root)
	err := daemonArgs("agent", []string{"--no-such-flag"})
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"no-such-flag", "sudo kanea config migrate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	requireUntouched(t, root, before)
	if len(*calls) != 0 {
		t.Errorf("systemctl called: %v", *calls)
	}
}

func TestRunConfigMigrateUsage(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, "usage: kanea config migrate [flags]"},
		{[]string{"show"}, `unknown config command "show" (have: migrate)`},
		{[]string{"migrate", "extra"}, `kanea config migrate takes no arguments (got "extra")`},
	}
	for _, tt := range tests {
		if err := runConfig(tt.args); err == nil || err.Error() != tt.want {
			t.Errorf("runConfig(%v) = %v, want %q", tt.args, err, tt.want)
		}
	}
}
