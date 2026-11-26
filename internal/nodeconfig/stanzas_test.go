package nodeconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// unsetFields walks v and names every field still at its zero value. Zero
// means unset throughout Config, so on the complete fixture the answer must
// be nothing: a field this returns is one the schema dropped on the floor.
func unsetFields(prefix string, v reflect.Value, skip map[string]bool) []string {
	var out []string
	for i := range v.NumField() {
		field := v.Type().Field(i)
		name := prefix + field.Name
		if skip[name] {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			out = append(out, unsetFields(name+".", fv, skip)...)
			continue
		}
		if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.Struct {
			out = append(out, unsetFields(name+".", fv.Elem(), skip)...)
			continue
		}
		if fv.IsZero() {
			out = append(out, name)
		}
	}
	return out
}

// TestTheCompleteFileLoadsWithEveryFieldSet is the schema's census: the
// fixture writes every attribute of PRD §15.1, and each one has to arrive.
func TestTheCompleteFileLoadsWithEveryFieldSet(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "complete.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse("complete.hcl", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ignored) != 0 {
		t.Fatalf("Ignored = %v; the complete file names no stanza this version does not read", cfg.Ignored)
	}
	// Path and Source are Load's; Ignored was just checked; the fixture's
	// gc block is enabled, so Disabled is rightly false.
	skip := map[string]bool{"Ignored": true, "Path": true, "Source": true, "ImageGC.Disabled": true}
	if unset := unsetFields("", reflect.ValueOf(*cfg), skip); len(unset) != 0 {
		t.Fatalf("fields the complete file did not populate: %v", unset)
	}

	// A few spot values, one per decoding path: a top-level attribute, a
	// direct struct, a duration twin, a nested block, a pointer scalar.
	if cfg.DataDir != "/var/lib/kanea" || cfg.Network.NodeCIDR != "10.244.0.0/24" {
		t.Fatalf("data_dir = %q, network.node_cidr = %q", cfg.DataDir, cfg.Network.NodeCIDR)
	}
	if got := *cfg.Edge.Publish.DrainTimeout; got != time.Minute {
		t.Fatalf("edge.publish.drain_timeout = %s", got)
	}
	if cfg.Auth.OIDC.Issuer == "" || len(*cfg.Auth.OIDC.Scopes) != 2 {
		t.Fatalf("auth.oidc = %+v", cfg.Auth.OIDC)
	}
	if *cfg.Edge.FunctionsPort != 0 || *cfg.Backup.S3.PathStyle != true {
		t.Fatalf("a written zero must arrive as a set pointer: %v %v",
			*cfg.Edge.FunctionsPort, *cfg.Backup.S3.PathStyle)
	}
}

// TestThePRDExampleLoads pins the document to the parser: the fenced block
// under §15.1 is what an operator copies, so it must load with nothing
// ignored. A stanza renamed in one and not the other fails here.
func TestThePRDExampleLoads(t *testing.T) {
	prd, err := os.ReadFile(filepath.Join("..", "..", "PRD.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, found := strings.Cut(string(prd), "\n### 15.1 ")
	if !found {
		t.Fatal("PRD.md has no §15.1 heading")
	}
	_, block, found := strings.Cut(after, "\n```hcl\n")
	if !found {
		t.Fatal("§15.1 has no fenced hcl block")
	}
	example, _, found := strings.Cut(block, "\n```")
	if !found {
		t.Fatal("§15.1's hcl block is not closed")
	}
	if strings.Contains(example, "\n### ") {
		t.Fatal("the first hcl block after §15.1 belongs to a later section")
	}
	cfg, err := Parse("PRD.md#15.1", []byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ignored) != 0 {
		t.Fatalf("§15.1's example carries stanzas nothing reads: %v", cfg.Ignored)
	}
	if _, err := ParseEdge("PRD.md#15.1", []byte(example)); err != nil {
		t.Fatalf("the edge must load the same example: %v", err)
	}
}

func TestParseRefusesAnUnknownAttributeInEveryStanza(t *testing.T) {
	for _, src := range []string{
		`auth { insecure_cookie = true }`,
		"auth {\n oidc { isuer = \"x\" }\n}",
		"auth {\n ldap { uri = \"x\" }\n}",
		`audit { retain = "1h" }`,
		`dashboard { enable = true }`,
		`network { node_cdir = "10.0.0.0/24" }`,
		`containerd { sock = "/x" }`,
		`metrics { every = "5s" }`,
		`scaling { enable = true }`,
		`builds { buildkit = "off" }`,
		`gitops { interval = "2m" }`,
		`secrets { interval = "5m" }`,
		`tls { default = "acme" }`,
		`acme { mail = "a@b.c" }`,
		"acme {\n dns01 { provider = \"cloudflare\" }\n}",
		`edge { routes = "/x" }`,
		"edge {\n publish { port = \"off\" }\n}",
		`notifications { allow_privat = true }`,
		`backup { directory = "/x" }`,
		"backup {\n s3 { bucket = \"x\" }\n}",
		`upgrade { repository = "a/b" }`,
		`storage { volumes_dir = "/x" }`,
	} {
		// "Unsupported argument" and not just any error: a source that fails
		// for its syntax would pass a bare err != nil and prove nothing.
		_, err := Parse("kanea.hcl", []byte(src))
		if err == nil || !strings.Contains(err.Error(), "Unsupported argument") {
			t.Errorf("%s: a typo inside a read stanza must be refused by name, got %v", src, err)
		}
	}
}

func TestParseNamesABadDurationByItsPath(t *testing.T) {
	for attr, src := range map[string]string{
		"audit.retention":            `audit { retention = "ninety days" }`,
		"metrics.interval":           `metrics { interval = "5" }`,
		"gitops.sync_interval":       `gitops { sync_interval = "soon" }`,
		"secrets.sync_interval":      `secrets { sync_interval = "5 m" }`,
		"edge.poll_interval":         `edge { poll_interval = "1sec" }`,
		"edge.publish.drain_timeout": "edge {\n publish { drain_timeout = \"x\" }\n}",
		"backup.snapshot_interval":   `backup { snapshot_interval = "6hours" }`,
	} {
		_, err := Parse("kanea.hcl", []byte(src))
		if err == nil || !strings.Contains(err.Error(), attr) || !strings.Contains(err.Error(), "kanea.hcl") {
			t.Errorf("%s: err = %v, want one naming the file and %s", src, err, attr)
		}
	}
}

// A duration written as "0" is a value, not an absence: audit.retention = "0"
// keeps entries forever, and the daemon must be able to tell.
func TestParseKeepsAZeroDurationDistinctFromUnset(t *testing.T) {
	cfg, err := Parse("kanea.hcl", []byte(`audit { retention = "0" }`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Retention == nil || *cfg.Audit.Retention != 0 {
		t.Fatalf("retention = %v, want a set zero", cfg.Audit.Retention)
	}
	cfg, err = Parse("kanea.hcl", []byte(`audit { }`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Retention != nil {
		t.Fatalf("retention = %v, want unset", *cfg.Audit.Retention)
	}
}

func TestParseTellsAbsentOIDCScopesFromNone(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		wantNil   bool
		wantLen   int
	}{
		{"absent", "auth {\n oidc { issuer = \"https://idp\" }\n}", true, 0},
		{"none", "auth {\n oidc { scopes = [] }\n}", false, 0},
		{"some", "auth {\n oidc { scopes = [\"groups\"] }\n}", false, 1},
	} {
		cfg, err := Parse("kanea.hcl", []byte(tc.src))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		scopes := cfg.Auth.OIDC.Scopes
		if (scopes == nil) != tc.wantNil {
			t.Fatalf("%s: scopes nil = %v, want %v", tc.name, scopes == nil, tc.wantNil)
		}
		if scopes != nil && len(*scopes) != tc.wantLen {
			t.Fatalf("%s: scopes = %v", tc.name, *scopes)
		}
	}
}

func TestParseEdge(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		wantErr   bool
		check     func(*testing.T, *EdgeFile)
	}{
		{
			name: "a kanead-only mistake does not stop the edge",
			src: `
auth { no_such_attribute = true }
bind { api_tls = "acme" }
edge { poll_interval = "2s" }`,
			check: func(t *testing.T, f *EdgeFile) {
				if f.Edge.PollInterval == nil || *f.Edge.PollInterval != 2*time.Second {
					t.Fatalf("poll_interval = %v", f.Edge.PollInterval)
				}
			},
		},
		{
			name: "https off round-trips",
			src:  "bind {\n edge_http = \":8080\"\n edge_https = \"off\"\n}",
			check: func(t *testing.T, f *EdgeFile) {
				if f.HTTPAddr != ":8080" || f.HTTPSAddr != "off" {
					t.Fatalf("http = %q, https = %q", f.HTTPAddr, f.HTTPSAddr)
				}
			},
		},
		{name: "a syntax error anywhere is fatal", src: `auth {`, wantErr: true},
		{name: "a typo in its own stanza is fatal", src: `edge { pol_interval = "1s" }`, wantErr: true},
		{name: "a bad duration in its own stanza is fatal", src: `edge { drain_timeout = "x" }`, wantErr: true},
		{name: "empty", src: ``, check: func(t *testing.T, f *EdgeFile) {
			if !reflect.DeepEqual(*f, EdgeFile{}) {
				t.Fatalf("an empty file must be the zero value, got %+v", f)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseEdge("kanea.hcl", []byte(tc.src))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && tc.check != nil {
				tc.check(t, f)
			}
		})
	}
}

func TestLoadEdge(t *testing.T) {
	f, err := LoadEdge(filepath.Join(t.TempDir(), "kanea.hcl"))
	if err != nil || f.Path != "" {
		t.Fatalf("a missing file is every default: %+v, %v", f, err)
	}

	path := writeConfig(t, `edge { status_addr = "off" }`, 0o644)
	f, err = LoadEdge(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Path != path || f.Edge.StatusAddr != "off" {
		t.Fatalf("got %+v", f)
	}

	// The trust check is the same one kanead applies: the edge must not be
	// configurable by a file its own unprivileged user could have written.
	if _, err := LoadEdge(writeConfig(t, `edge { }`, 0o666)); err == nil {
		t.Fatal("a world-writable file must be refused for the edge too")
	}
}

func TestLoadKeepsTheSourceBytes(t *testing.T) {
	const src = `data_dir = "/srv/kanea" # kept` + "\n"
	cfg, err := Load(writeConfig(t, src, 0o644))
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.Source) != src || cfg.DataDir != "/srv/kanea" {
		t.Fatalf("Source = %q, DataDir = %q", cfg.Source, cfg.DataDir)
	}
}
