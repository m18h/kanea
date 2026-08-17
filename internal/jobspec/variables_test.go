package jobspec_test

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

// R30: a variables block declares once, the spec references flat ${name} (or
// a bare identifier where HCL takes an expression) and precedence is
// node < spec < caller.

func TestVariablesResolveAcrossTheSpec(t *testing.T) {
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(`
spec_version = 1
variables {
  domain   = "shop.example.com"
  registry = "reg.example.com"
  replicas = 3
}
project "shop" {}
service "web" {
  project = "shop"
  count   = replicas
  task "app" {
    image = "${registry}/shop/web:v1"
    env = {
      PUBLIC_URL = "https://${domain}"
    }
  }
  network {
    port "http" { container = 3000 }
  }
  expose { domains = ["${domain}", "www.${domain}"] }
}
`))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	svc := spec.Services[0]
	if svc.Count != 3 {
		t.Errorf("count = %d, want 3 (bare identifier through a number variable)", svc.Count)
	}
	if svc.Task.Image != "reg.example.com/shop/web:v1" {
		t.Errorf("image = %q", svc.Task.Image)
	}
	if got := svc.Task.Env["PUBLIC_URL"]; got != "https://shop.example.com" {
		t.Errorf("env PUBLIC_URL = %q", got)
	}
	if got := svc.Exposes[0].Domains; got[0] != "shop.example.com" || got[1] != "www.shop.example.com" {
		t.Errorf("domains = %v", got)
	}
}

func TestVariablePrecedenceIsNodeSpecCaller(t *testing.T) {
	src := `
spec_version = 1
variables {
  domain = "spec.example.com"
}
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "img:v1"
    env = {
      DOMAIN = "${domain}"
      ZONE   = "${zone}"
    }
  }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{
		NodeVars: map[string]string{"domain": "node.example.com", "zone": "node-zone"},
	}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	env := spec.Services[0].Task.Env
	if env["DOMAIN"] != "spec.example.com" {
		t.Errorf("spec must win over node: DOMAIN = %q", env["DOMAIN"])
	}
	if env["ZONE"] != "node-zone" {
		t.Errorf("node default must apply when the spec is silent: ZONE = %q", env["ZONE"])
	}

	// Caller-supplied vars sit above the spec's own block.
	spec, diags = jobspec.ParseSource(jobspec.Options{
		NodeVars: map[string]string{"zone": "node-zone"},
		Vars:     map[string]string{"domain": "caller.example.com"},
	}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	if got := spec.Services[0].Task.Env["DOMAIN"]; got != "caller.example.com" {
		t.Errorf("caller must win over spec: DOMAIN = %q", got)
	}
}

func TestVariableDefinitionsMayReferenceNodeVarsButNeverSiblings(t *testing.T) {
	// A node var in a definition resolves; a sibling reference is an unknown
	// variable, by design (R30: no ordering, no cycles).
	spec, diags := jobspec.ParseSource(jobspec.Options{
		NodeVars: map[string]string{"base": "example.com"},
	}, "test.hcl", []byte(`
spec_version = 1
variables { domain = "shop.${base}" }
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "img:v1"
    env = { DOMAIN = "${domain}" }
  }
}
`))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	if got := spec.Services[0].Task.Env["DOMAIN"]; got != "shop.example.com" {
		t.Errorf("DOMAIN = %q", got)
	}

	out := parseErr(t, `
spec_version = 1
variables {
  base   = "example.com"
  domain = "shop.${base}"
}
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "img:v1" }
}
`)
	if !strings.Contains(out, "base") {
		t.Errorf("diagnostics = %q, want the sibling reference named", out)
	}
}

func TestVariableRefusals(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name:    "reserved built-in",
			src:     `variables { GIT_SHA_SHORT = "x" }`,
			wantErr: "Reserved variable name",
		},
		{
			name:    "reserved service namespace",
			src:     `variables { service = "x" }`,
			wantErr: "Reserved variable name",
		},
		{
			name:    "duplicate across blocks",
			src:     `variables { domain = "a" }` + "\n" + `variables { domain = "b" }`,
			wantErr: "Duplicate variable",
		},
		{
			name:    "list value",
			src:     `variables { domains = ["a", "b"] }`,
			wantErr: "Invalid variable value",
		},
		{
			name:    "null value",
			src:     `variables { domain = null }`,
			wantErr: "Invalid variable value",
		},
		{
			name: "undefined reference",
			src: `service "web" {
  project = "shop"
  task "app" { image = "${nope}:v1" }
}`,
			wantErr: "nope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := parseErr(t, "spec_version = 1\nproject \"shop\" {}\n"+tc.src)
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want mention of %q", out, tc.wantErr)
			}
		})
	}
}

func TestVariablesMergeAcrossFiles(t *testing.T) {
	// One spec may span files; variables declared in one are visible in the
	// other, and a cross-file duplicate is refused like a same-file one.
	spec, diags := jobspec.ParseContents(jobspec.Options{}, map[string][]byte{
		"vars.hcl": []byte(`variables { domain = "shop.example.com" }`),
		"web.hcl": []byte(`
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "img:v1"
    env = { DOMAIN = "${domain}" }
  }
}
`),
	})
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	if got := spec.Services[0].Task.Env["DOMAIN"]; got != "shop.example.com" {
		t.Errorf("DOMAIN = %q", got)
	}

	_, diags = jobspec.ParseContents(jobspec.Options{}, map[string][]byte{
		"a.hcl": []byte(`variables { domain = "a" }`),
		"b.hcl": []byte(`
spec_version = 1
variables { domain = "b" }
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "img:v1" }
}
`),
	})
	if !diags.HasErrors() {
		t.Fatal("expected a cross-file duplicate to be refused")
	}
	if out := jobspec.FormatDiagnostics(diags); !strings.Contains(out, "Duplicate variable") {
		t.Errorf("diagnostics = %q", out)
	}
}
