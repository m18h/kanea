package jobspec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

// parse is the common harness: parse one source and require success.
func parse(t *testing.T, src string) *jobspec.Spec {
	t.Helper()
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	return spec
}

// parseErr requires failure and returns the rendered diagnostics.
func parseErr(t *testing.T, src string) string {
	t.Helper()
	_, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if !diags.HasErrors() {
		t.Fatal("expected errors, got none")
	}
	return jobspec.FormatDiagnostics(diags)
}

const minimalSpec = `
spec_version = 1

project "shop" {}

service "web" {
  project = "shop"
  task "app" {
    image = "nginx:1.27-alpine"
  }
}
`

func TestMinimalImageOnlyService(t *testing.T) {
	// R8: the minimal service is just an image — no git, no build block.
	spec := parse(t, minimalSpec)

	if spec.SpecVersion != jobspec.SpecVersion {
		t.Errorf("spec_version = %d, want %d", spec.SpecVersion, jobspec.SpecVersion)
	}
	svc := spec.ServiceByName("shop", "web")
	if svc == nil {
		t.Fatal("service shop/web not found")
	}
	if svc.Count != jobspec.DefaultCount {
		t.Errorf("count = %d, want default %d", svc.Count, jobspec.DefaultCount)
	}
	if svc.Task.Image != "nginx:1.27-alpine" {
		t.Errorf("image = %q", svc.Task.Image)
	}
}

func TestResourceDefaultsAreAlwaysApplied(t *testing.T) {
	// R11: limits are mandatory, the declaration is optional. No alloc unlimited.
	spec := parse(t, minimalSpec)
	task := spec.ServiceByName("shop", "web").Task

	if task.Resources.CPU != jobspec.DefaultCPU {
		t.Errorf("cpu = %d, want default %d", task.Resources.CPU, jobspec.DefaultCPU)
	}
	if task.Resources.Memory != jobspec.DefaultMemory {
		t.Errorf("memory = %d, want default %d", task.Resources.Memory, jobspec.DefaultMemory)
	}
	if task.ResourcesDeclared {
		t.Error("ResourcesDeclared = true for an omitted block; plan could not distinguish defaults")
	}

	declared := parse(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    resources {
      cpu    = 500
      memory = 512
    }
  }
}
`)
	dt := declared.ServiceByName("shop", "web").Task
	if dt.Resources.CPU != 500 || dt.Resources.Memory != 512 {
		t.Errorf("declared resources = %+v", dt.Resources)
	}
	if !dt.ResourcesDeclared {
		t.Error("ResourcesDeclared = false for a declared block")
	}
}

func TestPartialResourcesKeepDefaultsForTheRest(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    resources {
      memory = 1024
    }
  }
}
`)
	res := spec.ServiceByName("shop", "web").Task.Resources
	if res.Memory != 1024 {
		t.Errorf("memory = %d, want 1024", res.Memory)
	}
	if res.CPU != jobspec.DefaultCPU {
		t.Errorf("cpu = %d, want default %d when only memory is declared", res.CPU, jobspec.DefaultCPU)
	}
}

func TestNameValidation(t *testing.T) {
	// R1 / PRD §4.2: names become DNS labels, so this is correctness.
	tests := []struct {
		name    string
		svcName string
		wantErr string
	}{
		{"lowercase alphanumeric", "web", ""},
		{"digits and dashes", "web-2", ""},
		{"single character", "w", ""},
		{"uppercase", "Web", "not a DNS-1123 label"},
		{"underscore", "web_1", "not a DNS-1123 label"},
		{"leading dash", "-web", "not a DNS-1123 label"},
		{"trailing dash", "web-", "not a DNS-1123 label"},
		{"dot", "web.api", "not a DNS-1123 label"},
		{"too long", strings.Repeat("a", 64), "at most 63"},
		{"exactly 63", strings.Repeat("a", 63), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "` + tc.svcName + `" {
  project = "shop"
  task "app" { image = "nginx" }
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			out := parseErr(t, src)
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want mention of %q", out, tc.wantErr)
			}
		})
	}
}

func TestSpecVersionIsGated(t *testing.T) {
	// R6: future revisions are gated by this field.
	t.Run("missing", func(t *testing.T) {
		out := parseErr(t, `
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
`)
		if !strings.Contains(out, "Missing spec_version") {
			t.Errorf("diagnostics = %q", out)
		}
	})

	t.Run("from the future", func(t *testing.T) {
		out := parseErr(t, `
spec_version = 99
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
`)
		if !strings.Contains(out, "Unsupported spec_version") {
			t.Errorf("diagnostics = %q", out)
		}
	})
}

func TestServiceRequiresAnImageSource(t *testing.T) {
	// R8: task.image, a build block, or both.
	out := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {}
}
`)
	if !strings.Contains(out, "no image") {
		t.Errorf("diagnostics = %q", out)
	}

	// build alone is enough: the image does not exist until the first build.
	parse(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  build {
    context = "./web"
    target  = "registry.example.com/shop/web"
  }
  task "app" {}
}
`)
}

func TestServiceProjectMustExist(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "unknown project",
			src: `
spec_version = 1
project "shop" {}
service "web" {
  project = "nope"
  task "app" { image = "nginx" }
}`,
			wantErr: "Unknown project",
		},
		{
			name: "missing project attribute",
			src: `
spec_version = 1
project "shop" {}
service "web" {
  task "app" { image = "nginx" }
}`,
			wantErr: "no project",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if out := parseErr(t, tc.src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestDuplicatesAreRejected(t *testing.T) {
	t.Run("duplicate service in a project", func(t *testing.T) {
		out := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
`)
		if !strings.Contains(out, "Duplicate service") {
			t.Errorf("diagnostics = %q", out)
		}
	})

	t.Run("same name in different projects is fine", func(t *testing.T) {
		// Names are unique per project, not globally (PRD §4.1).
		parse(t, `
spec_version = 1
project "shop" {}
project "blog" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
service "web" {
  project = "blog"
  task "app" { image = "nginx" }
}
`)
	})

	t.Run("duplicate project", func(t *testing.T) {
		out := parseErr(t, `
spec_version = 1
project "shop" {}
project "shop" {}
`)
		if !strings.Contains(out, "Duplicate project") {
			t.Errorf("diagnostics = %q", out)
		}
	})
}

func TestSecretReferencesAreProjectScoped(t *testing.T) {
	// R5: cross-project secret reads are an IDOR-class exfiltration path.
	tests := []struct {
		name    string
		ref     string
		wantErr string
	}{
		{"own project", "secret:shop/database-url", ""},
		{"shared scope", "secret:shared/registry-token", ""},
		{"other project", "secret:bank/database-url", "Cross-project secret reference"},
		{"no scope", "secret:database-url", "Malformed secret reference"},
		{"empty name", "secret:shop/", "Malformed secret reference"},
		{"not a secret", "postgres://localhost/db", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
project "bank" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    env = { DATABASE_URL = "` + tc.ref + `" }
  }
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestHealthCheckRules(t *testing.T) {
	// R7: http, tcp, exec — and exec takes an argument array, never a shell string.
	tests := []struct {
		name    string
		block   string
		wantErr string
	}{
		{
			name:  "http with path and port",
			block: "health_check \"http\" {\n type = \"http\"\n path = \"/healthz\"\n port = \"http\"\n}",
		},
		{
			name:  "tcp with port",
			block: "health_check \"tcp\" {\n type = \"tcp\"\n port = \"http\"\n}",
		},
		{
			name:  "exec with command array",
			block: "health_check \"alive\" {\n type = \"exec\"\n command = [\"pg_isready\", \"-U\", \"postgres\"]\n}",
		},
		{
			name:    "http without path",
			block:   "health_check \"http\" {\n type = \"http\"\n port = \"http\"\n}",
			wantErr: "needs path",
		},
		{
			name:    "http without port",
			block:   "health_check \"http\" {\n type = \"http\"\n path = \"/healthz\"\n}",
			wantErr: "needs port",
		},
		{
			name:    "port that is not declared",
			block:   "health_check \"http\" {\n type = \"http\"\n path = \"/x\"\n port = \"nope\"\n}",
			wantErr: "does not declare",
		},
		{
			name:    "exec without command",
			block:   `health_check "alive" { type = "exec" }`,
			wantErr: "argument array",
		},
		{
			name:    "unknown type",
			block:   `health_check "weird" { type = "carrier-pigeon" }`,
			wantErr: "Unknown health check type",
		},
		{
			name:    "no type",
			block:   `health_check "weird" { path = "/x" }`,
			wantErr: "no type",
		},
		{
			name:    "bad interval",
			block:   "health_check \"http\" {\n type = \"tcp\"\n port = \"http\"\n interval = \"soon\"\n}",
			wantErr: "Invalid duration",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  network {
    port "http" {
      container = 8080
    }
  }
  ` + tc.block + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestServiceReferencesResolveToDNSNames(t *testing.T) {
	// R9: references resolve to DNS names, never IPs, and file order is irrelevant.
	spec := parse(t, `
spec_version = 1
project "shop" {}

service "api" {
  project = "shop"
  task "api" {
    image = "api:1"
    env = {
      DATABASE_HOST = "${service.postgres.host}"
      DATABASE_PORT = "${service.postgres.port.pg}"
      ASSETS_ORIGIN = "http://${service.assets.host}"
    }
  }
}

service "postgres" {
  project = "shop"
  task "db" { image = "postgres:17" }
  network {
    port "pg" {
      container = 5432
    }
  }
}

service "assets" {
  project = "shop"
  task "cdn" { image = "nginx" }
}
`)
	env := spec.ServiceByName("shop", "api").Task.Env
	want := map[string]string{
		"DATABASE_HOST": "postgres.shop.kanea",
		"DATABASE_PORT": "5432",
		"ASSETS_ORIGIN": "http://assets.shop.kanea",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, env[k], v)
		}
	}
}

func TestServiceReferencesCreateDependencyEdges(t *testing.T) {
	// R10: every reference is also a dependency edge, merged with depends_on.
	spec := parse(t, `
spec_version = 1
project "shop" {}

service "api" {
  project    = "shop"
  depends_on = ["assets"]
  task "api" {
    image = "api:1"
    env = { DATABASE_HOST = "${service.postgres.host}" }
  }
}

service "postgres" {
  project = "shop"
  task "db" { image = "postgres:17" }
}

service "assets" {
  project = "shop"
  task "cdn" { image = "nginx" }
}
`)
	api := spec.ServiceByName("shop", "api")
	if got := strings.Join(api.Dependencies, ","); got != "assets,postgres" {
		t.Errorf("dependencies = %q, want \"assets,postgres\"", got)
	}
	if len(api.Refs) != 1 || api.Refs[0].Service != "postgres" || api.Refs[0].EnvKey != "DATABASE_HOST" {
		t.Errorf("refs = %+v", api.Refs)
	}
}

func TestServiceReferenceErrors(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		wantErr string
	}{
		{"unknown service", `X = "${service.ghost.host}"`, "not declared in project"},
		{"unknown port", `X = "${service.postgres.port.nope}"`, "no port named"},
		{"port on a service with no ports", `X = "${service.assets.port.http}"`, "no port named"},
		{"self reference", `X = "${service.api.host}"`, "references itself"},
		{"unknown attribute", `X = "${service.postgres.hostname}"`, "Unknown service attribute"},
		{"port without a name", `X = "${service.postgres.port}"`, "needs a port name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "api" {
  project = "shop"
  task "api" {
    image = "api:1"
    env = { ` + tc.env + ` }
  }
}
service "postgres" {
  project = "shop"
  task "db" { image = "postgres:17" }
  network {
    port "pg" {
      container = 5432
    }
  }
}
service "assets" {
  project = "shop"
  task "cdn" { image = "nginx" }
}
`
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestCrossProjectReferenceIsRejectedWithABetterMessage(t *testing.T) {
	// R9: same-project only in v1 — and the diagnostic should say which project
	// the target actually lives in, not just "unknown service".
	out := parseErr(t, `
spec_version = 1
project "shop" {}
project "bank" {}

service "api" {
  project = "shop"
  task "api" {
    image = "api:1"
    env = { DATABASE_HOST = "${service.ledger.host}" }
  }
}

service "ledger" {
  project = "bank"
  task "db" { image = "postgres:17" }
}
`)
	if !strings.Contains(out, `belongs to project "bank"`) || !strings.Contains(out, "same-project only") {
		t.Errorf("diagnostics = %q", out)
	}
}

func TestDependencyCyclesAreRejectedWithThePath(t *testing.T) {
	// R9: "cycles are rejected with the cycle shown in the diagnostic".
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "two-service cycle via depends_on",
			src: `
spec_version = 1
project "shop" {}
service "a" {
  project = "shop"
  depends_on = ["b"]
  task "t" { image = "x" }
}
service "b" {
  project = "shop"
  depends_on = ["a"]
  task "t" { image = "x" }
}`,
			want: []string{"a -> b -> a"},
		},
		{
			name: "three-service cycle",
			src: `
spec_version = 1
project "shop" {}
service "a" {
  project = "shop"
  depends_on = ["b"]
  task "t" { image = "x" }
}
service "b" {
  project = "shop"
  depends_on = ["c"]
  task "t" { image = "x" }
}
service "c" {
  project = "shop"
  depends_on = ["a"]
  task "t" { image = "x" }
}`,
			want: []string{"a -> b -> c -> a"},
		},
		{
			name: "cycle formed by references, not depends_on",
			src: `
spec_version = 1
project "shop" {}
service "a" {
  project = "shop"
  task "t" {
    image = "x"
    env = { PEER = "${service.b.host}" }
  }
}
service "b" {
  project = "shop"
  task "t" {
    image = "x"
    env = { PEER = "${service.a.host}" }
  }
}`,
			want: []string{"a -> b -> a"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := parseErr(t, tc.src)
			if !strings.Contains(out, "Dependency cycle") {
				t.Fatalf("diagnostics = %q", out)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("diagnostics = %q, want the cycle path %q", out, want)
				}
			}
		})
	}
}

func TestAcyclicDiamondIsAccepted(t *testing.T) {
	// A diamond is not a cycle; a naive visited-set check would reject it.
	parse(t, `
spec_version = 1
project "shop" {}
service "top" {
  project    = "shop"
  depends_on = ["left", "right"]
  task "t" { image = "x" }
}
service "left" {
  project    = "shop"
  depends_on = ["bottom"]
  task "t" { image = "x" }
}
service "right" {
  project    = "shop"
  depends_on = ["bottom"]
  task "t" { image = "x" }
}
service "bottom" {
  project = "shop"
  task "t" { image = "x" }
}
`)
}

func TestDependsOnErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "unknown dependency",
			src: `
spec_version = 1
project "shop" {}
service "a" {
  project    = "shop"
  depends_on = ["ghost"]
  task "t" { image = "x" }
}`,
			wantErr: "Unknown dependency",
		},
		{
			name: "self dependency",
			src: `
spec_version = 1
project "shop" {}
service "a" {
  project    = "shop"
  depends_on = ["a"]
  task "t" { image = "x" }
}`,
			wantErr: "depends on itself",
		},
		{
			name: "cross-project dependency",
			src: `
spec_version = 1
project "shop" {}
project "bank" {}
service "a" {
  project    = "shop"
  depends_on = ["ledger"]
  task "t" { image = "x" }
}
service "ledger" {
  project = "bank"
  task "t" { image = "x" }
}`,
			wantErr: "same-project only",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if out := parseErr(t, tc.src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestPortValidation(t *testing.T) {
	tests := []struct {
		name    string
		network string
		wantErr string
	}{
		{"valid", `network {
    port "http" {
      container = 8080
    }
  }`, ""},
		{"port zero", "network {\n port \"http\" {\n container = 0\n }\n}", "1-65535"},
		{"port too high", "network {\n port \"http\" {\n container = 70000\n }\n}", "1-65535"},
		{"negative", "network {\n port \"http\" {\n container = -1\n }\n}", "1-65535"},
		{
			"duplicate name",
			"network {\n port \"http\" {\n container = 80\n }\n port \"http\" {\n container = 81\n }\n}",
			"Duplicate port name",
		},
		{"invalid name", "network {\n port \"HTTP\" {\n container = 80\n }\n}", "not a DNS-1123 label"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  ` + tc.network + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestVolumeValidation(t *testing.T) {
	tests := []struct {
		name    string
		volumes string
		wantErr string
	}{
		{
			"valid",
			"volume \"data\" {\n storage = \"local-ssd\"\n mount_path = \"/var/lib/data\"\n}",
			"",
		},
		{
			"relative mount path",
			"volume \"data\" {\n storage = \"local-ssd\"\n mount_path = \"var/lib/data\"\n}",
			"must be absolute",
		},
		{
			"duplicate name",
			"volume \"data\" {\n storage = \"a\"\n mount_path = \"/a\"\n}\nvolume \"data\" {\n storage = \"b\"\n mount_path = \"/b\"\n}",
			"Duplicate volume name",
		},
		{
			"conflicting mount path",
			"volume \"one\" {\n storage = \"a\"\n mount_path = \"/data\"\n}\nvolume \"two\" {\n storage = \"b\"\n mount_path = \"/data\"\n}",
			"Conflicting mount path",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
storage "local-ssd" {
  type = "local"
}
storage "a" {
  type = "local"
}
storage "b" {
  type = "local"
}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  ` + tc.volumes + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

// Passthrough blocks name a grant and never a path (R17, R18). The spec is
// checked for shape only — whether the node has the grant is a server-config
// question this package deliberately cannot answer.
func TestPassthroughValidation(t *testing.T) {
	tests := []struct {
		name    string
		blocks  string
		volumes string
		wantErr string
	}{
		{
			name:   "a device grant",
			blocks: "device \"dri\" {\n  grant = \"gpu\"\n}",
		},
		{
			name:   "a socket grant",
			blocks: "socket \"runtime\" {\n  grant = \"containerd\"\n  mount_path = \"/var/run/docker.sock\"\n}",
		},
		{
			name:    "missing device grant",
			blocks:  "device \"dri\" {\n  grant = \"\"\n}",
			wantErr: "Missing grant",
		},
		{
			name:    "grant name no node config could define",
			blocks:  "device \"dri\" {\n  grant = \"My_GPU\"\n}",
			wantErr: "Invalid grant name",
		},
		{
			name:    "device name that is not a label",
			blocks:  "device \"My Device\" {\n  grant = \"gpu\"\n}",
			wantErr: "Invalid name",
		},
		{
			name: "duplicate passthrough names",
			blocks: "device \"thing\" {\n  grant = \"gpu\"\n}\n" +
				"socket \"thing\" {\n  grant = \"containerd\"\n  mount_path = \"/run/d.sock\"\n}",
			wantErr: "already declared",
		},
		{
			name:    "relative socket mount path",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"var/run/docker.sock\"\n}",
			wantErr: "must be absolute",
		},
		{
			name:    "traversal in a socket mount path",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"/var/../etc/docker.sock\"\n}",
			wantErr: "must not contain",
		},
		{
			name:    "socket mount path that is not simplest form",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"/var/run//d.sock\"\n}",
			wantErr: "simplest form",
		},
		{
			name:    "socket over the root filesystem",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"/\"\n}",
			wantErr: "root filesystem",
		},
		// /dev is the tmpfs a granted device is created in, and /proc and /sys
		// are what the masked-path list applies to. Binding over one of them
		// from a spec would undo a default the spec is constrained by.
		{
			name:    "socket over /dev",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"/dev/kanea.sock\"\n}",
			wantErr: "the sandbox owns",
		},
		{
			name:    "socket over /proc",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"/proc/d.sock\"\n}",
			wantErr: "the sandbox owns",
		},
		{
			name: "two sockets on one path",
			blocks: "socket \"a\" {\n  grant = \"containerd\"\n  mount_path = \"/run/d.sock\"\n}\n" +
				"socket \"b\" {\n  grant = \"containerd\"\n  mount_path = \"/run/d.sock\"\n}",
			wantErr: "Conflicting mount path",
		},
		// A socket and a volume claiming one path is the same mistake as two
		// volumes doing it, and must be caught across the block kinds.
		{
			name:    "a socket over a declared volume",
			blocks:  "socket \"rt\" {\n  grant = \"containerd\"\n  mount_path = \"/var/lib/data\"\n}",
			volumes: "volume \"data\" {\n  storage = \"local-ssd\"\n  mount_path = \"/var/lib/data\"\n}",
			wantErr: "Conflicting mount path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
storage "local-ssd" {
  type = "local"
}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    ` + tc.blocks + `
  }
  ` + tc.volumes + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

// There is no field to write a device path into. This is the property the whole
// grant model rests on, so it is asserted rather than assumed.
func TestASpecCannotNameADevicePath(t *testing.T) {
	src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    device "dri" {
      grant = "gpu"
      path  = "/dev/mem"
    }
  }
}
`
	if out := parseErr(t, src); !strings.Contains(out, "path") {
		t.Errorf("diagnostics = %q, want a complaint about the path argument", out)
	}
}

func TestPassthroughBlocksReachTheParsedSpec(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    device "dri" {
      grant = "gpu"
    }
    socket "runtime" {
      grant      = "containerd"
      mount_path = "/var/run/docker.sock"
    }
  }
}
`)
	task := spec.Services[0].Task
	if len(task.Devices) != 1 || task.Devices[0].Grant != "gpu" {
		t.Fatalf("devices = %+v, want one grant of gpu", task.Devices)
	}
	if len(task.Sockets) != 1 {
		t.Fatalf("sockets = %+v, want one", task.Sockets)
	}
	if got := task.Sockets[0].MountPath; got != "/var/run/docker.sock" {
		t.Errorf("mount_path = %q, want /var/run/docker.sock", got)
	}
}

// R19: auto-update follows a tag, so the parse-time job is to refuse the
// requests that cannot mean anything.
func TestAutoUpdateValidation(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		build   string
		update  string
		wantErr string
	}{
		{
			name:   "a tag to follow",
			image:  "jellyfin/jellyfin:10.9",
			update: "update {\n    auto = true\n  }",
		},
		{
			name:   "explicit interval and deadline",
			image:  "nginx:1.27",
			update: "update {\n    auto     = true\n    interval = \"30m\"\n    deadline = \"5m\"\n  }",
		},
		{
			name:   "auto off needs nothing",
			image:  "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			update: "update {\n    max_parallel = 2\n  }",
		},
		// A digest never moves, so this is a contradiction rather than a no-op.
		// Read as a no-op it would leave someone believing their service
		// updates when nothing ever will.
		{
			name:    "following a digest",
			image:   "nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			update:  "update {\n    auto = true\n  }",
			wantErr: "needs a tag, not a digest",
		},
		{
			name:    "auto with a build block",
			image:   "nginx:1.27",
			build:   "build {\n    context = \".\"\n    target  = \"registry.example.com/web\"\n  }",
			update:  "update {\n    auto = true\n  }",
			wantErr: "conflicts with build",
		},
		{
			name:    "interval below the floor",
			image:   "nginx:1.27",
			update:  "update {\n    auto     = true\n    interval = \"30s\"\n  }",
			wantErr: "too short",
		},
		{
			name:    "unparseable interval",
			image:   "nginx:1.27",
			update:  "update {\n    auto     = true\n    interval = \"soon\"\n  }",
			wantErr: "interval",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  ` + tc.build + `
  task "app" {
    image = "` + tc.image + `"
  }
  ` + tc.update + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

// The pull credential is scoped exactly like the push one (R19, R5).
func TestRegistryAuthRefIsProjectScoped(t *testing.T) {
	spec := func(ref string) string {
		return `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image             = "registry.example.com/web:1"
    registry_auth_ref = "` + ref + `"
  }
}
`
	}

	parse(t, spec("secret:shop/registry"))
	parse(t, spec("secret:shared/registry"))

	if out := parseErr(t, spec("secret:analytics/registry")); !strings.Contains(out, "Cross-project") {
		t.Errorf("diagnostics = %q, want a cross-project refusal", out)
	}
	if out := parseErr(t, spec("dXNlcjpwYXNz")); !strings.Contains(out, "not a secret reference") {
		t.Errorf("diagnostics = %q, want a refusal to inline a credential", out)
	}
}

func TestScalingValidation(t *testing.T) {
	tests := []struct {
		name    string
		count   string
		scaling string
		wantErr string
	}{
		{
			name:    "valid",
			count:   "count = 3",
			scaling: "scaling {\n min = 2\n max = 10\n metric \"cpu\" {\n target = 70\n }\n}",
		},
		{
			name:    "min above max",
			count:   "count = 3",
			scaling: "scaling {\n min = 10\n max = 2\n}",
			wantErr: "exceeds max",
		},
		{
			name:    "count below min",
			count:   "count = 1",
			scaling: "scaling {\n min = 3\n max = 10\n}",
			wantErr: "outside scaling bounds",
		},
		{
			name:    "non-positive metric target",
			count:   "count = 3",
			scaling: "scaling {\n min = 1\n max = 5\n metric \"cpu\" {\n target = 0\n }\n}",
			wantErr: "must be positive",
		},
		{
			name:    "bad cooldown",
			count:   "count = 3",
			scaling: "scaling {\n min = 1\n max = 5\n cooldown = \"later\"\n}",
			wantErr: "Invalid duration",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  ` + tc.count + `
  task "app" { image = "nginx" }
  ` + tc.scaling + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestExactlyOneTaskPerService(t *testing.T) {
	out := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "one" { image = "nginx" }
  task "two" { image = "redis" }
}
`)
	if !strings.Contains(out, "Multiple tasks") {
		t.Errorf("diagnostics = %q", out)
	}

	out = parseErr(t, `
spec_version = 1
project "shop" {}
service "web" { project = "shop" }
`)
	if !strings.Contains(out, "no task") {
		t.Errorf("diagnostics = %q", out)
	}
}

func TestVariableInterpolation(t *testing.T) {
	// R2: ${VAR} from -var-file and built-ins.
	spec, diags := jobspec.ParseSource(
		jobspec.Options{Vars: map[string]string{"GIT_SHA_SHORT": "abc1234", "REGISTRY": "reg.example.com"}},
		"test.hcl",
		[]byte(`
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  build {
    context = "./web"
    target  = "${REGISTRY}/shop/web"
    tag     = "${GIT_SHA_SHORT}"
  }
  task "app" { image = "${REGISTRY}/shop/web:${GIT_SHA_SHORT}" }
}
`))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	svc := spec.ServiceByName("shop", "web")
	if svc.Build.Tag != "abc1234" {
		t.Errorf("build.tag = %q, want abc1234", svc.Build.Tag)
	}
	if svc.Task.Image != "reg.example.com/shop/web:abc1234" {
		t.Errorf("image = %q", svc.Task.Image)
	}
}

func TestUndefinedVariableIsReported(t *testing.T) {
	out := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "${NOPE}/x" }
}
`)
	if !strings.Contains(out, "test.hcl:") {
		t.Errorf("diagnostics lack a source position: %q", out)
	}
}

func TestDiagnosticsCarryPositions(t *testing.T) {
	// R1: "parse errors abort the run with line/column diagnostics".
	out := parseErr(t, minimalSpec+`
service "BAD_NAME" {
  project = "shop"
  task "app" { image = "nginx" }
}
`)
	if !strings.Contains(out, "test.hcl:") {
		t.Fatalf("diagnostic has no file:line: %q", out)
	}
	if !strings.Contains(out, "Error:") {
		t.Errorf("diagnostic has no severity: %q", out)
	}
}

func TestParseFilesMergesAndIsOrderIndependent(t *testing.T) {
	// R9: references are validated against the full applied set; file order and
	// declaration order are irrelevant.
	dir := t.TempDir()
	apiFile := filepath.Join(dir, "api.hcl")
	dbFile := filepath.Join(dir, "db.hcl")

	if err := os.WriteFile(apiFile, []byte(`
spec_version = 1
project "shop" {}
service "api" {
  project = "shop"
  task "api" {
    image = "api:1"
    env = { DATABASE_HOST = "${service.postgres.host}" }
  }
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbFile, []byte(`
service "postgres" {
  project = "shop"
  task "db" { image = "postgres:17" }
  network {
    port "pg" {
      container = 5432
    }
  }
}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, order := range [][]string{{apiFile, dbFile}, {dbFile, apiFile}} {
		spec, diags := jobspec.ParseFiles(jobspec.Options{}, order...)
		if diags.HasErrors() {
			t.Fatalf("order %v: %s", order, jobspec.FormatDiagnostics(diags))
		}
		if got := spec.ServiceByName("shop", "api").Task.Env["DATABASE_HOST"]; got != "postgres.shop.kanea" {
			t.Errorf("order %v: DATABASE_HOST = %q", order, got)
		}
	}
}

func TestParseFilesReportsMissingFile(t *testing.T) {
	_, diags := jobspec.ParseFiles(jobspec.Options{}, filepath.Join(t.TempDir(), "nope.hcl"))
	if !diags.HasErrors() {
		t.Fatal("expected an error for a missing file")
	}
	if out := jobspec.FormatDiagnostics(diags); !strings.Contains(out, "Cannot read job spec") {
		t.Errorf("diagnostics = %q", out)
	}
}

func TestParseSourceRejectsSyntaxErrors(t *testing.T) {
	out := parseErr(t, `spec_version = 1
project "shop" {
`)
	if !strings.Contains(out, "test.hcl:") {
		t.Errorf("syntax error lacks a position: %q", out)
	}
}

func TestEmptyInputIsRejected(t *testing.T) {
	_, diags := jobspec.ParseFiles(jobspec.Options{})
	if !diags.HasErrors() {
		t.Fatal("expected an error for no files")
	}
}

func TestServiceHostFormat(t *testing.T) {
	if got := jobspec.ServiceHost("shop", "postgres"); got != "postgres.shop.kanea" {
		t.Errorf("ServiceHost = %q, want postgres.shop.kanea", got)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"10s", false},
		{"2m", false},
		{"1h30m", false},
		{"", true},
		{"10", true},
		{"soon", true},
		{"-5s", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			_, err := jobspec.ParseDuration(tc.in)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("ParseDuration(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestSpecLookupHelpers(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
project "blog" {}
service "web" {
  project = "shop"
  task "t" { image = "x" }
}
service "api" {
  project = "shop"
  task "t" { image = "x" }
}
service "cms" {
  project = "blog"
  task "t" { image = "x" }
}
`)
	if spec.ProjectByName("shop") == nil || spec.ProjectByName("ghost") != nil {
		t.Error("ProjectByName")
	}
	if spec.ServiceByName("shop", "web") == nil || spec.ServiceByName("blog", "web") != nil {
		t.Error("ServiceByName must be project-scoped")
	}
	if got := len(spec.ServicesInProject("shop")); got != 2 {
		t.Errorf("ServicesInProject(shop) = %d, want 2", got)
	}
}

// TestPRDExampleParses is the guard AGENTS.md asks for: "keep the PRD §6
// examples valid". testdata/prd-6.1-example.hcl is extracted verbatim from
// PRD §6.1, so a spec change that invalidates the documented example fails
// here rather than in a user's terminal.
func TestPRDExampleParses(t *testing.T) {
	spec, diags := jobspec.ParseFiles(
		jobspec.Options{Vars: map[string]string{"GIT_SHA_SHORT": "abc1234"}},
		filepath.Join("testdata", "prd-6.1-example.hcl"),
	)
	if diags.HasErrors() {
		t.Fatalf("the PRD §6.1 example does not parse:\n%s", jobspec.FormatDiagnostics(diags))
	}

	// Spot-check the parts the example exists to demonstrate.
	if spec.ProjectByName("shop") == nil {
		t.Fatal("project shop missing")
	}
	for _, name := range []string{"web", "api", "postgres", "assets"} {
		if spec.ServiceByName("shop", name) == nil {
			t.Errorf("service %q missing", name)
		}
	}

	api := spec.ServiceByName("shop", "api")
	if got := api.Task.Env["DATABASE_HOST"]; got != "postgres.shop.kanea" {
		t.Errorf("DATABASE_HOST = %q, want postgres.shop.kanea", got)
	}
	if got := api.Task.Env["DATABASE_PORT"]; got != "5432" {
		t.Errorf("DATABASE_PORT = %q, want 5432", got)
	}
	// depends_on plus the reference edges from env, merged and deduplicated.
	if got := strings.Join(api.Dependencies, ","); got != "assets,postgres" {
		t.Errorf("api dependencies = %q, want \"assets,postgres\"", got)
	}

	web := spec.ServiceByName("shop", "web")
	if web.Count != 3 {
		t.Errorf("web count = %d, want 3", web.Count)
	}
	if web.Build == nil || web.Build.Tag != "abc1234" {
		t.Errorf("web build = %+v (GIT_SHA_SHORT should interpolate)", web.Build)
	}
	if web.Expose == nil || len(web.Expose.Domains) != 2 {
		t.Errorf("web expose = %+v", web.Expose)
	}
}

func TestTaskCommandIsAnArgumentArray(t *testing.T) {
	// R12: an argument array, never a shell string.
	spec := parse(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image   = "nginx:1.27-alpine"
    command = ["nginx", "-g", "daemon off;"]
  }
}
`)
	got := spec.ServiceByName("shop", "web").Task.Command
	want := []string{"nginx", "-g", "daemon off;"}
	if len(got) != len(want) {
		t.Fatalf("command = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command = %v, want %v", got, want)
		}
	}

	// An empty *argument* is legitimate: `redis-server --save ""` is the
	// documented way to disable snapshots.
	parse(t, `
spec_version = 1
project "shop" {}
service "cache" {
  project = "shop"
  task "app" {
    image   = "redis:7-alpine"
    command = ["redis-server", "--save", "", "--appendonly", "no"]
  }
}
`)

	// An empty *program* is not: there is nothing to run.
	out := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image   = "nginx"
    command = ["", "-g"]
  }
}
`)
	if !strings.Contains(out, "cannot be empty") {
		t.Errorf("diagnostics = %q", out)
	}
}

func TestCapabilityAllowlist(t *testing.T) {
	// R13: only the permitted set may be requested, and privilege-equivalent
	// capabilities are refused with an explanation.
	tests := []struct {
		name    string
		caps    string
		wantErr string
	}{
		{"nginx needs chown", `["CAP_CHOWN"]`, ""},
		{"redis drops privileges", `["CAP_SETUID", "CAP_SETGID"]`, ""},
		{"binding port 80", `["CAP_NET_BIND_SERVICE"]`, ""},
		{"empty list", `[]`, ""},
		{"sys_admin is refused", `["CAP_SYS_ADMIN"]`, "equivalent to root"},
		{"ptrace is refused", `["CAP_SYS_PTRACE"]`, "escaping the container"},
		{"net_admin is refused", `["CAP_NET_ADMIN"]`, "Kanea's own datapath"},
		{"bpf is refused", `["CAP_BPF"]`, "host-level control"},
		{"unknown capability", `["CAP_NONSENSE"]`, "unknown or unsupported"},
		{"missing prefix", `["CHOWN"]`, "CAP_ prefix"},
		{"duplicate", `["CAP_CHOWN", "CAP_CHOWN"]`, "listed twice"},
		{"empty name", `[""]`, "empty capability name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image        = "nginx"
    capabilities = ` + tc.caps + `
  }
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

func TestForbiddenCapabilityDiagnosticSaysWhy(t *testing.T) {
	// "Not allowed" is not enough: the operator needs to know it is refused
	// because it is equivalent to privilege, not because of a typo.
	out := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image        = "nginx"
    capabilities = ["CAP_SYS_MODULE"]
  }
}
`)
	if !strings.Contains(out, "no privileged escape hatch") {
		t.Errorf("diagnostics = %q, want the reasoning spelled out", out)
	}
}

func TestNormalizeCapabilities(t *testing.T) {
	got := jobspec.NormalizeCapabilities([]string{"cap_setuid", "CAP_CHOWN", " CAP_CHOWN ", ""})
	want := []string{"CAP_CHOWN", "CAP_SETUID"}
	if len(got) != len(want) {
		t.Fatalf("normalized = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalized = %v, want %v (sorted and deduplicated)", got, want)
		}
	}
}

// R14: the per-service ingress allowlist. Every entry is checked at parse time
// because a network rule that fails to match denies silently — the failure mode
// this whole area is prone to.
func TestNetworkPolicyValidation(t *testing.T) {
	spec := func(allowFrom string) string {
		return `spec_version = 1
project "shop" {}
service "api" {
  project = "shop"
  task "app" { image = "busybox:1.37" }
  network {
    port "http" { container = 8080 }
    policy {
      allow_from = [` + allowFrom + `]
    }
  }
}`
	}

	tests := []struct {
		name      string
		allowFrom string
		want      string
	}{
		{name: "cross-project peer", allowFrom: `"analytics/collector"`},
		{
			// Redundant but harmless: the project default already permits it,
			// and being explicit stays correct if that default ever changes.
			name: "same-project peer is accepted", allowFrom: `"shop/web"`,
		},
		{
			name: "bare service name", allowFrom: `"collector"`,
			want: "<project>/<service>",
		},
		{
			// A wildcard would open a whole project at once; naming the peer is
			// the point of the field.
			name: "wildcard service", allowFrom: `"analytics/*"`,
			want: "wildcard",
		},
		{
			name: "wildcard project", allowFrom: `"*/collector"`,
			want: "wildcard",
		},
		{
			name: "too many separators", allowFrom: `"a/b/c"`,
			want: "more than one",
		},
		{
			name: "peer that is not a DNS label", allowFrom: `"Analytics/collector"`,
			want: "DNS-1123",
		},
		{
			name: "duplicate entry", allowFrom: `"analytics/collector", "analytics/collector"`,
			want: "listed twice",
		},
		{
			name: "service allows itself", allowFrom: `"shop/api"`,
			want: "reach itself",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == "" {
				parse(t, spec(tc.allowFrom))
				return
			}
			if got := parseErr(t, spec(tc.allowFrom)); !strings.Contains(got, tc.want) {
				t.Fatalf("diagnostics:\n%s\nwant a mention of %q", got, tc.want)
			}
		})
	}
}

// The parsed form is what the reconciler consumes, and a service with no policy
// block is by far the common case — so a nil block must be safe to read.
func TestNetworkPolicyPeers(t *testing.T) {
	var absent *jobspec.NetworkPolicy
	if got := absent.Peers(); got != nil {
		t.Errorf("Peers() on a nil policy = %v, want nil", got)
	}

	policy := &jobspec.NetworkPolicy{AllowFrom: []string{"analytics/collector", "ops/agent"}}
	peers := policy.Peers()
	if len(peers) != 2 {
		t.Fatalf("peers = %v", peers)
	}
	if peers[0].String() != "analytics/collector" || peers[1].String() != "ops/agent" {
		t.Errorf("peers = %v", peers)
	}
}

// R15's parse-time half: only the *shape* of a host path is decided here. Which
// paths are permitted is a server-config question that a job spec has no
// business answering.
func TestHostStorageValidation(t *testing.T) {
	spec := func(path string) string {
		return `spec_version = 1
project "shop" {}
storage "app-config" {
  type = "host"
  path = ` + path + `
}
service "web" {
  project = "shop"
  task "app" { image = "busybox:1.37" }
  volume "config" {
    storage    = "app-config"
    mount_path = "/etc/app"
  }
}`
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "absolute path", path: `"/srv/shop/config"`},
		{name: "missing path", path: `""`, want: "absolute `path`"},
		{name: "relative path", path: `"srv/config"`, want: "must be absolute"},
		// Refused rather than cleaned away: ".." is either a mistake or an
		// attempt to walk out of an allowlisted prefix, and silently rewriting
		// it would hide both.
		{name: "parent traversal", path: `"/srv/../etc"`, want: `must not contain`},
		{name: "trailing slash is not simplest form", path: `"/srv/config/"`, want: "simplest form"},
		{name: "root filesystem", path: `"/"`, want: "never permitted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == "" {
				parse(t, spec(tc.path))
				return
			}
			if got := parseErr(t, spec(tc.path)); !strings.Contains(got, tc.want) {
				t.Fatalf("diagnostics:\n%s\nwant a mention of %q", got, tc.want)
			}
		})
	}
}

// gitSpec is a project with a git block, for the validation cases below.
func gitSpec(block string) string {
	return `
spec_version = 1

project "shop" {
  git {
    url = "https://github.com/example/deploy.git"
    ` + block + `
  }
}
`
}

// R5 says a reference names the declaring project's scope or `shared/`, and
// that git, registry, storage and notification credentials all follow it. The
// PRD's own §6.1 example did not, which is what this catches (v1.22).
func TestGitCredentialsAreProjectScoped(t *testing.T) {
	valid := []struct{ name, block string }{
		{"own project", `auth_ref = "secret:shop/deploy-key"`},
		{"shared", `auth_ref = "secret:shared/deploy-key"`},
		{"webhook secret in scope", `webhook_secret_ref = "secret:shop/hook"`},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			parse(t, gitSpec(tc.block))
		})
	}

	invalid := []struct{ name, block, want string }{
		{"another project", `auth_ref = "secret:blog/deploy-key"`, "Cross-project"},
		{"inlined credential", `auth_ref = "ghp_averyrealtokenpastedinline"`, "not a secret reference"},
		{"malformed reference", `auth_ref = "secret:deploy-key"`, "Malformed"},
		{"webhook secret out of scope", `webhook_secret_ref = "secret:blog/hook"`, "Cross-project"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseErr(t, gitSpec(tc.block)); !strings.Contains(got, tc.want) {
				t.Fatalf("diagnostics = %s\nwant something about %q", got, tc.want)
			}
		})
	}
}

func TestGitPollIntervalMustParse(t *testing.T) {
	// A typo should fail `kanea plan`, in front of the person who made it, not
	// sixty seconds later inside a poll loop nobody is watching.
	got := parseErr(t, gitSpec(`poll_interval = "every so often"`))
	if !strings.Contains(got, "poll_interval") {
		t.Fatalf("diagnostics = %s; they do not name the field", got)
	}
}

func TestGitSourceNeedsAURL(t *testing.T) {
	src := `
spec_version = 1

project "shop" {
  git {
    url = ""
  }
}
`
	if got := parseErr(t, src); !strings.Contains(got, "url") {
		t.Fatalf("diagnostics = %s", got)
	}
}

func TestUpdateStrategyMustBeKnown(t *testing.T) {
	// A strategy nobody implements has to be rejected at parse time. Accepting
	// it and quietly rolling instead would mean the spec says one thing and the
	// deploy does another — on the operation where a surprise costs the most.
	got := parseErr(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  count   = 2
  task "web" { image = "nginx:1.27" }
  update { strategy = "canary" }
}
`)
	if !strings.Contains(got, "Unknown update strategy") {
		t.Errorf("diagnostic did not name the problem:\n%s", got)
	}
}

func TestUpdateBlockAcceptsTheDocumentedForm(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  count   = 2
  task "web" { image = "nginx:1.27" }
  update {
    strategy     = "rolling"
    max_parallel = 1
    min_healthy  = "30s"
  }
}
`)
	up := spec.Services[0].Update
	if up == nil {
		t.Fatal("the update block was parsed away")
	}
	if up.Strategy != "rolling" || up.MaxParallel != 1 || up.MinHealthy != "30s" {
		t.Errorf("update = %+v, want the declared values", *up)
	}
}

// R23/R24: who a container runs as, and who owns its data.

func TestUserAndVolumeOwnershipValidation(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		storage string
		volume  string
		wantErr string
	}{
		{
			name: "a uid and gid",
			user: "user {\n  uid = 999\n  gid = 999\n}",
		},
		{
			name: "supplementary groups",
			user: "user {\n  uid = 999\n  gid = 999\n  groups = [1000, 2000]\n}",
		},
		{
			name: "root asked for explicitly",
			user: "user {\n  uid = 0\n  gid = 0\n}",
		},
		{
			name:    "a negative uid",
			user:    "user {\n  uid = -1\n}",
			wantErr: "must not be negative",
		},
		{
			name:    "a uid past the end of uid_t",
			user:    "user {\n  uid = 4294967296\n}",
			wantErr: "largest allowed",
		},
		// (uid_t)-1 is chown(2)'s "leave unchanged" sentinel, so a workload
		// asking to run as it is asking for something that is not a user.
		{
			name:    "the unchanged sentinel",
			user:    "user {\n  gid = 4294967295\n}",
			wantErr: "largest allowed",
		},
		{
			name:    "a duplicated supplementary group",
			user:    "user {\n  uid = 999\n  groups = [1000, 1000]\n}",
			wantErr: "Duplicate supplementary group",
		},
		{
			name:    "a negative supplementary group",
			user:    "user {\n  uid = 999\n  groups = [-5]\n}",
			wantErr: "must not be negative",
		},
		// There is no field for a username. This is the property R23 rests on.
		{
			name:    "a username",
			user:    "user {\n  name = \"postgres\"\n}",
			wantErr: "name",
		},
		{
			name:   "an explicit volume mode",
			volume: "volume \"d\" {\n  storage = \"local-ssd\"\n  mount_path = \"/d\"\n  mode = \"0770\"\n}",
		},
		{
			name:   "a mode without its leading zero",
			volume: "volume \"d\" {\n  storage = \"local-ssd\"\n  mount_path = \"/d\"\n  mode = \"770\"\n}",
		},
		{
			name:    "a mode that is not octal",
			volume:  "volume \"d\" {\n  storage = \"local-ssd\"\n  mount_path = \"/d\"\n  mode = \"0778\"\n}",
			wantErr: "Invalid volume mode",
		},
		{
			name:    "a mode setting the setuid bit",
			volume:  "volume \"d\" {\n  storage = \"local-ssd\"\n  mount_path = \"/d\"\n  mode = \"4755\"\n}",
			wantErr: "above 0777",
		},
		{
			name:    "a volume uid past the end of uid_t",
			volume:  "volume \"d\" {\n  storage = \"local-ssd\"\n  mount_path = \"/d\"\n  uid = 4294967296\n}",
			wantErr: "Invalid volume uid",
		},
		// A host directory is the operator's: R15 says Kanea never creates it
		// and never deletes it, and chowning it is the same trespass.
		{
			name:    "ownership on a host volume",
			storage: "storage \"h\" {\n  type = \"host\"\n  path = \"/srv/data\"\n}",
			volume:  "volume \"d\" {\n  storage = \"h\"\n  mount_path = \"/d\"\n  uid = 999\n}",
			wantErr: "cannot own a volume",
		},
		// The kernel NFS client has no uid= at all; ownership is the server's.
		{
			name:    "ownership on an nfs volume",
			storage: "storage \"n\" {\n  type = \"nfs\"\n  server = \"10.0.0.5\"\n  export = \"/e\"\n}",
			volume:  "volume \"d\" {\n  storage = \"n\"\n  mount_path = \"/d\"\n  gid = 999\n}",
			wantErr: "no uid= or gid= mount option",
		},
		// Inheritance stops at a driver that cannot carry ownership. Adding a
		// user block to a task must not break the NFS volume it happens to
		// have — there would be no way to say "not that one" — and the task's
		// user is a statement about the process, not about the NFS server.
		{
			name:    "an nfs volume in a service whose task names a user",
			user:    "user {\n  uid = 999\n  gid = 999\n}",
			storage: "storage \"n\" {\n  type = \"nfs\"\n  server = \"10.0.0.5\"\n  export = \"/e\"\n}",
			volume:  "volume \"d\" {\n  storage = \"n\"\n  mount_path = \"/d\"\n}",
		},
		{
			name:    "a host volume in a service whose task names a user",
			user:    "user {\n  uid = 999\n  gid = 999\n}",
			storage: "storage \"h\" {\n  type = \"host\"\n  path = \"/srv/data\"\n}",
			volume:  "volume \"d\" {\n  storage = \"h\"\n  mount_path = \"/d\"\n}",
		},
		// smb and s3 take ownership at mount time, so they are accepted.
		{
			name:    "ownership on an smb volume",
			storage: "storage \"s\" {\n  type = \"smb\"\n  server = \"10.0.0.5\"\n  share = \"x\"\n}",
			volume:  "volume \"d\" {\n  storage = \"s\"\n  mount_path = \"/d\"\n  uid = 999\n}",
		},
		{
			name:    "ownership on an s3 volume",
			storage: "storage \"b\" {\n  type = \"s3\"\n  bucket = \"x\"\n}",
			volume:  "volume \"d\" {\n  storage = \"b\"\n  mount_path = \"/d\"\n  uid = 999\n}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `
spec_version = 1
project "shop" {}
storage "local-ssd" {
  type = "local"
}
` + tc.storage + `
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    ` + tc.user + `
  }
  ` + tc.volume + `
}
`
			if tc.wantErr == "" {
				parse(t, src)
				return
			}
			if out := parseErr(t, src); !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
		})
	}
}

// A volume with no ownership of its own takes the task's. Without this the
// common spec carries the same two numbers twice, and forgetting the second
// copy fails at alloc start rather than at plan — the exact failure R23/R24
// exist to remove.
func TestVolumeOwnershipInheritsTheTaskUser(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
storage "local-ssd" { type = "local" }
service "db" {
  project = "shop"
  task "pg" {
    image = "postgres:17"
    user {
      uid = 999
      gid = 999
    }
  }
  volume "data" {
    storage    = "local-ssd"
    mount_path = "/var/lib/postgresql/data"
  }
  volume "shared" {
    storage    = "local-ssd"
    mount_path = "/shared"
    uid        = 0
    gid        = 999
    mode       = "0770"
  }
}
`)
	svc := spec.Services[0]
	if u := svc.Task.User; u == nil || u.UID != 999 || u.GID != 999 {
		t.Fatalf("task user = %+v, want 999:999", svc.Task.User)
	}

	data := svc.Volumes[0]
	if data.UID == nil || *data.UID != 999 || data.GID == nil || *data.GID != 999 {
		t.Errorf("inherited owner = %v:%v, want 999:999", deref(data.UID), deref(data.GID))
	}
	// 0700 rather than the 0750 an unowned volume is created with, and it is
	// also the only mode postgres will start on.
	if data.Mode == nil || *data.Mode != "0700" {
		t.Errorf("inherited mode = %v, want 0700", data.Mode)
	}

	// An explicit uid of 0 is a request for root, not an absent field.
	shared := svc.Volumes[1]
	if shared.UID == nil || *shared.UID != 0 {
		t.Errorf("explicit uid = %v, want 0", deref(shared.UID))
	}
	if shared.GID == nil || *shared.GID != 999 || shared.Mode == nil || *shared.Mode != "0770" {
		t.Errorf("explicit gid/mode = %v/%v, want 999/0770", deref(shared.GID), shared.Mode)
	}
}

// Inheritance stops at a driver that cannot carry ownership, and the volume is
// left unowned rather than refused.
//
// This is what keeps R24 additive. If inheritance applied and then failed
// validation, adding a `user` block to a task would break every host and NFS
// volume that service happened to have, with no field to opt out of a default
// nobody typed. A volume that declares ownership on one of these is still an
// error — that is a claim the spec made.
func TestOwnershipDoesNotInheritIntoADriverThatCannotCarryIt(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
storage "local-ssd" { type = "local" }
storage "shared-nfs" {
  type   = "nfs"
  server = "10.0.0.5"
  export = "/exports/shop"
}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx"
    user {
      uid = 999
      gid = 999
    }
  }
  volume "local" {
    storage    = "local-ssd"
    mount_path = "/local"
  }
  volume "remote" {
    storage    = "shared-nfs"
    mount_path = "/remote"
  }
}
`)
	svc := spec.Services[0]
	if v := svc.Volumes[0]; v.UID == nil || *v.UID != 999 {
		t.Errorf("local volume uid = %v, want the inherited 999", deref(v.UID))
	}
	if v := svc.Volumes[1]; v.Owned() {
		t.Errorf("nfs volume owned = %v:%v mode %v, want none — inheritance must stop here",
			deref(v.UID), deref(v.GID), v.Mode)
	}
}

// A task with no user block leaves its volumes exactly as every spec written
// before R24 leaves them. This is what makes the feature additive: nothing
// about an existing spec changes when the binary gains it.
func TestNoUserBlockLeavesVolumesUnowned(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
storage "local-ssd" { type = "local" }
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  volume "data" {
    storage    = "local-ssd"
    mount_path = "/data"
  }
}
`)
	svc := spec.Services[0]
	if svc.Task.User != nil {
		t.Errorf("task user = %+v, want nil", svc.Task.User)
	}
	if v := svc.Volumes[0]; v.Owned() {
		t.Errorf("volume owned = %v:%v mode %v, want none",
			deref(v.UID), deref(v.GID), v.Mode)
	}
}

// A volume may name an owner without the task naming one — a directory owned
// by a uid the image itself drops to. It still gets the default mode.
func TestVolumeMayDeclareOwnershipWithoutATaskUser(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}
storage "local-ssd" { type = "local" }
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  volume "data" {
    storage    = "local-ssd"
    mount_path = "/data"
    uid        = 101
  }
}
`)
	v := spec.Services[0].Volumes[0]
	if v.UID == nil || *v.UID != 101 {
		t.Fatalf("uid = %v, want 101", deref(v.UID))
	}
	if v.GID != nil {
		t.Errorf("gid = %v, want nil: an undeclared half is left unchanged", deref(v.GID))
	}
	if v.Mode == nil || *v.Mode != "0700" {
		t.Errorf("mode = %v, want the 0700 default", v.Mode)
	}
}

func TestParseMode(t *testing.T) {
	ok := map[string]uint32{"0700": 0o700, "700": 0o700, "0": 0, "0777": 0o777, "755": 0o755}
	for in, want := range ok {
		if got, err := jobspec.ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %04o, %v; want %04o", in, got, err, want)
		}
	}
	// "0778" is not octal; "1777" and "4755" set bits above 0777, which are
	// not permissions on a data directory. "00700" is longer than four digits.
	for _, in := range []string{"", "0778", "abc", "1777", "4755", "00700", "-1"} {
		if _, err := jobspec.ParseMode(in); err == nil {
			t.Errorf("ParseMode(%q) succeeded; want an error", in)
		}
	}
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}
