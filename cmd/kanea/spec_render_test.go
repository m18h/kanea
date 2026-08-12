package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
)

// renderText runs the real renderer over one file, as the API routes do.
func renderText(t *testing.T, text string) ([]reconciler.Desired, []gitops.Config) {
	t.Helper()
	r := specRenderer{opts: jobspec.Options{BaseDomain: "kanea.test"}}
	result, err := r.Render(map[string][]byte{"spec.hcl": []byte(text)})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, d := range result.Diagnostics {
		if d.Severity == "error" {
			t.Fatalf("render diagnostics: %s (%s:%d) — %s", d.Summary, d.File, d.Line, d.Detail)
		}
	}
	return result.Services, result.Pipelines
}

const roundTripSpec = `
spec_version = 1

project "shop" {}

service "web" {
  project = "shop"
  count   = 3

  depends_on = ["api"]

  task "app" {
    image = "registry.example.com/shop/web:1.14.0"

    # The "none" token and an explicit grant must both survive the round trip
    # in their stored, normalized forms (R13, v1.56).
    capabilities = ["none", "CAP_NET_RAW"]

    env = {
      NODE_ENV     = "production"
      DATABASE_URL = "secret:shop/database-url"
    }

    resources {
      cpu    = 500
      memory = 512
    }

    user {
      uid    = 1000
      gid    = 1000
      groups = [44]
    }
  }

  network {
    port "http" { container = 3000 }

    publish "http" {
      host = 8080
      ip_restriction { allow = ["192.168.0.0/16"] }
    }

    policy {
      allow_from = ["analytics/collector"]
    }
  }

  expose {
    domains = ["shop.example.com"]
    tls { mode = "acme" }

    rate_limit {
      requests = 100
      window   = "1m"
      per      = "ip"
      burst    = 20
    }

    auth { basic_ref = "secret:shop/web-users" }
  }

  health_check "http" {
    type     = "http"
    path     = "/healthz"
    port     = "http"
    interval = "10s"
    timeout  = "2s"
    failures = 3
  }

  scaling {
    min = 2
    max = 10
    metric "p95_latency_ms" { target = 80 }
    metric "rps" { target = 500 }
    cooldown = "2m"
  }

  update {
    strategy     = "rolling"
    max_parallel = 1
    min_healthy  = "30s"
  }

  restart {
    attempts = 5
    backoff  = "10s,30s,1m,5m"
  }
}

service "api" {
  project = "shop"
  count   = 2

  task "app" {
    image = "registry.example.com/shop/api:0.9.1"

    resources {
      cpu    = 250
      memory = 256
    }
  }

  network {
    port "http" { container = 8080 }
  }
}

service "search" {
  project = "shop"
  count   = 1

  task "app" {
    image = "registry.example.com/shop/search:4.2.0"

    resources {
      cpu    = 250
      memory = 256
    }
  }

  # The exposed port is named explicitly (R16, v1.49): neither port is named
  # "http", so the generator must emit port = "query" for the trip to hold.
  network {
    port "query"   { container = 7700 }
    port "metrics" { container = 9100 }
  }

  expose {
    domains = ["search.shop.example.com"]
    port    = "query"
    tls { mode = "acme" }
  }

  # A second route on the same service (v1.50): its own domains, port and TLS.
  expose {
    domains = ["search-metrics.shop.example.com"]
    port    = "metrics"
    tls { mode = "self-signed" }
    ip_restriction { allow = ["192.168.0.0/16"] }
  }
}

service "voice" {
  project = "shop"
  count   = 1

  task "app" {
    image = "registry.example.com/shop/voice:2.1.0"

    resources {
      cpu    = 500
      memory = 512
    }
  }

  network {
    port "rtp" {
      container = 10000
      protocol  = "udp"
    }

    publish "rtp" {
      host = 10000
      mode = "udp"
      ip_restriction { allow = ["192.168.0.0/16"] }
    }
  }
}
`

// TestGeneratedSpecRoundTripsToTheSameDesired is the gate on "edit spec"
// (v1.38): what toHCL writes must mean exactly what was running. A field that
// cannot survive the trip must refuse generation, never drift.
func TestGeneratedSpecRoundTripsToTheSameDesired(t *testing.T) {
	original, pipelines := renderText(t, roundTripSpec)
	if len(original) != 4 {
		t.Fatalf("services = %d, want 4", len(original))
	}

	text, err := toHCL(original, pipelines)
	if err != nil {
		t.Fatalf("toHCL: %v", err)
	}

	regenerated, _ := renderText(t, text)
	if len(regenerated) != len(original) {
		t.Fatalf("regenerated services = %d, want %d\n%s", len(regenerated), len(original), text)
	}

	for i := range original {
		want, got := original[i], regenerated[i]
		// The server-owned fields the apply path carries are not spec fields
		// and are zero on both sides here; everything else must match exactly.
		if !reflect.DeepEqual(want, got) {
			t.Errorf("service %s/%s did not round-trip.\nwant: %+v\ngot:  %+v\ngenerated:\n%s",
				want.Project, want.Service, want, got, text)
		}
	}
}

// R11 (v1.58): an omitted limit is unbounded (zero in the record), and it
// must regenerate as omission — a generated `cpu = 0` would read as a
// declaration nobody made, and a generated default would re-bound a service
// the operator left unbounded.
func TestUnboundedResourcesRoundTripAsOmission(t *testing.T) {
	original, pipelines := renderText(t, `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
`)
	if len(original) != 1 {
		t.Fatalf("services = %d, want 1", len(original))
	}
	if original[0].Resources.CPUMillis != 0 || original[0].Resources.MemoryBytes != 0 {
		t.Fatalf("resources = %+v, want zero (unbounded)", original[0].Resources)
	}

	text, err := toHCL(original, pipelines)
	if err != nil {
		t.Fatalf("toHCL: %v", err)
	}
	if strings.Contains(text, "resources") {
		t.Fatalf("generated spec declares resources for an unbounded service:\n%s", text)
	}

	regenerated, _ := renderText(t, text)
	if !reflect.DeepEqual(original[0], regenerated[0]) {
		t.Errorf("unbounded service did not round-trip.\nwant: %+v\ngot:  %+v", original[0], regenerated[0])
	}
}

const functionRoundTripSpec = `
spec_version = 1

project "shop" {}

function "resize-avatar" {
  project = "shop"
  module  = "registry.example.com/shop/resize-avatar:v3"
  port    = 9000
  count   = 2

  env = { LOG = "info" }

  resources {
    cpu    = 200
    memory = 64
  }

  signing_ref = "secret:shop/resize-signing"

  trigger "http" {
    domains = ["fn.example.com"]
    tls { mode = "acme" }
    auth {
      jwt {
        algorithm      = "RS256"
        public_key_ref = "secret:shop/jwt-pub"
        issuer         = "https://issuer.example.com"
        audience       = "resize-avatar"
      }
    }
  }

  trigger "event" {
    on   = ["deploy.failed", "service.unhealthy"]
    path = "/kanea/event"
  }

  trigger "cron" {
    schedule = "0 3 * * *"
    path     = "/nightly"
  }

  health_check "http" {
    type = "http"
    path = "/healthz"
    port = "http"
  }

  restart {
    attempts = 3
    backoff  = "10s,30s"
  }
}
`

// A lowered function must regenerate as a `function` block that lowers back to
// the identical Desired — runtime, triggers and all (R25). A service block
// carrying runtime internals could not be re-parsed into what is running.
func TestGeneratedFunctionRoundTripsToTheSameDesired(t *testing.T) {
	original, pipelines := renderText(t, functionRoundTripSpec)
	if len(original) != 1 {
		t.Fatalf("services = %d, want 1", len(original))
	}
	if original[0].Runtime == "" || original[0].Function == nil {
		t.Fatalf("the lowered function carries no runtime/function meta: %+v", original[0])
	}

	text, err := toHCL(original, pipelines)
	if err != nil {
		t.Fatalf("toHCL: %v", err)
	}
	if !strings.Contains(text, `function "resize-avatar"`) {
		t.Fatalf("the generator emitted a function as something else:\n%s", text)
	}

	regenerated, _ := renderText(t, text)
	if len(regenerated) != 1 {
		t.Fatalf("regenerated services = %d, want 1\n%s", len(regenerated), text)
	}
	if !reflect.DeepEqual(original[0], regenerated[0]) {
		t.Errorf("function did not round-trip.\nwant: %+v\ngot:  %+v\ngenerated:\n%s",
			original[0], regenerated[0], text)
	}
}

// A desired record marked as a function but carrying what a function block
// cannot express (R25) did not come from the parser; generation must refuse by
// name rather than emit a lie.
func TestGenerateRefusesAMalformedFunctionRecord(t *testing.T) {
	svc := reconciler.Desired{
		Project: "shop", Service: "fn", Count: 1, Image: "example.com/fn:1",
		Runtime:  "io.containerd.wasmtime.v1",
		Function: &reconciler.FunctionMeta{HTTP: true},
		Ports:    []reconciler.Port{{Name: "http", Container: 8080}},
		User:     &runtime.User{UID: 999, GID: 999},
	}
	if _, err := toHCL([]reconciler.Desired{svc}, nil); err == nil {
		t.Fatal("a function record with a user block generated instead of refusing")
	} else if !strings.Contains(err.Error(), "user") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

func TestGeneratedSpecCarriesTheGitBlock(t *testing.T) {
	spec := `
spec_version = 1

project "shop" {
  git {
    url    = "https://git.kanea.test/shop/deploy.git"
    branch = "main"
  }
}

service "web" {
  project = "shop"
  count   = 1
  task "app" {
    image = "nginx:1.29-alpine"
    resources {
      cpu    = 100
      memory = 128
    }
  }
}
`
	services, pipelines := renderText(t, spec)
	text, err := toHCL(services, pipelines)
	if err != nil {
		t.Fatalf("toHCL: %v", err)
	}
	_, regenerated := renderText(t, text)
	if len(regenerated) != 1 {
		t.Fatalf("pipelines = %d, want 1\n%s", len(regenerated), text)
	}
	if regenerated[0].Source.URL != "https://git.kanea.test/shop/deploy.git" {
		t.Errorf("git url did not round-trip: %+v", regenerated[0].Source)
	}
}

func TestGenerateRefusesWhatItCannotExpress(t *testing.T) {
	svc := reconciler.Desired{
		Project: "shop", Service: "web", Count: 1, Image: "nginx:1.29-alpine",
		Volumes: []reconciler.Volume{{Name: "data", Storage: "local-ssd", MountPath: "/data"}},
	}
	if _, err := toHCL([]reconciler.Desired{svc}, nil); err == nil {
		t.Fatal("a service with volumes generated instead of refusing")
	} else if !strings.Contains(err.Error(), "volume") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

func TestRenderReportsDiagnosticsWithPositions(t *testing.T) {
	r := specRenderer{opts: jobspec.Options{}}
	result, err := r.Render(map[string][]byte{"broken.hcl": []byte("service \"web\" {\n  bogus\n}\n")})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(result.Diagnostics) == 0 {
		t.Fatal("a broken spec produced no diagnostics")
	}
	first := result.Diagnostics[0]
	if first.Severity != "error" || first.File != "broken.hcl" || first.Line == 0 {
		t.Errorf("diagnostic is not positioned: %+v", first)
	}
}

// R28 (v1.41): a grpc-marked service round-trips — the protocol attribute is
// regenerated and the port named "grpc" is re-selected by the same rule.
func TestGeneratedGRPCServiceRoundTripsToTheSameDesired(t *testing.T) {
	const grpcSpec = `
spec_version = 1

project "shop" {}

service "api" {
  project = "shop"

  task "app" {
    image = "registry.example.com/shop/grpc-api:2.1.0"

    resources {
      cpu    = 250
      memory = 256
    }
  }

  network {
    port "grpc" { container = 50051 }
    port "metrics" { container = 9090 }
  }

  expose {
    domains  = ["api.shop.example.com"]
    protocol = "grpc"
    tls { mode = "acme" }
  }
}
`
	original, pipelines := renderText(t, grpcSpec)
	if len(original) != 1 {
		t.Fatalf("services = %d, want 1", len(original))
	}
	if original[0].Expose.Protocol != "grpc" {
		t.Fatalf("Protocol = %q, want grpc", original[0].Expose.Protocol)
	}
	if original[0].Expose.Port != 50051 {
		t.Fatalf("Port = %d, want the grpc-named port 50051", original[0].Expose.Port)
	}

	text, err := toHCL(original, pipelines)
	if err != nil {
		t.Fatalf("toHCL: %v", err)
	}
	regenerated, _ := renderText(t, text)
	if len(regenerated) != 1 {
		t.Fatalf("regenerated services = %d, want 1\n%s", len(regenerated), text)
	}
	if !reflect.DeepEqual(original[0], regenerated[0]) {
		t.Errorf("grpc service did not round-trip.\nwant: %+v\ngot:  %+v\ngenerated:\n%s",
			original[0], regenerated[0], text)
	}
}
