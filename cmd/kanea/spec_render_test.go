package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
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
`

// TestGeneratedSpecRoundTripsToTheSameDesired is the gate on "edit spec"
// (v1.38): what toHCL writes must mean exactly what was running. A field that
// cannot survive the trip must refuse generation, never drift.
func TestGeneratedSpecRoundTripsToTheSameDesired(t *testing.T) {
	original, pipelines := renderText(t, roundTripSpec)
	if len(original) != 2 {
		t.Fatalf("services = %d, want 2", len(original))
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
