package jobspec_test

// Env groups (PRD v1.85, §6.2 R34).

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

const twoProjectSpec = `spec_version = 1
project "shop" {}
project "analytics" {}

env_group "common" {
  LOG_LEVEL = "info"
  REGION    = "eu-central-1"
}

env_group "db" {
  DATABASE_HOST = "${service.postgres.host}"
}

service "postgres" {
  project = "shop"
  task "db" {
    image = "postgres:17"
  }
  network {
    port "pg" {
      container = 5432
    }
  }
}

service "postgres" {
  project = "analytics"
  task "db" {
    image = "postgres:17"
  }
  network {
    port "pg" {
      container = 5432
    }
  }
}

service "web" {
  project  = "shop"
  env_from = ["common", "db"]
  task "app" {
    image = "nginx:1.27"
    env = {
      LOG_LEVEL = "debug"
    }
  }
}

service "collector" {
  project  = "analytics"
  env_from = ["db"]
  task "app" {
    image = "collector:1"
  }
}
`

// TestTheServicesOwnEnvWinsOverAGroup is R34's precedence in one assertion:
// groups in declaration order, then the container's own env on top.
func TestTheServicesOwnEnvWinsOverAGroup(t *testing.T) {
	spec, diags := parseSpec(t, twoProjectSpec)
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	env := spec.ServiceByName("shop", "web").Task.Env

	if env["LOG_LEVEL"] != "debug" {
		t.Errorf("LOG_LEVEL = %q, want debug: the service's own env must win", env["LOG_LEVEL"])
	}
	if env["REGION"] != "eu-central-1" {
		t.Errorf("REGION = %q; a key the service did not override must come from the group",
			env["REGION"])
	}
}

// TestOneGroupResolvesPerProject is why a group is evaluated once per consuming
// service rather than once per spec: the service-reference namespace is
// project-scoped, so the same group means two different addresses.
func TestOneGroupResolvesPerProject(t *testing.T) {
	spec, diags := parseSpec(t, twoProjectSpec)
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	shop := spec.ServiceByName("shop", "web").Task.Env["DATABASE_HOST"]
	analytics := spec.ServiceByName("analytics", "collector").Task.Env["DATABASE_HOST"]

	if shop != "postgres.shop.kanea" {
		t.Errorf("shop resolved %q", shop)
	}
	if analytics != "postgres.analytics.kanea" {
		t.Errorf("analytics resolved %q", analytics)
	}
	if shop == analytics {
		t.Error("one group resolved to one address for two projects; it must be evaluated " +
			"per consuming service")
	}
}

// TestAGroupsReferenceIsTheConsumersDependency. The edge has to land on the
// service that took the group, or R10 never orders it behind what its own
// environment names.
func TestAGroupsReferenceIsTheConsumersDependency(t *testing.T) {
	spec, diags := parseSpec(t, twoProjectSpec)
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	deps := spec.ServiceByName("shop", "web").Dependencies
	if len(deps) != 1 || deps[0] != "postgres" {
		t.Errorf("dependencies = %v, want [postgres]", deps)
	}
}

// TestAGroupsSecretIsScopedPerConsumer is v1.72's storage.auth_ref rule applied
// to a second top-level block: a group knows no project, so the check happens
// where one exists - once per service that takes it.
func TestAGroupsSecretIsScopedPerConsumer(t *testing.T) {
	src := `spec_version = 1
project "shop" {}
project "analytics" {}

env_group "creds" {
  DATABASE_URL = "secret:shop/database-url"
}

service "web" {
  project  = "shop"
  env_from = ["creds"]
  task "app" {
    image = "nginx:1.27"
  }
}
`
	if _, diags := parseSpec(t, src); diags.HasErrors() {
		t.Fatalf("a service in the secret's own project was refused: %s",
			jobspec.FormatDiagnostics(diags))
	}

	// The same group, taken from another project, is refused.
	crossed := strings.Replace(src, `  project  = "shop"`, `  project  = "analytics"`, 1)
	diags := func() string {
		_, d := parseSpec(t, crossed)
		return jobspec.FormatDiagnostics(d)
	}()
	if !strings.Contains(diags, "another project") {
		t.Errorf("a group carrying shop's secret was taken by an analytics service "+
			"without a refusal; got %s", diags)
	}
}

func TestEnvGroupRefusalsNameTheProblem(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{
			"unknown group",
			`env_from = ["nope"]`,
			"not declared",
		},
		{
			"duplicate reference",
			`env_from = ["common", "common"]`,
			"twice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `spec_version = 1
project "shop" {}
env_group "common" {
  A = "b"
}
service "web" {
  project = "shop"
  ` + tc.src + `
  task "app" {
    image = "nginx:1.27"
  }
}
`
			_, diags := parseSpec(t, src)
			if !diags.HasErrors() {
				t.Fatal("expected a refusal")
			}
			if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, tc.want) {
				t.Errorf("want %q; got %s", tc.want, got)
			}
		})
	}
}

func TestADuplicateEnvGroupIsRefused(t *testing.T) {
	_, diags := parseSpec(t, `spec_version = 1
project "shop" {}
env_group "common" {
  A = "b"
}
env_group "common" {
  C = "d"
}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx:1.27"
  }
}
`)
	if !diags.HasErrors() {
		t.Fatal("two groups with one name were accepted")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "already declared") {
		t.Errorf("want a duplicate refusal; got %s", got)
	}
}

// TestSecretIsAReservedVariableName: it is the namespace R35 interpolates
// through, so a variable of that name would shadow it.
func TestSecretIsAReservedVariableName(t *testing.T) {
	_, diags := parseSpec(t, `spec_version = 1
project "shop" {}
variables {
  secret = "oops"
}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx:1.27"
  }
}
`)
	if !diags.HasErrors() {
		t.Fatal("a variable named `secret` was accepted")
	}
}
