package jobspec_test

// The `function` block (PRD v1.39, §6.2 R25-R26): lowering, and the refusals.
// R25's structural half (no volume/device/socket/capabilities/user/scaling
// field exists) is asserted here too, because "the schema has no field" is a
// property someone could quietly change.

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

const minimalFunction = `
spec_version = 1

project "shop" {}

function "resize-avatar" {
  project = "shop"
  module  = "registry.example.com/shop/resize:v3"

  trigger "http" {}
}
`

func TestFunctionLowersToAService(t *testing.T) {
	spec := parse(t, minimalFunction)
	if len(spec.Services) != 1 {
		t.Fatalf("services = %d, want 1 (the lowered function)", len(spec.Services))
	}
	svc := spec.Services[0]

	if svc.Function == nil {
		t.Fatal("the lowered service carries no Function marker")
	}
	if svc.Name != "resize-avatar" || svc.Project != "shop" {
		t.Errorf("lowered to %s/%s, want shop/resize-avatar", svc.Project, svc.Name)
	}
	if svc.Task == nil || svc.Task.Image != "registry.example.com/shop/resize:v3" {
		t.Errorf("module did not become the task image: %+v", svc.Task)
	}
	if svc.Count != 1 {
		t.Errorf("count = %d, want the default 1", svc.Count)
	}
	// The sole declared port, named "http", at the default; that is what
	// makes R16's port selection and the edge work untouched.
	if svc.Network == nil || len(svc.Network.Ports) != 1 ||
		svc.Network.Ports[0].Name != "http" ||
		svc.Network.Ports[0].Container != jobspec.DefaultFunctionPort {
		t.Errorf("lowered ports = %+v, want one port \"http\" at %d", svc.Network, jobspec.DefaultFunctionPort)
	}
	// Function defaults: cpu is the service default, memory the smaller
	// function one (a wasm module's baseline is kilobytes).
	if svc.Task.Resources.CPU != jobspec.DefaultCPU || svc.Task.Resources.Memory != jobspec.DefaultFunctionMemory {
		t.Errorf("resources = %+v, want cpu=%d memory=%d",
			svc.Task.Resources, jobspec.DefaultCPU, jobspec.DefaultFunctionMemory)
	}
	// An http trigger lowers to Expose.
	if !svc.Function.HTTP || svc.Expose == nil {
		t.Errorf("the http trigger did not lower to an expose: HTTP=%v Expose=%v",
			svc.Function.HTTP, svc.Expose)
	}
}

func TestFunctionTriggersLower(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}

function "fanout" {
  project = "shop"
  module  = "example.com/fanout:1"
  port    = 9000

  trigger "event" {
    on   = ["deploy.failed", "service.*"]
    path = "/kanea/event"
  }
  trigger "cron" {
    schedule = "0 3 * * *"
    path     = "/nightly"
  }
  trigger "cron" {
    schedule = "*/15 * * * *"
  }
}
`)
	fn := spec.Services[0].Function
	if fn == nil {
		t.Fatal("no function meta")
	}
	if fn.HTTP {
		t.Error("no http trigger was declared, but HTTP is set")
	}
	if fn.Port != 9000 {
		t.Errorf("port = %d, want 9000", fn.Port)
	}
	if len(fn.Events) != 1 || len(fn.Events[0].On) != 2 || fn.Events[0].Path != "/kanea/event" {
		t.Errorf("event triggers = %+v", fn.Events)
	}
	if len(fn.Crons) != 2 || fn.Crons[0].Schedule != "0 3 * * *" || fn.Crons[1].Path != "" {
		t.Errorf("cron triggers = %+v", fn.Crons)
	}
}

// R8 applies to functions verbatim: a build block with no module is legal and
// waits for its first build.
func TestFunctionWithBuildAndNoModuleIsLegal(t *testing.T) {
	spec := parse(t, `
spec_version = 1
project "shop" {}

function "built" {
  project = "shop"
  build { context = "./fn" }
  trigger "http" {}
}
`)
	if spec.Services[0].Build == nil {
		t.Fatal("the build block did not lower")
	}
	if spec.Services[0].Task.Image != "" {
		t.Fatalf("image = %q, want empty until the first build pins a digest", spec.Services[0].Task.Image)
	}
}

func TestFunctionRefusals(t *testing.T) {
	tests := []struct {
		name string
		body string // inside `function "fn" { project = "shop" ... }`
		want string
	}{
		{
			"no trigger",
			`module = "example.com/fn:1"`,
			"no trigger",
		},
		{
			"no module and no build",
			`trigger "http" {}`,
			"no module",
		},
		{
			"unknown trigger kind",
			`module = "example.com/fn:1"
			 trigger "queue" {}`,
			"Unknown trigger kind",
		},
		{
			"duplicate http trigger",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 trigger "http" {}`,
			"Duplicate http trigger",
		},
		{
			"event trigger with no patterns",
			`module = "example.com/fn:1"
			 trigger "event" {}`,
			"no `on` list",
		},
		{
			"unknown event pattern",
			`module = "example.com/fn:1"
			 trigger "event" { on = ["depoly.*"] }`,
			"matches no known event",
		},
		// R26: a pattern that would match function.* is a feedback loop.
		{
			"function.* pattern",
			`module = "example.com/fn:1"
			 trigger "event" { on = ["function.*"] }`,
			"feedback loop",
		},
		{
			"catch-all pattern",
			`module = "example.com/fn:1"
			 trigger "event" { on = ["*"] }`,
			"feedback loop",
		},
		{
			"bad cron schedule",
			`module = "example.com/fn:1"
			 trigger "cron" { schedule = "every day" }`,
			"Invalid cron schedule",
		},
		{
			"cron with no schedule",
			`module = "example.com/fn:1"
			 trigger "cron" {}`,
			"no schedule",
		},
		{
			"relative trigger path",
			`module = "example.com/fn:1"
			 trigger "event" {
			   on   = ["deploy.failed"]
			   path = "kanea/event"
			 }`,
			"absolute",
		},
		{
			"traversal in trigger path",
			`module = "example.com/fn:1"
			 trigger "cron" {
			   schedule = "0 3 * * *"
			   path     = "/a/../b"
			 }`,
			"Invalid trigger path",
		},
		{
			"port out of range",
			`module = "example.com/fn:1"
			 port = 70000
			 trigger "http" {}`,
			"1-65535",
		},
		// R25: the wasmtime shim has no exec, refused by name.
		{
			"exec health check",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 health_check "hc" {
			   type    = "exec"
			   command = ["/bin/check"]
			 }`,
			"exec",
		},
		// R25's structural refusals: the block has no field for any of these,
		// so HCL itself refuses at the exact line.
		{
			"volume block",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 volume "data" {
			   storage    = "x"
			   mount_path = "/data"
			 }`,
			"volume",
		},
		{
			"user block",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 user { uid = 999 }`,
			"user",
		},
		{
			"device block",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 device "gpu" { grant = "gpu" }`,
			"device",
		},
		{
			"socket block",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 socket "rt" {
			   grant      = "containerd"
			   mount_path = "/var/run/docker.sock"
			 }`,
			"socket",
		},
		{
			"scaling block",
			`module = "example.com/fn:1"
			 trigger "http" {}
			 scaling {
			   min = 0
			   max = 5
			 }`,
			"scaling",
		},
		{
			"capabilities attribute",
			`module = "example.com/fn:1"
			 capabilities = ["CAP_CHOWN"]
			 trigger "http" {}`,
			"capabilities",
		},
		// R25/R11 (v1.88): resources.pids is a parse-shallow-looking but real
		// schema field, so it needs an explicit refusal; the sandbox's caps
		// are fixed.
		{
			"pids in resources",
			`module = "example.com/fn:1"
			 resources { pids = 128 }
			 trigger "http" {}`,
			"pids",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := "spec_version = 1\nproject \"shop\" {}\n\nfunction \"fn\" {\n  project = \"shop\"\n  " +
				tc.body + "\n}\n"
			got := parseErr(t, src)
			if !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics do not mention %q:\n%s", tc.want, got)
			}
		})
	}
}

// A function and a service are one namespace: the lowered function is a
// service, so the existing duplicate check covers the collision.
func TestFunctionAndServiceNamesCollide(t *testing.T) {
	got := parseErr(t, `
spec_version = 1
project "shop" {}

service "web" {
  project = "shop"
  task "app" { image = "nginx:1.29-alpine" }
}

function "web" {
  project = "shop"
  module  = "example.com/fn:1"
  trigger "http" {}
}
`)
	if !strings.Contains(got, "Duplicate service") {
		t.Errorf("a function shadowing a service was not refused:\n%s", got)
	}
}

// The http trigger carries the expose sub-schema, so R16's middleware rules
// apply to it verbatim.
func TestFunctionHTTPTriggerGetsExposeValidation(t *testing.T) {
	got := parseErr(t, `
spec_version = 1
project "shop" {}

function "fn" {
  project = "shop"
  module  = "example.com/fn:1"
  trigger "http" {
    ip_restriction { allow = ["not-a-cidr"] }
  }
}
`)
	if !strings.Contains(got, "not-a-cidr") {
		t.Errorf("an invalid CIDR on an http trigger was not refused:\n%s", got)
	}
}

// R28's function half is structural: `trigger "http"` has no `protocol` field
// and must not gain one; wasi-http is HTTP/1.1, and the absent field is the
// refusal (R25's pattern). This pins the absence, because "the schema has no
// field" is a property someone could quietly change.
func TestFunctionTriggerHasNoProtocolField(t *testing.T) {
	msg := parseErr(t, `
spec_version = 1

project "shop" {}

function "resize-avatar" {
  project = "shop"
  module  = "registry.example.com/shop/resize:v3"

  trigger "http" {
    protocol = "grpc"
  }
}
`)
	if !strings.Contains(msg, "protocol") {
		t.Errorf("the diagnostic does not name the unsupported argument:\n%s", msg)
	}
}
