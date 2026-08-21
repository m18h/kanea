package jobspec_test

// Init containers and pull policy (PRD v1.84, §6.2 R32 / R33).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/m18h/kanea/internal/jobspec"
)

// parseInitSpec parses a one-service spec carrying the given blocks.
func parseInitSpec(t *testing.T, blocks string) (*jobspec.Spec, hcl.Diagnostics) {
	t.Helper()
	src := `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
` + blocks + `
  task "app" {
    image = "nginx:1.27"
  }
}
`
	return jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
}

func TestAnInitBlockParsesIntoTheService(t *testing.T) {
	spec, diags := parseInitSpec(t, `
  init "fix-perms" {
    image        = "busybox:1.36"
    command      = ["chown", "-R", "999:999", "/data"]
    capabilities = ["CAP_CHOWN"]
    timeout      = "1m"
    user {
      uid = 0
      gid = 0
    }
    resources {
      cpu    = 200
      memory = 128
    }
  }
  init "migrate" {
    image   = "migrate:1"
    command = ["/bin/migrate", "up"]
  }`)
	if diags.HasErrors() {
		t.Fatalf("refused a valid spec: %s", jobspec.FormatDiagnostics(diags))
	}
	svc := spec.Services[0]
	if len(svc.Inits) != 2 {
		t.Fatalf("got %d init blocks, want 2", len(svc.Inits))
	}
	// Declaration order is run order, and nothing may reorder it.
	if svc.Inits[0].Name != "fix-perms" || svc.Inits[1].Name != "migrate" {
		t.Errorf("init order is %q, %q; declaration order is run order",
			svc.Inits[0].Name, svc.Inits[1].Name)
	}
	if got := svc.Inits[0].Resources.CPU; got != 200 {
		t.Errorf("resources.cpu = %d, want 200", got)
	}
	if svc.Inits[0].User == nil || svc.Inits[0].User.UID != 0 {
		t.Errorf("the user block did not survive conversion: %+v", svc.Inits[0].User)
	}
	// R11: an omitted resources block is unbounded, never a default filled in.
	if svc.Inits[1].Resources.CPU != 0 || svc.Inits[1].Resources.Memory != 0 {
		t.Errorf("an omitted resources block was defaulted: %+v", svc.Inits[1].Resources)
	}
}

// TestAnInitBlockHasNoFieldForWhatAStepMayNotAsk. The absence *is* the refusal
// (R25's pattern): an init container is a step, not a service, and a grant
// delegated to one would widen the grant surface for nothing anybody asked for.
func TestAnInitBlockHasNoFieldForWhatAStepMayNotAsk(t *testing.T) {
	for name, body := range map[string]string{
		"device":       "device \"gpu\" {\n      grant = \"gpu\"\n    }",
		"socket":       "socket \"ctr\" {\n      grant = \"ctr\"\n      mount_path = \"/s\"\n    }",
		"health_check": "health_check \"h\" {\n      type = \"tcp\"\n    }",
		"expose":       "expose {\n      port = \"http\"\n    }",
		"scaling":      "scaling {\n      min = 1\n      max = 3\n    }",
		"build":        "build {\n      context = \".\"\n    }",
		"count":        "count = 2",
		"depends_on":   "depends_on = [\"db\"]",
		"network":      "network {\n      port \"p\" {\n        container = 1\n      }\n    }",
	} {
		t.Run(name, func(t *testing.T) {
			_, diags := parseInitSpec(t, "  init \"s\" {\n    image = \"x:1\"\n    "+body+"\n  }")
			if !diags.HasErrors() {
				t.Fatalf("an init block accepted %q; R32 gives it no such field", name)
			}
		})
	}
}

func TestInitRefusalsNameTheOffendingField(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block string
		want  string
	}{
		{"no image", "init \"s\" {\n}", "must set image"},
		{"bad name", "init \"Not_A_Label\" {\n    image = \"x:1\"\n  }", "DNS-1123"},
		{"empty command", "init \"s\" {\n    image = \"x:1\"\n    command = [\"\", \"y\"]\n  }", "names the program"},
		{"negative cpu", "init \"s\" {\n    image = \"x:1\"\n    resources {\n      cpu = -1\n    }\n  }", "cannot be negative"},
		{"pids", "init \"s\" {\n    image = \"x:1\"\n    resources {\n      pids = 1024\n    }\n  }", "the alloc's"},
		{"bad capability", "init \"s\" {\n    image = \"x:1\"\n    capabilities = [\"CAP_SYS_ADMIN\"]\n  }", "cannot be granted"},
		{"cross-project secret", "init \"s\" {\n    image = \"x:1\"\n    env = { A = \"secret:other/b\" }\n  }", "Cross-project"},
		{"bad timeout", "init \"s\" {\n    image = \"x:1\"\n    timeout = \"soon\"\n  }", "Invalid duration"},
		{"always pull", "init \"s\" {\n    image = \"x:1\"\n    pull_policy = \"always\"\n  }", "belongs to the task"},
		{"unknown policy", "init \"s\" {\n    image = \"x:1\"\n    pull_policy = \"sometimes\"\n  }", "not a policy"},
		{"bad uid", "init \"s\" {\n    image = \"x:1\"\n    user {\n      uid = -1\n    }\n  }", "must not be negative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := parseInitSpec(t, "  "+tc.block)
			if !diags.HasErrors() {
				t.Fatal("expected a refusal, got none")
			}
			if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, tc.want) {
				t.Errorf("the refusal must name the problem.\n  want substring: %s\n  got: %s",
					tc.want, got)
			}
		})
	}
}

// TestDuplicateInitNamesAreRefused: a name composes into a container id and a
// log file, so two steps sharing one is two containers sharing an identity.
func TestDuplicateInitNamesAreRefused(t *testing.T) {
	_, diags := parseInitSpec(t, `
  init "s" {
    image = "a:1"
  }
  init "s" {
    image = "b:1"
  }`)
	if !diags.HasErrors() {
		t.Fatal("two init blocks with one name were accepted")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "more than once") {
		t.Errorf("refusal should say the name repeats; got %s", got)
	}
}

// TestAnInitNameSharesTheContainerIDBudget. The alloc id, the ordinal and the
// step name compose into one containerd identifier, and going past its ceiling
// fails every alloc with an error nobody can attribute to a name in the spec.
func TestAnInitNameSharesTheContainerIDBudget(t *testing.T) {
	long := strings.Repeat("a", 63)
	_, diags := parseInitSpec(t, "  init \""+long+"\" {\n    image = \"x:1\"\n  }")
	if !diags.HasErrors() {
		t.Fatal("a name that overruns the container id ceiling was accepted")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "budget") {
		t.Errorf("the refusal should explain the shared budget; got %s", got)
	}
}

// TestAnInitEnvReferenceIsADependencyEdge. An init container shares the alloc's
// network namespace, so ${service.db.host} in a wait-for-database step is a real
// address - and therefore a real R9/R10 edge. Missing it would let the step run
// before the service it names is up.
func TestAnInitEnvReferenceIsADependencyEdge(t *testing.T) {
	src := `spec_version = 1
project "shop" {}
service "db" {
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
service "web" {
  project = "shop"
  init "wait" {
    image = "busybox:1.36"
    env   = { HOST = "${service.db.host}" }
  }
  task "app" {
    image = "nginx:1.27"
  }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("refused a valid spec: %s", jobspec.FormatDiagnostics(diags))
	}
	web := spec.ServiceByName("shop", "web")
	found := false
	for _, dep := range web.Dependencies {
		if dep == "db" {
			found = true
		}
	}
	if !found {
		t.Errorf("an init container's ${service.db.host} created no dependency edge; "+
			"got %v. The step would run before db is healthy", web.Dependencies)
	}
	if got := web.Inits[0].Env["HOST"]; got != "db.shop.kanea" {
		t.Errorf("the init env was not resolved: HOST = %q", got)
	}
}

// --- R33 ------------------------------------------------------------------

func TestTaskPullPolicyParses(t *testing.T) {
	for _, policy := range []string{"if-not-present", "never"} {
		t.Run(policy, func(t *testing.T) {
			src := `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image       = "nginx:1.27"
    pull_policy = "` + policy + `"
  }
}
`
			spec, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
			if diags.HasErrors() {
				t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
			}
			if got := spec.Services[0].Task.PullPolicy; got != policy {
				t.Errorf("pull_policy = %q, want %q", got, policy)
			}
		})
	}
}

// TestPullAlwaysLowersToAutoUpdate is R33's central decision: "always" is not a
// second mechanism, it is auto-update spelled differently, so a moved tag pins
// a digest and every replica rolls together rather than two replicas of one
// spec hash running different bytes.
func TestPullAlwaysLowersToAutoUpdate(t *testing.T) {
	src := `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image       = "nginx:1.27"
    pull_policy = "always"
  }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	up := spec.Services[0].Update
	if up == nil || !up.Auto {
		t.Fatalf(`pull_policy = "always" did not turn on auto-update: %+v`, up)
	}
}

// TestPullAlwaysInheritsAutoUpdatesRefusals, worded for what was written: a
// diagnostic naming update.auto for a spec that says pull_policy sends someone
// looking for a block they never wrote.
func TestPullAlwaysInheritsAutoUpdatesRefusals(t *testing.T) {
	for _, tc := range []struct{ name, task, extra, want string }{
		{"digest", "image = \"nginx@sha256:abc\"\n    pull_policy = \"always\"", "", `pull_policy = "always"`},
		{"build", "image = \"x:1\"\n    pull_policy = \"always\"",
			"\n  build {\n    context = \"./web\"\n    target  = \"r/x\"\n  }", `pull_policy = "always"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"` + tc.extra + `
  task "app" {
    ` + tc.task + `
  }
}
`
			_, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
			if !diags.HasErrors() {
				t.Fatal("expected a refusal, got none")
			}
			if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, tc.want) {
				t.Errorf("the refusal must name what was written.\n  want: %s\n  got:  %s",
					tc.want, got)
			}
		})
	}
}

// TestPullAlwaysBesideAutoFalseIsRefused: two answers to one question. Refuse
// rather than pick a winner (R21's rule, applied to a spec arguing with itself).
func TestPullAlwaysBesideAutoFalseIsRefused(t *testing.T) {
	src := `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  update {
    auto = false
  }
  task "app" {
    image       = "nginx:1.27"
    pull_policy = "always"
  }
}
`
	_, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
	if !diags.HasErrors() {
		t.Fatal(`pull_policy = "always" beside update { auto = false } was accepted`)
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "two answers to one question") {
		t.Errorf("the refusal should name the contradiction; got %s", got)
	}
}

// TestAnAbsentAutoBlockStillMeansOff. Making hclUpdate.Auto a *bool must not
// change what an update block with no `auto` means.
func TestAnAbsentAutoBlockStillMeansOff(t *testing.T) {
	src := `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  update {
    strategy     = "rolling"
    max_parallel = 2
  }
  task "app" {
    image = "nginx:1.27"
  }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	if spec.Services[0].Update.Auto {
		t.Error("an update block with no `auto` turned auto-update on")
	}
}

// TestAFunctionMayNotDeclareInitContainers (R25): the wasm runtime runs one
// module and has no second container to run.
func TestAFunctionMayNotDeclareInitContainers(t *testing.T) {
	src := `spec_version = 1
project "shop" {}
function "thumb" {
  project = "shop"
  module  = "registry/thumb:1"
  init "warm" {
    image = "busybox:1.36"
  }
  trigger "http" {
  }
}
`
	_, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
	if !diags.HasErrors() {
		t.Fatal("a function accepted an init block")
	}
}

// --- init runs once, volumes do not (v1.92) --------------------------------

// warningsFor parses a spec that must succeed and returns its warnings.
func warningsFor(t *testing.T, src string) string {
	t.Helper()
	_, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	return jobspec.FormatDiagnostics(diags)
}

const initWithLocalVolume = `
spec_version = 1
project "shop" {}
storage "scratch" { type = "local" }
service "web" {
  project = "shop"
  count   = %d
  task "app" { image = "nginx:1.27-alpine" }
  %s
  volume "data" {
    storage = "scratch"
    mount_path = "/data"
  }
}
`

const chownStep = `
  init "chown" {
    image   = "busybox:1.36"
    command = ["chown", "-R", "999", "/data"]
  }
`

// The one shape v1.92 quietly changed meaning for. An init sequence runs once,
// on the first alloc, while local storage gives every alloc its own directory,
// so a chown step prepares one replica's copy and no other. That failure is a
// service which starts, passes its health check on alloc 0 and fails on the
// rest, with nothing on screen connecting it to the init block.
func TestInitOnAPerAllocVolumeWarns(t *testing.T) {
	got := warningsFor(t, fmt.Sprintf(initWithLocalVolume, 3, chownStep))
	for _, want := range []string{"runs once", "per alloc", "data", "scratch"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning does not carry %q:\n%s", want, got)
		}
	}
}

// Quiet where it should be. A single-replica service has no second alloc to
// leave unprepared, and a service with no init steps has nothing to run once.
func TestInitOnAPerAllocVolumeIsQuietWhenItCannotBite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		init  string
	}{
		{"one alloc", 1, chownStep},
		{"no init steps", 3, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := warningsFor(t, fmt.Sprintf(initWithLocalVolume, tc.count, tc.init)); got != "" {
				t.Errorf("unexpected warning:\n%s", got)
			}
		})
	}
}

// Shared storage is the case the warning must not fire on: every alloc mounts
// the same thing, so preparing it once is exactly right.
func TestInitOnSharedStorageDoesNotWarn(t *testing.T) {
	src := `
spec_version = 1
project "shop" {}
storage "shared" {
  type   = "nfs"
  server = "nfs.example.com"
  export = "/exports/web"
}
service "web" {
  project = "shop"
  count   = 3
  task "app" { image = "nginx:1.27-alpine" }
  init "seed" {
    image   = "busybox:1.36"
    command = ["sh", "-c", "seed"]
  }
  volume "data" {
    storage = "shared"
    mount_path = "/data"
  }
}
`
	if got := warningsFor(t, src); got != "" {
		t.Errorf("shared storage warned:\n%s", got)
	}
}
