package jobspec_test

// The hardening posture and its plan warnings (PRD v1.103, §6.2 R13).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

// hardeningSpec builds a one-service spec: attrs land on the service, body
// inside the task.
func hardeningSpec(attrs, body string) string {
	return fmt.Sprintf(`
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  %s
  task "app" {
    image = "nginx:1.27-alpine@sha256:0f9e6ee1a1b0a2c6d3f0e0e3a3d3c1b0a2c6d3f0e0e3a3d3c1b0a2c6d3f0e0e3"
    read_only_rootfs = true
    %s
  }
}
`, attrs, body)
}

const nonRootUser = `user {
      uid = 999
      gid = 999
    }`

func TestRestrictedParsesWithANonRootUser(t *testing.T) {
	spec := parse(t, hardeningSpec(`hardening = "restricted"`, nonRootUser))
	if got := spec.Services[0].Hardening; got != jobspec.HardeningRestricted {
		t.Errorf("Hardening = %q, want %q", got, jobspec.HardeningRestricted)
	}
	if !spec.Services[0].Task.ReadOnlyRootfs {
		t.Error("read_only_rootfs did not survive conversion")
	}
}

// "compatible" is the default's explicit spelling and must canonicalise to
// empty: only restricted may reach a record, or the word would enter the
// SpecHash material and roll every service that wrote the default out loud.
func TestCompatibleCanonicalisesToEmpty(t *testing.T) {
	spec := parse(t, hardeningSpec(`hardening = "compatible"`, nonRootUser))
	if got := spec.Services[0].Hardening; got != "" {
		t.Errorf("Hardening = %q, want empty", got)
	}
}

func TestHardeningRefusals(t *testing.T) {
	for _, tc := range []struct {
		name        string
		attrs, body string
		want        string
	}{
		{"unknown value", `hardening = "paranoid"`, nonRootUser, "unknown hardening"},
		{"no user", `hardening = "restricted"`, "", "requires a user block"},
		{"root user", `hardening = "restricted"`, "user {\n      uid = 0\n      gid = 0\n    }", "refuses uid 0"},
		{"a capability grant", `hardening = "restricted"`,
			nonRootUser + "\n    capabilities = [\"CAP_NET_RAW\"]", "grants no capabilities"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseErr(t, hardeningSpec(tc.attrs, tc.body))
			if !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want it to say %q", got, tc.want)
			}
		})
	}
}

// "none" is redundant under restricted (drop-ALL is already the posture) and
// a spec saying the same thing twice is not wrong.
func TestRestrictedAcceptsTheNoneToken(t *testing.T) {
	parse(t, hardeningSpec(`hardening = "restricted"`,
		nonRootUser+"\n    capabilities = [\"none\"]"))
}

// warningLines parses and returns the rendered warnings; errors fail the test.
func warningLines(t *testing.T, src string) string {
	t.Helper()
	_, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", jobspec.FormatDiagnostics(diags))
	}
	return jobspec.FormatDiagnostics(diags)
}

// The fully hardened shape warns about nothing: that silence is what makes
// the warnings below readable.
func TestAHardenedSpecPlansSilently(t *testing.T) {
	if got := warningLines(t, hardeningSpec(`hardening = "restricted"`, nonRootUser)); got != "" {
		t.Errorf("unexpected warnings:\n%s", got)
	}
}

func TestPlanWarnsOnTheWeakDefaults(t *testing.T) {
	src := `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx:latest"
  }
}
`
	got := warningLines(t, src)
	for _, want := range []string{"moving tag", "image's own user", "writable"} {
		if !strings.Contains(got, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, got)
		}
	}
}

func TestPlanWarnsOnADeclaredRootUser(t *testing.T) {
	got := warningLines(t, hardeningSpec("", "user {\n      uid = 0\n      gid = 0\n    }"))
	if !strings.Contains(got, "runs as root") {
		t.Errorf("uid 0 earned no warning:\n%s", got)
	}
}

// The tag warning stands down for every deliberate shape: a pinned digest, a
// build block (the pipeline pins what it produces), auto-update (following
// the tag is the stated point), and a build-pending empty image.
func TestTheTagWarningKnowsTheDeliberateShapes(t *testing.T) {
	for name, src := range map[string]string{
		"digest": hardeningSpec("", nonRootUser),
		"auto-update": `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  task "app" {
    image = "nginx:latest"
  }
  update {
    auto = true
  }
}
`,
		"build block": `
spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  build {
    context = "."
  }
  task "app" {
    image = "registry.example.com/web:latest"
  }
}
`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := warningLines(t, src); strings.Contains(got, "moving tag") {
				t.Errorf("warned about a deliberate shape:\n%s", got)
			}
		})
	}
}
