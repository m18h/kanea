package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
)

// PRD v1.57: on the plan/run command line, existence wins — an argument that
// names a file on disk is a spec file even when it would also parse as a
// selector.
func TestAnExistingFileIsNeverReadAsASelector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shop")
	if err := os.WriteFile(path, []byte("spec_version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, sels, err := splitFilesAndSelectors([]string{path})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(files) != 1 || files[0] != path {
		t.Fatalf("files = %v, want the existing file", files)
	}
	if len(sels) != 0 {
		t.Fatalf("selectors = %v, want none", sels)
	}
}

func TestSelectorsSplitFromSpecFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.hcl")
	if err := os.WriteFile(path, []byte("spec_version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, sels, err := splitFilesAndSelectors([]string{path, "shop", "shop/web"})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(files) != 1 || files[0] != path {
		t.Fatalf("files = %v, want [%s]", files, path)
	}
	if len(sels) != 2 {
		t.Fatalf("selectors = %v, want two", sels)
	}
	if sels[0] != (selector{raw: "shop", project: "shop"}) {
		t.Errorf("first selector = %+v, want the whole project shop", sels[0])
	}
	if sels[1] != (selector{raw: "shop/web", project: "shop", service: "web"}) {
		t.Errorf("second selector = %+v, want shop/web", sels[1])
	}
}

// A typo'd filename cannot be a selector — a dot cannot appear in a DNS-1123
// label — so it is refused by name rather than silently selecting nothing.
func TestAnArgThatIsNeitherFileNorSelectorIsRefusedByName(t *testing.T) {
	for _, arg := range []string{"app.hlc", "Shop/Web", "shop/web/extra", "shop/", "/web"} {
		if _, _, err := splitFilesAndSelectors([]string{arg}); err == nil {
			t.Errorf("%q was accepted; want a refusal", arg)
		} else if !strings.Contains(err.Error(), arg) {
			t.Errorf("refusal for %q does not name it: %v", arg, err)
		}
	}
}

func specDesired() []reconciler.Desired {
	return []reconciler.Desired{
		{Project: "shop", Service: "web", Count: 1},
		{Project: "shop", Service: "api", Count: 1},
		{Project: "blog", Service: "ghost", Count: 1},
	}
}

func TestAServiceSelectorKeepsExactlyThatService(t *testing.T) {
	kept, err := filterDesired(specDesired(), []selector{{raw: "shop/api", project: "shop", service: "api"}})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(kept) != 1 || kept[0].Project != "shop" || kept[0].Service != "api" {
		t.Fatalf("kept = %v, want exactly shop/api", kept)
	}
}

func TestAProjectSelectorKeepsEveryServiceInTheProject(t *testing.T) {
	kept, err := filterDesired(specDesired(), []selector{{raw: "shop", project: "shop"}})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(kept) != 2 || kept[0].Service != "web" || kept[1].Service != "api" {
		t.Fatalf("kept = %v, want shop's web and api in spec order", kept)
	}
}

func TestOverlappingSelectorsDoNotDuplicateAService(t *testing.T) {
	kept, err := filterDesired(specDesired(), []selector{
		{raw: "shop", project: "shop"},
		{raw: "shop/web", project: "shop", service: "web"},
	})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %v, want shop's two services exactly once each", kept)
	}
}

func TestFilterDesiredWithNoSelectorsIsIdentity(t *testing.T) {
	desired := specDesired()
	kept, err := filterDesired(desired, nil)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(kept) != len(desired) {
		t.Fatalf("kept %d of %d services with no selectors", len(kept), len(desired))
	}
}

// install --only's rule: a selector that matches nothing is a typo, and the
// refusal names what the spec does declare.
func TestASelectorThatMatchesNothingIsRefusedWithWhatExists(t *testing.T) {
	for _, tc := range []struct {
		sel  selector
		want string
	}{
		// Mistyped service in a project that exists: list its services.
		{selector{raw: "shop/wbe", project: "shop", service: "wbe"}, `project "shop" declares api, web`},
		// Mistyped project: list the projects.
		{selector{raw: "shp", project: "shp"}, "the spec declares projects blog, shop"},
		{selector{raw: "shp/web", project: "shp", service: "web"}, "the spec declares projects blog, shop"},
	} {
		_, err := filterDesired(specDesired(), []selector{tc.sel})
		if err == nil {
			t.Errorf("selector %q was accepted; want a refusal", tc.sel.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.sel.raw) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("refusal for %q = %v, want it to name the selector and %q", tc.sel.raw, err, tc.want)
		}
	}
}

// The v1.57 hazard regression: the server replaces a project's Builds
// wholesale on apply, so the pipeline config a scoped apply sends must be
// derived from the unfiltered spec — selecting one service must not delete
// its siblings' build entries.
func TestPipelineBuildsSurviveASelectorScopedApply(t *testing.T) {
	src := `
spec_version = 1
project "shop" {
  git {
    url      = "https://example.com/shop.git"
    branch   = "main"
    auth_ref = "secret:shop/deploy-key"
  }
}
service "web" {
  project = "shop"
  build {
    context = "./web"
    target  = "registry.example.com/shop/web"
  }
  task "app" { image = "registry.example.com/shop/web:latest" }
}
service "api" {
  project = "shop"
  build {
    context = "./api"
    target  = "registry.example.com/shop/api"
  }
  task "app" { image = "registry.example.com/shop/api:latest" }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("parse:\n%s", jobspec.FormatDiagnostics(diags))
	}
	desired, err := toDesired(spec)
	if err != nil {
		t.Fatalf("toDesired: %v", err)
	}

	pipelines := pipelineConfigs(spec)
	kept, err := filterDesired(desired, []selector{{raw: "shop/web", project: "shop", service: "web"}})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	pipelines = filterPipelines(pipelines, kept)

	if len(pipelines) != 1 || pipelines[0].Project != "shop" {
		t.Fatalf("pipelines = %+v, want shop's config", pipelines)
	}
	if _, ok := pipelines[0].Builds["api"]; !ok {
		t.Fatalf("shop's config lost the unselected sibling's build entry: %+v", pipelines[0].Builds)
	}
	if _, ok := pipelines[0].Builds["web"]; !ok {
		t.Fatalf("shop's config lost the selected service's build entry: %+v", pipelines[0].Builds)
	}
}

// Applying one project must not rewrite another's sync state: a project with
// no selected service sends no pipeline config at all.
func TestFilteredPipelinesDropUnselectedProjects(t *testing.T) {
	src := `
spec_version = 1
project "shop" {
  git {
    url      = "https://example.com/shop.git"
    branch   = "main"
    auth_ref = "secret:shop/deploy-key"
  }
}
project "blog" {
  git {
    url      = "https://example.com/blog.git"
    branch   = "main"
    auth_ref = "secret:blog/deploy-key"
  }
}
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
}
service "ghost" {
  project = "blog"
  task "app" { image = "ghost" }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("parse:\n%s", jobspec.FormatDiagnostics(diags))
	}
	desired, err := toDesired(spec)
	if err != nil {
		t.Fatalf("toDesired: %v", err)
	}

	kept, err := filterDesired(desired, []selector{{raw: "shop", project: "shop"}})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	pipelines := filterPipelines(pipelineConfigs(spec), kept)
	if len(pipelines) != 1 || pipelines[0].Project != "shop" {
		t.Fatalf("pipelines = %+v, want only shop's config", pipelines)
	}
}

// The filter runs after parse and validation, so a selected service's
// ${service.*} references to unselected peers resolve exactly as they always
// did.
func TestAFilteredServiceStillResolvesReferencesToUnselectedPeers(t *testing.T) {
	src := `
spec_version = 1
project "shop" {}
service "api" {
  project = "shop"
  task "app" {
    image = "api:1"
    env   = { DATABASE_HOST = "${service.postgres.host}" }
  }
}
service "postgres" {
  project = "shop"
  task "pg" { image = "postgres:17" }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("parse:\n%s", jobspec.FormatDiagnostics(diags))
	}
	desired, err := toDesired(spec)
	if err != nil {
		t.Fatalf("toDesired: %v", err)
	}

	kept, err := filterDesired(desired, []selector{{raw: "shop/api", project: "shop", service: "api"}})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(kept) != 1 || kept[0].Service != "api" {
		t.Fatalf("kept = %v, want only shop/api", kept)
	}
	host := kept[0].Env["DATABASE_HOST"]
	if host == "" || strings.Contains(host, "${") {
		t.Fatalf("DATABASE_HOST = %q, want the resolved host of the unselected postgres", host)
	}
}

func TestSelectorsRefuseTheImagePath(t *testing.T) {
	_, _, err := loadSpec(nil, []selector{{raw: "shop/web", project: "shop", service: "web"}},
		"nginx", "web", "demo", 1)
	if err == nil || !strings.Contains(err.Error(), "do not combine") {
		t.Fatalf("err = %v, want the --image refusal", err)
	}
}

func TestASelectorWithoutASpecFileIsRefused(t *testing.T) {
	_, _, err := loadSpec(nil, []selector{{raw: "shop/web", project: "shop", service: "web"}},
		"", "", "", 1)
	if err == nil || !strings.Contains(err.Error(), "needs a spec file") {
		t.Fatalf("err = %v, want the no-spec-file refusal", err)
	}
}
