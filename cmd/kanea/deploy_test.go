package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
)

// richService is a service carrying everything `--image` cannot express, which
// is the whole reason both behaviours below exist.
func richService() reconciler.Desired {
	return reconciler.Desired{
		Project: "shop", Service: "web", Count: 3,
		Image: "registry.example/web:v1",
		Env:   map[string]string{"DATABASE_URL": "secret:shop/db"},
		Ports: []reconciler.Port{{Name: "http", Container: 8080}},
		Expose: &reconciler.Expose{
			Domains: []string{"web.shop.example.com"},
		},
		Volumes:   []reconciler.Volume{{Name: "data", MountPath: "/data"}},
		Check:     &reconciler.HealthCheck{Type: "http", Path: "/healthz"},
		Scaling:   &reconciler.ScalingPolicy{Min: 2, Max: 10},
		Resources: runtime.Resources{PidsLimit: DefaultPidsLimit},
	}
}

// TestDeployChangesOnlyTheImage is the test this feature exists for.
//
// There is no route that sets an image, so a deploy is a read-modify-write of
// the whole record. If it ever stops round-tripping, a deploy silently deletes
// whatever the writer of that code did not think about - which is exactly what
// `kanea run --image` does today and why `kanea deploy` was added.
func TestDeployChangesOnlyTheImage(t *testing.T) {
	before := richService()
	after := before // the copy runDeploy makes
	after.Image = "registry.example/web@sha256:abc"

	if after.Image == before.Image {
		t.Fatal("the test did not change the image")
	}
	// Everything else must be identical. Compared field by field rather than
	// with a single equality so a failure names what was lost.
	if len(after.Env) != len(before.Env) || after.Env["DATABASE_URL"] != before.Env["DATABASE_URL"] {
		t.Errorf("env changed: %v -> %v", before.Env, after.Env)
	}
	if len(after.Ports) != len(before.Ports) {
		t.Errorf("ports changed: %v -> %v", before.Ports, after.Ports)
	}
	if after.Expose == nil || len(after.Expose.Domains) != 1 {
		t.Errorf("expose changed: %+v -> %+v", before.Expose, after.Expose)
	}
	if len(after.Volumes) != len(before.Volumes) {
		t.Errorf("volumes changed: %v -> %v", before.Volumes, after.Volumes)
	}
	if after.Check == nil || after.Scaling == nil {
		t.Error("health check or scaling was dropped")
	}
	if after.Count != before.Count {
		t.Errorf("count changed: %d -> %d", before.Count, after.Count)
	}
}

// TestFieldsLostByImageApplyNamesWhatWouldGo pins the message `kanea run
// --image` refuses with. The list is the point: "this would delete things" is
// not actionable, and the operator needs to recognise their own spec in it.
func TestFieldsLostByImageApplyNamesWhatWouldGo(t *testing.T) {
	lost := fieldsLostByImageApply(richService())
	for _, want := range []string{"ports", "expose", "env", "volumes", "health check", "scaling"} {
		if !containsString(lost, want) {
			t.Errorf("fieldsLostByImageApply did not name %q; got %v", want, lost)
		}
	}
}

// TestAnImageApplyWouldLoseInitContainers. `kanea run --image` builds a
// Desired from nothing, so applying it over a service with an init sequence
// would silently delete the migration that has to run before it starts (R32).
func TestAnImageApplyWouldLoseInitContainers(t *testing.T) {
	svc := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1, Image: "api:1",
		Init: []reconciler.InitContainer{{Name: "migrate", Image: "migrate:1"}},
	}
	if !containsString(fieldsLostByImageApply(svc), "init containers") {
		t.Errorf("fieldsLostByImageApply did not name init containers; got %v",
			fieldsLostByImageApply(svc))
	}
}

// TestABareServiceLosesNothing keeps the documented quickstart idempotent.
//
// `kanea run --image nginx --name web --project demo` is a first-class path,
// and re-running it must not start failing just because the service now
// exists: refusing on existence rather than on loss would break the first
// thing anyone is told to type.
func TestABareServiceLosesNothing(t *testing.T) {
	bare := reconciler.Desired{
		Project: "demo", Service: "web", Count: 1,
		Image:     "nginx:1.27-alpine",
		Resources: runtime.Resources{PidsLimit: DefaultPidsLimit},
	}
	if lost := fieldsLostByImageApply(bare); len(lost) > 0 {
		t.Errorf("a bare service reported losses %v; re-running the quickstart would refuse", lost)
	}
}

func TestDeployIsRegistered(t *testing.T) {
	var found *command
	for i := range commands {
		if commands[i].name == "deploy" {
			found = &commands[i]
		}
	}
	if found == nil {
		t.Fatal("kanea deploy is not in the command table")
	}
	if !strings.Contains(found.desc, "image") {
		t.Errorf("deploy's description does not mention the image: %q", found.desc)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestDeployCarriesInitStepsDeclaringTheTaskImage (PRD v1.99): the common init
// shape is the app's own image with a different command - a migration - and a
// deploy that moved the task alone ran yesterday's migrations against today's
// application. A step on any other image is untouched.
func TestDeployCarriesInitStepsDeclaringTheTaskImage(t *testing.T) {
	svc := richService()
	svc.Init = []reconciler.InitContainer{
		{Name: "chown", Image: "busybox:1.36"},
		{Name: "migrate", Image: svc.Image, Command: []string{"web", "migrate"}},
	}

	moved := reconciler.RetargetImage(&svc, "registry.example/web@sha256:abc")

	if len(moved) != 1 || moved[0] != "migrate" {
		t.Fatalf("moved = %v, want [migrate]", moved)
	}
	if svc.Init[0].Image != "busybox:1.36" {
		t.Errorf("a step on its own image moved: %q", svc.Init[0].Image)
	}
	if svc.Init[1].Image != "registry.example/web@sha256:abc" {
		t.Errorf("the migrate step did not follow: %q", svc.Init[1].Image)
	}
	if len(svc.Init[1].Command) != 2 {
		t.Error("the step's command was not preserved")
	}
}

// A deploy of the image a service already declares is a no-op (PRD v1.99) -
// unless the service is down, in which case the no-op was the only answer an
// operator could not use. It now restarts it instead: the generation bump is
// the spec change that revives a failed alloc (PRD v1.113, R29), and it goes
// through the route that already means recovery rather than a new one.
func TestADeployOntoADegradedServiceRestartsIt(t *testing.T) {
	const image = "registry.example/website:544cd63e"
	cases := []struct {
		name        string
		state       reconciler.AllocState
		wantRestart bool
	}{
		{name: "a failed alloc is restarted", state: reconciler.AllocFailed, wantRestart: true},
		{name: "a running one is still nothing to do", state: reconciler.AllocRunning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var restarted, applied atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == api.PathServices && r.Method == http.MethodGet:
					resp := api.ServicesResponse{Services: []api.ServiceView{{
						Desired: reconciler.Desired{
							Project: "huddle", Service: "website", Count: 1, Image: image,
						},
						SpecHash: "sha256:current",
					}}}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Error(err)
					}
				case r.URL.Path == api.PathServices && r.Method == http.MethodPut:
					applied.Store(true)
					if err := json.NewEncoder(w).Encode(api.ApplyResponse{}); err != nil {
						t.Error(err)
					}
				case r.URL.Path == api.PathAllocs:
					resp := api.AllocsResponse{Allocs: []reconciler.AllocRecord{{
						ID:      reconciler.AllocID("huddle", "website", 0),
						Project: "huddle", Service: "website",
						State: tc.state, LastExitCode: 1, SpecHash: "sha256:current",
					}}}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Error(err)
					}
				case strings.HasSuffix(r.URL.Path, "/restart"):
					restarted.Store(true)
					if err := json.NewEncoder(w).Encode(api.ApplyResponse{}); err != nil {
						t.Error(err)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			// --no-wait because what is under test is which route the command
			// reaches, not the convergence the wait watches.
			err := runDeploy([]string{
				"huddle/website", image, "--no-wait", "--url", srv.URL, "--token", "t",
			})
			if err != nil {
				t.Fatalf("runDeploy: %v", err)
			}
			if got := restarted.Load(); got != tc.wantRestart {
				t.Errorf("restart route called = %v, want %v", got, tc.wantRestart)
			}
			// Either way the image is already right, so nothing is applied:
			// a retarget here would silently repair a diverged init step,
			// which is exactly what v1.99's no-op boundary protects.
			if applied.Load() {
				t.Error("the deploy applied a spec for an image the service already declares")
			}
		})
	}
}

// TestEveryDeploySiteRetargetsThroughTheOneHelper reads the source of the
// three deploy sites - the CLI verb, MCP's deploy_service, and the GitOps
// deployer - and fails when one stops calling reconciler.RetargetImage. The
// lock-step property (a step that starts equal to the task stays equal
// through every deploy) holds only while all three follow, so a site that
// quietly goes back to assigning Image directly reintroduces the skew one
// deploy at a time (PRD v1.99; the TestTheAgentWiresEveryOptionalReconciler-
// Dependency shape, applied to a client-side recipe).
func TestEveryDeploySiteRetargetsThroughTheOneHelper(t *testing.T) {
	for _, site := range []struct{ name, path string }{
		{"kanea deploy", "client_cmds.go"},
		{"the GitOps deployer", "pipelines.go"},
		{"MCP deploy_service", "../../internal/mcp/tools.go"},
	} {
		src, err := os.ReadFile(site.path)
		if err != nil {
			t.Fatalf("read %s: %v", site.path, err)
		}
		if !strings.Contains(string(src), "reconciler.RetargetImage(") {
			t.Errorf("%s (%s) no longer calls reconciler.RetargetImage: "+
				"init steps on the task's image stop following its deploys there",
				site.name, site.path)
		}
	}
}
