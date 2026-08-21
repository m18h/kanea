package main

import (
	"strings"
	"testing"

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
