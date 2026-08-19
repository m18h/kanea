package api_test

import (
	"context"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/reconciler"
)

// otherProject is a service outside "shop", to prove a scoped prune stays
// inside the projects it claims.
func otherProject(service string) reconciler.Desired {
	d := testService(service, 1)
	d.Project = "data"
	return d
}

func TestPruneRemovesOnlyUndeclaredServicesInScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, []reconciler.Desired{
		testService("web", 1), testService("legacy", 1), otherProject("postgres"),
	}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := h.client.ApplyScoped(ctx, api.ApplyRequest{
		Services:      []reconciler.Desired{testService("web", 1)},
		PruneProjects: []string{"shop"},
	})
	if err != nil {
		t.Fatalf("prune apply: %v", err)
	}
	if len(resp.Removed) != 1 || resp.Removed[0] != "shop/legacy" {
		t.Fatalf("Removed = %v, want [shop/legacy]", resp.Removed)
	}

	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	got := map[string]bool{}
	for _, svc := range services {
		got[svc.Project+"/"+svc.Service] = true
	}
	if !got["shop/web"] {
		t.Error("the declared service was removed")
	}
	if got["shop/legacy"] {
		t.Error("the orphan survived the prune")
	}
	// The failure that would matter most: a spec owning "shop" must never
	// reach into another project.
	if !got["data/postgres"] {
		t.Error("a prune scoped to shop deleted a service in data")
	}
}

// TestApplyStaysAdditiveWithoutAScope pins the invariant this feature bends.
// Every apply that does not ask to prune must behave exactly as it always did.
func TestApplyStaysAdditiveWithoutAScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, []reconciler.Desired{
		testService("web", 1), testService("legacy", 1),
	}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := h.client.Apply(ctx, []reconciler.Desired{testService("web", 1)}, nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(resp.Removed) != 0 {
		t.Errorf("Removed = %v, want nothing: an apply with no scope prunes nothing", resp.Removed)
	}
	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 2 {
		t.Errorf("services = %d, want 2: the undeclared one must survive", len(services))
	}
}

// TestPruneCanEmptyAProject covers the case the empty-Services refusal used to
// make impossible: a spec that still owns a project after its last service is
// removed from the file.
func TestPruneCanEmptyAProject(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, []reconciler.Desired{testService("web", 1)}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := h.client.ApplyScoped(ctx, api.ApplyRequest{PruneProjects: []string{"shop"}})
	if err != nil {
		t.Fatalf("empty prune apply: %v", err)
	}
	if len(resp.Removed) != 1 || resp.Removed[0] != "shop/web" {
		t.Fatalf("Removed = %v, want [shop/web]", resp.Removed)
	}
	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("services = %v, want the project emptied", services)
	}
}

// TestAnEmptyApplyIsStillRefused: relaxing the empty-Services check must not
// let a request that asks for nothing through.
func TestAnEmptyApplyIsStillRefused(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.ApplyScoped(context.Background(), api.ApplyRequest{}); err == nil {
		t.Error("an apply with no services and no prune scope should be rejected")
	}
}

// TestPruneAndApplyLandTogether: the deletes ride in the same store batch as
// the puts, so a rename never exists in a state where both or neither service
// is declared. Asserted through the index, which is one write for the batch.
func TestPruneAndApplyLandTogether(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.client.Apply(ctx, []reconciler.Desired{testService("old", 1)}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := h.client.ApplyScoped(ctx, api.ApplyRequest{
		Services:      []reconciler.Desired{testService("new", 1)},
		PruneProjects: []string{"shop"},
	})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if len(resp.Applied) != 1 || len(resp.Removed) != 1 {
		t.Fatalf("Applied = %v, Removed = %v, want one of each", resp.Applied, resp.Removed)
	}
	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 1 || services[0].Service != "new" {
		t.Errorf("services = %v, want only the renamed one", services)
	}
}
