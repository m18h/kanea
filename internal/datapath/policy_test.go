package datapath

import (
	"testing"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

func allowPolicy(project, service string, from ...network.ServiceRef) network.ProjectPolicy {
	return network.ProjectPolicy{
		Project:  project,
		Services: []network.ServicePolicy{{Service: service, AllowFrom: from}},
	}
}

func TestSyncPoliciesAddsTheDeclaredEdges(t *testing.T) {
	f := newFixture(t)
	policies := []network.ProjectPolicy{
		allowPolicy("shop", "db",
			network.ServiceRef{Project: "analytics", Service: "etl"},
			network.ServiceRef{Project: "backup", Service: "agent"},
		),
	}
	if err := f.d.SyncPolicies(t.Context(), policies); err != nil {
		t.Fatalf("SyncPolicies: %v", err)
	}
	if len(f.maps.allows) != 2 {
		t.Fatalf("allow_v4 holds %d edges, want 2: %v", len(f.maps.allows), f.maps.allows)
	}

	dst, err := f.d.ids.ServiceID(t.Context(), "shop", "db")
	if err != nil {
		t.Fatal(err)
	}
	src, err := f.d.ids.ServiceID(t.Context(), "analytics", "etl")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.maps.allows[dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src}]; !ok {
		t.Fatalf("allow_v4 misses %d<-%d: %v", dst, src, f.maps.allows)
	}
}

func TestSyncPoliciesRemovesStaleEdges(t *testing.T) {
	f := newFixture(t)
	etl := network.ServiceRef{Project: "analytics", Service: "etl"}
	agent := network.ServiceRef{Project: "backup", Service: "agent"}

	if err := f.d.SyncPolicies(t.Context(), []network.ProjectPolicy{
		allowPolicy("shop", "db", etl, agent),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.SyncPolicies(t.Context(), []network.ProjectPolicy{
		allowPolicy("shop", "db", etl),
	}); err != nil {
		t.Fatal(err)
	}

	if len(f.maps.allows) != 1 {
		t.Fatalf("allow_v4 holds %d edges after the withdrawal, want 1: %v", len(f.maps.allows), f.maps.allows)
	}
	dst, err := f.d.ids.ServiceID(t.Context(), "shop", "db")
	if err != nil {
		t.Fatal(err)
	}
	src, err := f.d.ids.ServiceID(t.Context(), "analytics", "etl")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.maps.allows[dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src}]; !ok {
		t.Fatal("the surviving edge is not the declared one")
	}
}

func TestSyncPoliciesIsIdempotent(t *testing.T) {
	f := newFixture(t)
	policies := []network.ProjectPolicy{
		allowPolicy("shop", "db", network.ServiceRef{Project: "analytics", Service: "etl"}),
	}
	if err := f.d.SyncPolicies(t.Context(), policies); err != nil {
		t.Fatal(err)
	}
	f.log.reset()

	if err := f.d.SyncPolicies(t.Context(), policies); err != nil {
		t.Fatal(err)
	}
	if got := f.log.taken(); len(got) != 0 {
		t.Fatalf("an unchanged policy set cost writes: %v", got)
	}
}

func TestSyncPoliciesEmptiesTheMapWhenNothingIsDeclared(t *testing.T) {
	f := newFixture(t)
	if err := f.d.SyncPolicies(t.Context(), []network.ProjectPolicy{
		allowPolicy("shop", "db", network.ServiceRef{Project: "analytics", Service: "etl"}),
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.d.SyncPolicies(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.maps.allows) != 0 {
		t.Fatalf("allow_v4 still holds %v; only declared edges live there", f.maps.allows)
	}
}
