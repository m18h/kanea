package datapath

import (
	"testing"
)

func TestIDsAreMonotonicAndDistinct(t *testing.T) {
	st := newFakeStore()
	a := newIDAllocator(st)
	ctx := t.Context()

	project, err := a.ProjectID(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	service, err := a.ServiceID(ctx, "shop", "web")
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := a.FrontendID(ctx, "shop", "web", "http")
	if err != nil {
		t.Fatal(err)
	}
	if project == 0 || service == 0 || frontend == 0 {
		t.Fatalf("ids = %d/%d/%d: zero must never be minted, it reads as unset", project, service, frontend)
	}
	if project == service || uint32(frontend) == service || uint32(frontend) == project {
		t.Fatalf("ids = %d/%d/%d, want all distinct: one sequence covers every namespace", project, service, frontend)
	}
	if project >= service || service >= uint32(frontend) {
		t.Fatalf("ids = %d/%d/%d, want monotonic in allocation order", project, service, frontend)
	}
}

func TestIDsAreStableAcrossRestarts(t *testing.T) {
	st := newFakeStore()
	ctx := t.Context()

	first := newIDAllocator(st)
	serviceA, err := first.ServiceID(ctx, "shop", "web")
	if err != nil {
		t.Fatal(err)
	}
	serviceB, err := first.ServiceID(ctx, "shop", "db")
	if err != nil {
		t.Fatal(err)
	}

	// A "restart": a fresh allocator over the same store.
	second := newIDAllocator(st)
	gotA, err := second.ServiceID(ctx, "shop", "web")
	if err != nil {
		t.Fatal(err)
	}
	if gotA != serviceA {
		t.Fatalf("shop/web = %d after restart, want the original %d", gotA, serviceA)
	}

	// A new name gets a new id above everything ever minted, never a reuse,
	// even of ids whose owners are long gone (a reused id would make a pinned
	// map lie).
	fresh, err := second.ServiceID(ctx, "shop", "cache")
	if err != nil {
		t.Fatal(err)
	}
	if fresh <= serviceB {
		t.Fatalf("new id %d is not above the high-water mark %d", fresh, serviceB)
	}
}

func TestServiceNameResolvesTheReverseMapping(t *testing.T) {
	st := newFakeStore()
	a := newIDAllocator(st)
	ctx := t.Context()

	id, err := a.ServiceID(ctx, "shop", "web")
	if err != nil {
		t.Fatal(err)
	}

	// Through a fresh allocator, so the reverse map is proven to load from
	// the store rather than living only in the minting process.
	b := newIDAllocator(st)
	ref, ok, err := b.ServiceName(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || ref.Project != "shop" || ref.Service != "web" {
		t.Fatalf("ServiceName(%d) = %v (ok=%v), want shop/web", id, ref, ok)
	}

	if _, ok, err := b.ServiceName(ctx, 9999); err != nil || ok {
		t.Fatalf("ServiceName(9999) ok=%v err=%v, want a clean miss", ok, err)
	}
}

func TestFrontendServiceFoldsPortsIntoTheirService(t *testing.T) {
	st := newFakeStore()
	a := newIDAllocator(st)
	ctx := t.Context()

	http, err := a.FrontendID(ctx, "shop", "web", "http")
	if err != nil {
		t.Fatal(err)
	}
	grpc, err := a.FrontendID(ctx, "shop", "web", "grpc")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint16{http, grpc} {
		ref, ok, err := a.FrontendService(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok || ref.String() != "shop/web" {
			t.Fatalf("FrontendService(%d) = %v (ok=%v), want shop/web", id, ref, ok)
		}
	}
}

func TestFrontendIDRefusesThe16BitOverflow(t *testing.T) {
	st := newFakeStore()
	// The shared sequence has run past what svc_val.svc_id can carry.
	st.seed(t, idSeqKey, uint32(70000))
	a := newIDAllocator(st)

	if _, err := a.FrontendID(t.Context(), "shop", "web", "http"); err == nil {
		t.Fatal("FrontendID = nil beyond 65535, want a refusal: a wrapped id would collide in svc_backends")
	}
}
