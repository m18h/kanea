package reconciler

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/m18h/kanea/internal/store"
)

// The v6 VIP twin (PRD v1.41): its own lb/vip6/ key space, allocated in the
// same pass and the same Apply batch, and the lb/vip/ records stay
// byte-identical, so a rollback or a replicated Store from a v4-only node
// reads unchanged.

func vipStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestVIPSyncAllocatesBothFamilies(t *testing.T) {
	s := vipStore(t)
	a, err := newVIPAllocator(s, "10.201.0.0/16", "fd10:245::/64")
	if err != nil {
		t.Fatal(err)
	}

	refs := []serviceRef{{Project: "shop", Service: "web"}, {Project: "shop", Service: "api"}}
	v4, v6, err := a.Sync(context.Background(), refs)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if v4["shop/api"] != "10.201.0.1" || v4["shop/web"] != "10.201.0.2" {
		t.Errorf("v4 = %v, want lowest-free in sorted order", v4)
	}
	if v6["shop/api"] != "fd10:245::1" || v6["shop/web"] != "fd10:245::2" {
		t.Errorf("v6 = %v, want the twins in the same order", v6)
	}

	// A second sync changes nothing: both assignments are durable.
	again4, again6, err := a.Sync(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	if again4["shop/web"] != v4["shop/web"] || again6["shop/web"] != v6["shop/web"] {
		t.Errorf("assignments moved across a sync: %v %v", again4, again6)
	}

	// Releasing a service releases both halves.
	v4, v6, err = a.Sync(context.Background(), refs[:1])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v4["shop/api"]; ok {
		t.Error("released v4 assignment survived")
	}
	if _, ok := v6["shop/api"]; ok {
		t.Error("released v6 assignment survived")
	}
}

// The lb/vip/ record encoding is pinned byte-for-byte: a JSON string of the
// address, nothing else. A v6-enabled node writing anything different into
// the v4 space would break a rollback and every replicated reader.
func TestVIPRecordEncodingIsUnchanged(t *testing.T) {
	s := vipStore(t)
	a, err := newVIPAllocator(s, "10.201.0.0/16", "fd10:245::/64")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Sync(context.Background(), []serviceRef{{Project: "shop", Service: "web"}}); err != nil {
		t.Fatal(err)
	}

	rec, err := s.Get(context.Background(), store.KindKV, VIPKey("shop", "web"))
	if err != nil {
		t.Fatalf("read the v4 record: %v", err)
	}
	if got := string(rec.Value); got != `"10.201.0.1"` {
		t.Errorf("lb/vip record = %s, want the bare JSON string a pre-v1.41 node wrote", got)
	}
	rec6, err := s.Get(context.Background(), store.KindKV, VIP6Key("shop", "web"))
	if err != nil {
		t.Fatalf("read the v6 record: %v", err)
	}
	if got := string(rec6.Value); got != `"fd10:245::1"` {
		t.Errorf("lb/vip6 record = %s", got)
	}
}

// With v6 off, the lb/vip6/ key space is left exactly as it is: stale twins
// from a formerly-enabled node are released only when v6 is enabled again,
// never silently deleted (PRD v1.41).
func TestV4OnlySyncLeavesStaleV6TwinsAlone(t *testing.T) {
	s := vipStore(t)

	dual, err := newVIPAllocator(s, "10.201.0.0/16", "fd10:245::/64")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := dual.Sync(context.Background(),
		[]serviceRef{{Project: "shop", Service: "web"}}); err != nil {
		t.Fatal(err)
	}

	// The node's v6 is turned off; the service is later deleted.
	v4only, err := newVIPAllocator(s, "10.201.0.0/16", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, v6, err := v4only.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	} else if v6 != nil {
		t.Errorf("a v4-only allocator returned a v6 map: %v", v6)
	}

	if _, err := s.Get(context.Background(), store.KindKV, VIP6Key("shop", "web")); err != nil {
		t.Errorf("the stale v6 twin was deleted by a v4-only sync: %v", err)
	}

	// Re-enabling v6 is when the stale twin is finally released.
	if _, _, err := dual.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), store.KindKV, VIP6Key("shop", "web")); err == nil {
		t.Error("re-enabling v6 did not release the stale twin")
	}
}
