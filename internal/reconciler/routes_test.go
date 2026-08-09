package reconciler_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/reconciler"
)

// routeHarness is a reconciler that publishes an edge route table.
func routeHarness(t *testing.T, baseDomain string) (*harness, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge", "routes.json")
	h := newHarness(t, func(cfg *reconciler.Config) {
		cfg.EdgeSnapshot = path
		cfg.BaseDomain = baseDomain
	})
	return h, path
}

// exposedService is a service with a frontend and an expose block.
func exposedService(domains ...string) reconciler.Desired {
	d := desiredWithPort(1)
	d.Expose = &reconciler.Expose{Domains: domains, Port: 8080}
	return d
}

func loadRoutes(t *testing.T, path string) edge.Snapshot {
	t.Helper()
	snap, err := edge.Load(path)
	if err != nil {
		t.Fatalf("load published routes: %v", err)
	}
	return snap
}

func TestReconcilePublishesEdgeRoutes(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService("shop.example.com"))
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Routes) != 1 {
		t.Fatalf("routes = %+v, want 1", snap.Routes)
	}
	route := snap.Routes[0]
	if route.Name() != "shop/web" {
		t.Errorf("route = %s", route.Name())
	}
	// The upstream is the service frontend, not an alloc: scaling must not
	// change the route table.
	if route.Upstream != h.network.vipOf("shop", "web") {
		t.Errorf("upstream = %q, want the service VIP %q", route.Upstream, h.network.vipOf("shop", "web"))
	}
	if route.Port != 8080 {
		t.Errorf("port = %d, want 8080", route.Port)
	}
	if snap.Index == 0 {
		t.Error("the snapshot carries no store index")
	}
}

// One wildcard DNS record for the base domain makes every service routable
// without another DNS change (PRD §7.2).
func TestReconcileGeneratesTheAutoFQDN(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService())
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Routes) != 1 {
		t.Fatalf("routes = %+v, want 1", snap.Routes)
	}
	if got := snap.Routes[0].Domains; len(got) != 1 || got[0] != "web.shop.apps.example.com" {
		t.Errorf("domains = %v, want [web.shop.apps.example.com]", got)
	}
}

// The auto-FQDN needs a base domain. Without one there is no name to publish,
// and inventing one would route traffic somewhere nobody asked for.
func TestReconcileSkipsAnExposedServiceWithNoName(t *testing.T) {
	h, path := routeHarness(t, "")
	h.setDesired(t, exposedService())
	h.reconcile(t)

	// The table is published and empty rather than absent: "there are no
	// routes" is a statement the edge needs, and withholding it would leave a
	// running edge serving whatever it had before.
	if got := loadRoutes(t, path).Routes; len(got) != 0 {
		t.Errorf("routes = %+v, want none for a service with no domain", got)
	}
}

// A service that is not exposed has no business in the edge's table.
func TestReconcileDoesNotPublishUnexposedServices(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, desiredWithPort(1))
	h.reconcile(t)

	if got := loadRoutes(t, path).Routes; len(got) != 0 {
		t.Errorf("routes = %+v, want none for an unexposed service", got)
	}
}

// The edge polls this file forever. Rewriting it every pass would make every
// reconcile look like a routing change.
func TestReconcileRepublishesOnlyOnChange(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService("shop.example.com"))
	h.reconcile(t)

	before := statOf(t, path)
	h.reconcile(t)
	h.reconcile(t)
	if after := statOf(t, path); after != before {
		t.Errorf("the snapshot was rewritten with no change (%v -> %v)", before, after)
	}

	// A real change must land, though.
	h.setDesired(t, exposedService("shop.example.com", "www.shop.example.com"))
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Routes) != 1 || len(snap.Routes[0].Domains) != 2 {
		t.Errorf("routes = %+v, want the added domain", snap.Routes)
	}
}

// Removing the expose block withdraws the route.
func TestReconcileWithdrawsARoute(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService("shop.example.com"))
	h.reconcile(t)
	if len(loadRoutes(t, path).Routes) != 1 {
		t.Fatal("the route was not published")
	}

	h.setDesired(t, desiredWithPort(1))
	h.reconcile(t)
	if got := loadRoutes(t, path).Routes; len(got) != 0 {
		t.Errorf("routes = %+v, want none after the expose block was removed", got)
	}
}

// Domains are canonicalised on the way into the table, because that is the form
// a Host header is matched against.
func TestReconcileCanonicalisesDomains(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService("SHOP.Example.COM."))
	h.reconcile(t)

	got := loadRoutes(t, path).Routes[0].Domains
	if len(got) != 1 || got[0] != "shop.example.com" {
		t.Errorf("domains = %v, want [shop.example.com]", got)
	}
}

// R16 rejects a collision inside one applied set; two separately applied
// projects can still collide, and the result must be deterministic rather than
// dependent on map iteration order.
func TestReconcileResolvesADomainCollisionDeterministically(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")

	first := exposedService("shop.example.com")
	second := exposedService("shop.example.com")
	second.Project = "blog"
	second.Service = "www"

	h.setDesired(t, first)
	h.setDesired(t, second)
	h.reconcile(t)

	snap := loadRoutes(t, path)
	// One claim survives — Validate would reject two — and it is the same one
	// every time: "blog/www" sorts before "shop/web".
	if len(snap.Routes) != 1 {
		t.Fatalf("routes = %+v, want exactly one surviving claim", snap.Routes)
	}
	if snap.Routes[0].Name() != "blog/www" {
		t.Errorf("winner = %s, want the first in sort order", snap.Routes[0].Name())
	}
}

// A published table must always be loadable by the edge: publishing something
// the reader rejects would freeze routing at the last good state for no reason.
func TestPublishedRoutesAreAlwaysValid(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService("shop.example.com"))
	second := exposedService()
	second.Service = "api"
	h.setDesired(t, second)
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if err := snap.Validate(); err != nil {
		t.Fatalf("published snapshot is invalid: %v", err)
	}
	if _, err := edge.NewTable(snap); err != nil {
		t.Fatalf("published snapshot does not index: %v", err)
	}
}

// statOf identifies a file version by its modification time and size, which is
// enough to notice a rewrite.
func statOf(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fmt.Sprintf("%d@%s", info.Size(), info.ModTime().Format(time.RFC3339Nano))
}

// kanead must repair its own output. A snapshot deleted on reboot, truncated by
// a full disk, or hand-edited would otherwise never be rewritten — nothing
// about desired state changed — and the edge would come back to an empty table
// and 404 the whole node.
func TestReconcileRepublishesAfterTheSnapshotIsLost(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, exposedService("shop.example.com"))
	h.reconcile(t)
	if len(loadRoutes(t, path).Routes) != 1 {
		t.Fatal("the route was not published")
	}

	for _, damage := range []func(){
		func() {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove: %v", err)
			}
		},
		func() {
			if err := os.WriteFile(path, []byte("{ truncated"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		},
	} {
		damage()
		h.reconcile(t)

		snap := loadRoutes(t, path)
		if len(snap.Routes) != 1 || snap.Routes[0].Name() != "shop/web" {
			t.Fatalf("routes = %+v, want the table rebuilt", snap.Routes)
		}
	}
}

// The precedence R20 defines, in the one place it lives. Getting this wrong
// means either ignoring what an operator wrote in a spec or ignoring what they
// set on the node, and both look like "TLS is broken".
func TestResolveTLSMode(t *testing.T) {
	tests := []struct {
		name        string
		expose      *reconciler.Expose
		nodeDefault string
		want        string
	}{
		{"no expose block", nil, "acme", ""},
		{"explicit beats the default", &reconciler.Expose{TLSMode: "self-signed"}, "acme", "self-signed"},
		{"explicit plaintext is honoured", &reconciler.Expose{TLSMode: "plaintext"}, "acme", "plaintext"},
		{"unset takes the node default", &reconciler.Expose{}, "self-signed", "self-signed"},
		{"unset with no default is unset", &reconciler.Expose{}, "", ""},
		// A record written before v1.33 meant ACME then and means ACME now,
		// which is what lets this change ship without a schema migration.
		{"pre-v1.33 record", &reconciler.Expose{LetsEncrypt: true}, "self-signed", "acme"},
		// The new field wins over the old one on a record that somehow carries
		// both — R20 refuses that combination at plan time.
		{"both, explicit wins", &reconciler.Expose{TLSMode: "provided", LetsEncrypt: true}, "acme", "provided"},
		// letsencrypt = false used to be indistinguishable from an absent
		// field, and still is: it defers to the node.
		{"pre-v1.33 false defers", &reconciler.Expose{LetsEncrypt: false}, "plaintext", "plaintext"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.expose.ResolveTLSMode(tc.nodeDefault); got != tc.want {
				t.Errorf("ResolveTLSMode(%q) = %q, want %q", tc.nodeDefault, got, tc.want)
			}
		})
	}
}

// A TLS mode change is a certificate decision, not a container one. Rolling
// every alloc of a service because its certificate now comes from somewhere
// else would be a restart nobody asked for.
func TestSpecHashIgnoresTLSMode(t *testing.T) {
	base := reconciler.Desired{
		Project: "shop", Service: "web", Count: 1,
		Image:  "nginx:1.27",
		Expose: &reconciler.Expose{Domains: []string{"shop.example.com"}, Port: 80, TLSMode: "acme"},
	}
	changed := base
	expose := *base.Expose
	expose.TLSMode = "self-signed"
	expose.TLSName = "shop"
	changed.Expose = &expose

	if reconciler.SpecHash(base) != reconciler.SpecHash(changed) {
		t.Error("changing the certificate source rolled the allocs")
	}
}
