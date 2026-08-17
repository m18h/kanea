package reconciler_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// A protocol-only edit must republish; the routesArePublished lesson: a
// field buildRoutes sets but routesEqual does not compare publishes exactly
// once and never again (R28, v1.41).
func TestProtocolEditIsRepublished(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	d := exposedService("api.shop.example.com")
	h.setDesired(t, d)
	h.reconcile(t)

	if got := loadRoutes(t, path).Routes[0].Protocol; got != "" {
		t.Fatalf("protocol = %q before the edit, want empty", got)
	}

	expose := *d.Expose
	expose.Protocol = "grpc"
	d.Expose = &expose
	h.setDesired(t, d)
	h.reconcile(t)

	if got := loadRoutes(t, path).Routes[0].Protocol; got != "grpc" {
		t.Errorf("protocol = %q after the edit, want grpc: the equality check is missing the field", got)
	}
}

// Removing the expose block withdraws the route.
// functionService is a lowered function with an http trigger and no declared
// domains: the case the mode resolution decides (§7.2.3).
func functionService() reconciler.Desired {
	d := desiredWithPort(1)
	d.Runtime = "io.containerd.wasmtime.v1"
	d.Function = &reconciler.FunctionMeta{HTTP: true}
	d.Expose = &reconciler.Expose{Port: 8080}
	return d
}

// The node-side mode resolution (§7.2.3, R20's pattern): with a base domain a
// function is host-routed like any service; with none it goes to the
// functions-port dispatch table, and never to both.
func TestFunctionRoutesResolveByBaseDomain(t *testing.T) {
	t.Run("base domain present", func(t *testing.T) {
		h, path := routeHarness(t, "apps.example.com")
		h.setDesired(t, functionService())
		h.reconcile(t)

		snap := loadRoutes(t, path)
		if len(snap.Routes) != 1 || len(snap.Functions) != 0 {
			t.Fatalf("routes=%d functions=%d, want 1/0: with a base domain a function is host-routed",
				len(snap.Routes), len(snap.Functions))
		}
		if got := snap.Routes[0].Domains[0]; got != "web.shop.apps.example.com" {
			t.Errorf("function FQDN = %q, want the auto-FQDN", got)
		}
	})

	t.Run("no base domain", func(t *testing.T) {
		h, path := routeHarness(t, "")
		h.setDesired(t, functionService())
		h.reconcile(t)

		snap := loadRoutes(t, path)
		if len(snap.Routes) != 0 || len(snap.Functions) != 1 {
			t.Fatalf("routes=%d functions=%d, want 0/1: with no base domain a function is path-dispatched",
				len(snap.Routes), len(snap.Functions))
		}
		fr := snap.Functions[0]
		if fr.Project != "shop" || fr.Function != "web" || fr.UpstreamPort != 8080 {
			t.Errorf("function route = %+v", fr)
		}
	})
}

// The snapshotIsPublished comparison must cover the functions table; the
// routesArePublished lesson: a half-compared snapshot publishes an edit
// exactly once and never again.
func TestFunctionTableEditsRepublish(t *testing.T) {
	h, path := routeHarness(t, "")
	d := functionService()
	h.setDesired(t, d)
	h.reconcile(t)

	before := loadRoutes(t, path)
	if len(before.Functions) != 1 || before.Functions[0].RateLimit != nil {
		t.Fatalf("unexpected initial table: %+v", before.Functions)
	}

	// Edit only the function's middleware: nothing else in the snapshot
	// changes, so a comparison that skipped functions would find it equal.
	d.Expose.RateLimit = &edge.RateLimit{Requests: 10, Window: "1m", Per: "ip"}
	h.setDesired(t, d)
	h.reconcile(t)

	after := loadRoutes(t, path)
	if len(after.Functions) != 1 || after.Functions[0].RateLimit == nil {
		t.Fatalf("the middleware edit was never republished: %+v", after.Functions)
	}
}

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
	// One claim survives (Validate would reject two) and it is the same one
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
// a full disk, or hand-edited would otherwise never be rewritten (nothing
// about desired state changed) and the edge would come back to an empty table
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
		// both; R20 refuses that combination at plan time.
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

// R28 (v1.41): the upstream-protocol marker is not baked into a container, so
// flipping it republishes routes and must never roll an alloc.
func TestSpecHashIgnoresExposeProtocol(t *testing.T) {
	base := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1,
		Image:  "grpc-api:v3",
		Expose: &reconciler.Expose{Domains: []string{"api.shop.example.com"}, Port: 50051},
	}
	changed := base
	expose := *base.Expose
	expose.Protocol = "grpc"
	changed.Expose = &expose

	if reconciler.SpecHash(base) != reconciler.SpecHash(changed) {
		t.Error("changing the upstream protocol rolled the allocs")
	}
}

// publishedService is a service with a node port.
func publishedService(host int, mode string) reconciler.Desired {
	d := desiredWithPort(1)
	d.Publish = []reconciler.PublishedPort{{Port: "http", Host: host, Mode: mode}}
	return d
}

func TestReconcilePublishesListeners(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, publishedService(8096, "http"))
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Listeners) != 1 {
		t.Fatalf("listeners = %+v, want 1", snap.Listeners)
	}
	l := snap.Listeners[0]
	if l.Port != 8096 || l.Mode != "http" {
		t.Errorf("listener = %+v", l)
	}
	// The upstream is the service VIP, exactly as a route's is: the eBPF LB
	// balances, so scaling must not change the listener.
	if l.Upstream != h.network.vipOf("shop", "web") || l.UpstreamPort != 8080 {
		t.Errorf("upstream = %s:%d, want the service frontend", l.Upstream, l.UpstreamPort)
	}
	// A published service is not automatically routed by name.
	if len(snap.Routes) != 0 {
		t.Errorf("routes = %+v, want none for a service with no expose block", snap.Routes)
	}
}

// The trap this whole change is most likely to fall into. snapshotIsPublished
// used to compare only routes, so a listener-only edit would be published once
// and never again: a steady-state pass finds the routes equal and returns
// early, and the edit sits in memory forever.
func TestPublishChangeIsRepublished(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, publishedService(8096, "http"))
	h.reconcile(t)

	before := statOf(t, path)
	h.reconcile(t)
	if after := statOf(t, path); after != before {
		t.Fatalf("a steady-state pass rewrote the snapshot (%v -> %v)", before, after)
	}

	// Only the CIDR changes: no route, no port, no upstream.
	changed := publishedService(8096, "http")
	changed.Publish[0].IPRestriction = &edge.IPRestriction{Allow: []string{"192.168.0.0/16"}}
	h.setDesired(t, changed)
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Listeners) != 1 || snap.Listeners[0].IPRestriction == nil {
		t.Fatalf("listeners = %+v, want the ip_restriction published", snap.Listeners)
	}

	// And it must stay published: a second pass must not decide the file is
	// stale and flip it back.
	settled := statOf(t, path)
	h.reconcile(t)
	if after := statOf(t, path); after != settled {
		t.Error("the listener edit never settled; the snapshot is rewritten every pass")
	}
}

// Two services cannot hold one node port. The survivor is the same one every
// time rather than whichever map iteration reached first.
func TestReconcileResolvesAPortCollisionDeterministically(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")

	first := publishedService(8096, "http")
	second := publishedService(8096, "http")
	second.Project = "blog"
	second.Service = "www"

	h.setDesired(t, first)
	h.setDesired(t, second)
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Listeners) != 1 {
		t.Fatalf("listeners = %+v, want exactly one surviving claim", snap.Listeners)
	}
	if snap.Listeners[0].Name() != "blog/www" {
		t.Errorf("winner = %s, want the first in sort order", snap.Listeners[0].Name())
	}
}

// A tcp listener carries only what it can enforce. A record written by hand
// with a rate limit on one must not produce a snapshot the edge refuses:
// which would freeze routing at the last good table.
func TestBuildListenersDropsMiddlewareATCPListenerCannotApply(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")

	d := publishedService(5432, "tcp")
	d.Publish[0].RateLimit = &edge.RateLimit{Requests: 10, Window: "1m"}
	d.Publish[0].Headers = &edge.Headers{RequestSet: map[string]string{"X-Real-IP": "1"}}
	h.setDesired(t, d)
	h.reconcile(t)

	snap := loadRoutes(t, path)
	if len(snap.Listeners) != 1 {
		t.Fatalf("listeners = %+v, want 1", snap.Listeners)
	}
	if snap.Listeners[0].RateLimit != nil || snap.Listeners[0].Headers != nil {
		t.Error("a tcp listener was published carrying middleware it cannot apply")
	}
	if err := snap.Validate(); err != nil {
		t.Fatalf("the published snapshot is invalid: %v", err)
	}
}

// A published port that names a port the service never declared would be a
// listening socket in front of nothing.
func TestBuildListenersNeverDialsAnUndeclaredPort(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")

	d := desiredWithPort(1)
	d.Publish = []reconciler.PublishedPort{{Port: "grpc", Host: 9000, Mode: "tcp"}}
	h.setDesired(t, d)
	h.reconcile(t)

	if got := loadRoutes(t, path).Listeners; len(got) != 0 {
		t.Errorf("listeners = %+v, want none for a port the service does not declare", got)
	}
}

// Publishing a port changes nothing baked into a container. If it were in the
// spec hash, fixing a typo in a CIDR would roll every alloc of the service.
func TestSpecHashIgnoresPublish(t *testing.T) {
	base := reconciler.Desired{
		Project: "media", Service: "jellyfin", Count: 1, Image: "jellyfin:10.9",
		Ports: []reconciler.Port{{Name: "http", Container: 8096}},
	}
	changed := base
	changed.Publish = []reconciler.PublishedPort{{
		Port: "http", Host: 8096, Mode: "http",
		IPRestriction: &edge.IPRestriction{Allow: []string{"192.168.0.0/16"}},
	}}

	if reconciler.SpecHash(base) != reconciler.SpecHash(changed) {
		t.Error("publishing a node port rolled the allocs")
	}
}

// udpService is a service whose only port is udp: no frontend, publish-only
// reachability (v1.42).
func udpService(count int) reconciler.Desired {
	d := desired(count)
	d.Ports = []reconciler.Port{{Name: "game", Container: 34197, Protocol: reconciler.PortProtocolUDP}}
	d.Publish = []reconciler.PublishedPort{{Port: "game", Host: 34197, Mode: "udp"}}
	return d
}

// A udp listener carries backend addresses, not the VIP (the LB cannot front
// datagrams) and a udp-only service holds no frontend at all.
func TestReconcilePublishesAUDPListenerWithBackends(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, udpService(2))
	h.reconcile(t)

	if svcs := h.network.lastLBSync(); len(svcs) != 0 {
		t.Fatalf("LB services = %+v, want none for a udp-only service", svcs)
	}

	snap := loadRoutes(t, path)
	if len(snap.Listeners) != 1 {
		t.Fatalf("listeners = %+v, want 1", snap.Listeners)
	}
	l := snap.Listeners[0]
	if l.Mode != edge.ListenerUDP || l.Port != 34197 || l.UpstreamPort != 34197 {
		t.Errorf("listener = %+v", l)
	}
	if l.Upstream != "" {
		t.Errorf("upstream = %q, want none: a udp listener dials backends", l.Upstream)
	}
	if len(l.Backends) != 2 {
		t.Errorf("backends = %v, want both running allocs", l.Backends)
	}
}

// Backend churn must republish the snapshot: the backend list is how a udp
// listener reaches anything, so leaving it out of listenersEqual would repeat
// the routesArePublished mistake with a new field.
func TestUDPBackendChurnRepublishes(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	h.setDesired(t, udpService(2))
	h.reconcile(t)
	if got := loadRoutes(t, path).Listeners[0].Backends; len(got) != 2 {
		t.Fatalf("backends = %v, want 2", got)
	}

	h.setDesired(t, udpService(1))
	h.reconcile(t)
	h.reconcile(t) // the pass after the stop sees the shrunken attachment set
	if got := loadRoutes(t, path).Listeners[0].Backends; len(got) != 1 {
		t.Fatalf("backends = %v, want the survivor only", got)
	}
}

// A tcp port beside a udp one keeps its frontend: only the udp half leaves the
// LB, and the two listeners of one service may share a host port across
// families.
func TestMixedProtocolServiceKeepsItsTCPFrontend(t *testing.T) {
	h, path := routeHarness(t, "apps.example.com")
	d := desiredWithPort(1)
	d.Ports = append(d.Ports, reconciler.Port{Name: "game", Container: 8080, Protocol: reconciler.PortProtocolUDP})
	d.Publish = []reconciler.PublishedPort{
		{Port: "http", Host: 9000, Mode: "tcp"},
		{Port: "game", Host: 9000, Mode: "udp"},
	}
	h.setDesired(t, d)
	h.reconcile(t)

	svcs := h.network.lastLBSync()
	if len(svcs) != 1 || len(svcs[0].Ports) != 1 || svcs[0].Ports[0].Name != "http" {
		t.Fatalf("LB services = %+v, want the tcp port alone", svcs)
	}
	snap := loadRoutes(t, path)
	if len(snap.Listeners) != 2 {
		t.Fatalf("listeners = %+v, want the tcp and udp listeners to share the port", snap.Listeners)
	}
}

// A pre-v1.50 record (one expose block) must serialize exactly as it always
// has: ExtraExposes rides omitempty, so the key exists only on records that
// declared a second route. A key appearing on every record would be a
// byte-level change to state nobody edited (the R23 lesson).
func TestASingleRouteRecordCarriesNoExtraExposesKey(t *testing.T) {
	d := reconciler.Desired{Project: "shop", Service: "web",
		Expose: &reconciler.Expose{Port: 80}}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "extra_exposes") {
		t.Errorf("a single-route record serialized an extra_exposes key:\n%s", raw)
	}

	// And AllExposes is the one read path: first block first, extras after.
	d.ExtraExposes = []reconciler.Expose{{Port: 9090}}
	all := d.AllExposes()
	if len(all) != 2 || all[0].Port != 80 || all[1].Port != 9090 {
		t.Errorf("AllExposes = %+v, want ports [80 9090]", all)
	}
}
