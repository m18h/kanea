package datapath

import (
	"net/netip"
	"testing"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

func webService(backends ...network.Backend) network.Service {
	return network.Service{
		Project: "shop", Service: "web", VIP: "10.201.0.1",
		Ports:    []network.ServicePort{{Name: "http", Port: 80, TargetPort: 8080}},
		Backends: backends,
	}
}

var webKey = dpmap.SvcAddr{IP: netip.MustParseAddr("10.201.0.1"), Port: 80, Proto: protoTCP}

func TestSyncServicesProgramsAFrontend(t *testing.T) {
	f := newFixture(t)
	svc := webService(
		network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"},
		network.Backend{AllocID: "shop-web-1", IPv4: "10.200.0.3"},
	)
	if err := f.d.SyncServices(t.Context(), []network.Service{svc}); err != nil {
		t.Fatalf("SyncServices: %v", err)
	}

	val, ok := f.maps.services[webKey]
	if !ok {
		t.Fatalf("no svc_v4 entry for %v; have %v", webKey, f.maps.services)
	}
	if val.Count != 2 || val.Gen != 1 {
		t.Fatalf("svc_val = %+v, want count 2 gen 1", val)
	}
	backend, ok := f.maps.backends[dpmap.BackendKey{SvcID: val.SvcID, Index: 0, Gen: 1}]
	if !ok {
		t.Fatalf("no backend at index 0 gen 1; have %v", f.maps.backends)
	}
	if backend.IP.String() != "10.200.0.2" || backend.Port != 8080 {
		t.Fatalf("backend 0 = %+v, want 10.200.0.2:8080 (sorted by alloc id, target port)", backend)
	}
}

func TestSyncServicesNoDriftNoWrites(t *testing.T) {
	f := newFixture(t)
	svcs := []network.Service{webService(network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"})}
	if err := f.d.SyncServices(t.Context(), svcs); err != nil {
		t.Fatalf("first SyncServices: %v", err)
	}
	f.log.reset()

	if err := f.d.SyncServices(t.Context(), svcs); err != nil {
		t.Fatalf("second SyncServices: %v", err)
	}
	if got := f.log.taken(); len(got) != 0 {
		t.Fatalf("an unchanged set of services cost writes: %v", got)
	}
}

func TestSyncServicesFlipsAChangedBackendSet(t *testing.T) {
	f := newFixture(t)
	if err := f.d.SyncServices(t.Context(), []network.Service{
		webService(network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"}),
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.d.SyncServices(t.Context(), []network.Service{
		webService(network.Backend{AllocID: "shop-web-1", IPv4: "10.200.0.3"}),
	}); err != nil {
		t.Fatal(err)
	}

	val := f.maps.services[webKey]
	if val.Gen != 2 || val.Count != 1 {
		t.Fatalf("svc_val after flip = %+v, want count 1 gen 2", val)
	}
	if _, stale := f.maps.backends[dpmap.BackendKey{SvcID: val.SvcID, Index: 0, Gen: 1}]; stale {
		t.Fatal("gen 1 backend survived the flip")
	}
	fresh, ok := f.maps.backends[dpmap.BackendKey{SvcID: val.SvcID, Index: 0, Gen: 2}]
	if !ok || fresh.IP.String() != "10.200.0.3" {
		t.Fatalf("gen 2 backend = %+v (ok=%v), want 10.200.0.3", fresh, ok)
	}
}

func TestFlipOpsPutThenCommitThenDelete(t *testing.T) {
	f := newFixture(t)
	if err := f.d.SyncServices(t.Context(), []network.Service{
		webService(network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.SyncServices(t.Context(), []network.Service{
		webService(
			network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"},
			network.Backend{AllocID: "shop-web-1", IPv4: "10.200.0.3"},
		),
	}); err != nil {
		t.Fatal(err)
	}

	last := f.maps.flips[len(f.maps.flips)-1]
	// Puts of the new generation, one commit, deletes of the old; in that
	// order and no other: the commit is the atomicity.
	wantKinds := []dpmap.OpKind{dpmap.OpPutBackend, dpmap.OpPutBackend, dpmap.OpCommitService, dpmap.OpDeleteBackend}
	if len(last) != len(wantKinds) {
		t.Fatalf("flip has %d ops (%v), want %d", len(last), last, len(wantKinds))
	}
	for i, k := range wantKinds {
		if last[i].Kind != k {
			t.Fatalf("flip op %d = %v, want kind %v", i, last[i], k)
		}
	}
}

func TestSyncServicesRemovesStaleFrontends(t *testing.T) {
	f := newFixture(t)
	if err := f.d.SyncServices(t.Context(), []network.Service{
		webService(network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"}),
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.d.SyncServices(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.maps.services) != 0 {
		t.Fatalf("svc_v4 still holds %v after the service went away", f.maps.services)
	}
	if len(f.maps.backends) != 0 {
		t.Fatalf("svc_backends still holds %v after the service went away", f.maps.backends)
	}
}

func TestSyncServicesRefusesUDP(t *testing.T) {
	f := newFixture(t)
	svc := network.Service{
		Project: "shop", Service: "syslog", VIP: "10.201.0.1",
		Ports: []network.ServicePort{{Name: "syslog", Port: 514, Protocol: "UDP"}},
	}
	if err := f.d.SyncServices(t.Context(), []network.Service{svc}); err == nil {
		t.Fatal("SyncServices = nil for a UDP port, want a refusal: a control the datapath silently drops is worse than one the spec never claimed")
	}
	if got := f.log.taken(); len(got) != 0 {
		t.Fatalf("a refused sync still wrote: %v", got)
	}
}

func TestSyncServicesSkipsPortlessServices(t *testing.T) {
	f := newFixture(t)
	svc := network.Service{Project: "shop", Service: "worker"}
	if err := f.d.SyncServices(t.Context(), []network.Service{svc}); err != nil {
		t.Fatalf("SyncServices: %v", err)
	}
	if len(f.maps.services) != 0 {
		t.Fatalf("a portless service was programmed: %v", f.maps.services)
	}
}

func TestSyncServicesDefaultsTheTargetPort(t *testing.T) {
	f := newFixture(t)
	svc := network.Service{
		Project: "shop", Service: "web", VIP: "10.201.0.1",
		Ports:    []network.ServicePort{{Name: "http", Port: 80}},
		Backends: []network.Backend{{AllocID: "shop-web-0", IPv4: "10.200.0.2"}},
	}
	if err := f.d.SyncServices(t.Context(), []network.Service{svc}); err != nil {
		t.Fatal(err)
	}
	val := f.maps.services[webKey]
	backend := f.maps.backends[dpmap.BackendKey{SvcID: val.SvcID, Index: 0, Gen: 1}]
	if backend.Port != 80 {
		t.Fatalf("backend port = %d, want the frontend port 80 when no target is named", backend.Port)
	}
}

func TestSyncServicesPublishesTheZoneFromTheSameCall(t *testing.T) {
	f := newFixture(t)
	zone := &zoneRecorder{}
	f.d.dns = zone

	svcs := []network.Service{webService(network.Backend{AllocID: "shop-web-0", IPv4: "10.200.0.2"})}
	if err := f.d.SyncServices(t.Context(), svcs); err != nil {
		t.Fatal(err)
	}
	zone.mu.Lock()
	defer zone.mu.Unlock()
	if len(zone.calls) != 1 || len(zone.calls[0]) != 1 {
		t.Fatalf("SetZone calls = %v, want exactly one with the synced services", zone.calls)
	}
}
