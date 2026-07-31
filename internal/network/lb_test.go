package network

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLBWriter(t *testing.T) (*Cilium, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lb-state.json")
	c, err := New(Config{LBStateFile: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, path
}

func readLBState(t *testing.T, path string) lbState {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lb state: %v", err)
	}
	var state lbState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("lb state is not valid JSON: %v\n%s", err, raw)
	}
	return state
}

func webService(backends ...string) Service {
	return Service{
		Project: "shop", Service: "web", VIP: "10.201.0.1",
		Ports:    []ServicePort{{Name: "http", Port: 8080, TargetPort: 8080}},
		Backends: backends,
	}
}

func TestSyncServicesWritesServiceAndEndpointSlice(t *testing.T) {
	c, path := testLBWriter(t)

	if err := c.SyncServices(t.Context(), []Service{webService("10.200.1.5", "10.200.1.6")}); err != nil {
		t.Fatalf("SyncServices: %v", err)
	}
	state := readLBState(t, path)

	if len(state.Services) != 1 || len(state.Endpoints) != 1 {
		t.Fatalf("state = %d services, %d slices; want 1 and 1", len(state.Services), len(state.Endpoints))
	}
	svc := state.Services[0]
	if svc.Metadata.Name != "web" || svc.Metadata.Namespace != "shop" {
		t.Errorf("service identity = %s/%s", svc.Metadata.Namespace, svc.Metadata.Name)
	}
	if svc.Spec.Type != serviceTypeClusterIP || svc.Spec.ClusterIP != "10.201.0.1" {
		t.Errorf("service spec = %+v", svc.Spec)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Protocol != protocolTCP {
		t.Errorf("ports = %+v, want one TCP port", svc.Spec.Ports)
	}

	slice := state.Endpoints[0]
	// Without this label the slice belongs to nothing and the frontend has no
	// backends — the failure is a service that exists and refuses every connection.
	if got := slice.Metadata.Labels[serviceNameLabel]; got != "web" {
		t.Errorf("%s = %q, want web", serviceNameLabel, got)
	}
	if slice.AddressType != addressTypeIPv4 {
		t.Errorf("addressType = %q", slice.AddressType)
	}
	if len(slice.Endpoints) != 2 {
		t.Fatalf("backends = %d, want 2", len(slice.Endpoints))
	}
	for _, e := range slice.Endpoints {
		if !e.Conditions.Ready || !e.Conditions.Serving {
			t.Errorf("backend %v is not marked ready and serving", e.Addresses)
		}
	}
}

// A full rewrite is the batching primitive Cilium offers here: many backends
// changing across many services is one write and one settle window.
func TestSyncServicesBatchesEverythingIntoOneFile(t *testing.T) {
	c, path := testLBWriter(t)

	api := webService("10.200.1.9")
	api.Service = "api"
	api.VIP = "10.201.0.2"

	if err := c.SyncServices(t.Context(), []Service{webService("10.200.1.5"), api}); err != nil {
		t.Fatalf("SyncServices: %v", err)
	}
	state := readLBState(t, path)
	if len(state.Services) != 2 || len(state.Endpoints) != 2 {
		t.Fatalf("want both services in one file, got %d/%d", len(state.Services), len(state.Endpoints))
	}
}

// Rewriting an unchanged file costs a datapath settle window for nothing, and
// map iteration order alone would otherwise trigger it on every pass.
func TestSyncServicesIsIdempotent(t *testing.T) {
	c, path := testLBWriter(t)
	services := []Service{webService("10.200.1.6", "10.200.1.5")}

	if err := c.SyncServices(t.Context(), services); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	backdated := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, backdated, backdated); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Same services, backends listed in a different order.
	reordered := []Service{webService("10.200.1.5", "10.200.1.6")}
	if err := c.SyncServices(t.Context(), reordered); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.ModTime().Equal(backdated) {
		t.Error("reordering the same backends rewrote the state file")
	}
}

func TestSyncServicesRemovesDeletedServices(t *testing.T) {
	c, path := testLBWriter(t)
	if err := c.SyncServices(t.Context(), []Service{webService("10.200.1.5")}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := c.SyncServices(t.Context(), nil); err != nil {
		t.Fatalf("resync: %v", err)
	}

	state := readLBState(t, path)
	if len(state.Services) != 0 || len(state.Endpoints) != 0 {
		t.Fatalf("state = %+v, want empty", state)
	}
	// Empty must marshal as [] rather than null: the agent reads a document,
	// not an absence.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), "null") {
		t.Errorf("empty state encoded nulls:\n%s", raw)
	}
}

// A service with zero healthy backends keeps its frontend but advertises
// nothing. Dropping the frontend entirely would make the name stop resolving
// mid-outage, which turns a 503 into a DNS failure and confuses every client.
func TestSyncServicesKeepsFrontendWithNoBackends(t *testing.T) {
	c, path := testLBWriter(t)
	if err := c.SyncServices(t.Context(), []Service{webService()}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	state := readLBState(t, path)
	if len(state.Services) != 1 {
		t.Fatalf("frontend disappeared with no backends: %+v", state)
	}
	if len(state.Endpoints) != 1 || len(state.Endpoints[0].Endpoints) != 0 {
		t.Errorf("want an empty slice, got %+v", state.Endpoints)
	}
}

func TestSyncServicesSkipsPortlessServices(t *testing.T) {
	c, path := testLBWriter(t)
	worker := Service{Project: "shop", Service: "worker"}

	if err := c.SyncServices(t.Context(), []Service{worker}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if state := readLBState(t, path); len(state.Services) != 0 {
		t.Fatalf("a service with no ports got a frontend: %+v", state.Services)
	}
}

func TestServiceValidation(t *testing.T) {
	tests := []struct {
		name string
		svc  Service
		want string
	}{
		{name: "valid", svc: webService("10.200.1.5")},
		{
			name: "no frontend address",
			svc:  Service{Project: "shop", Service: "web", Ports: []ServicePort{{Name: "http", Port: 80}}},
			want: "no valid frontend",
		},
		{
			name: "backend that is not an address",
			svc:  webService("not-an-ip"),
			want: "invalid backend",
		},
		{
			name: "unnamed port",
			svc: Service{Project: "shop", Service: "web", VIP: "10.201.0.1",
				Ports: []ServicePort{{Port: 80}}},
			want: "unnamed port",
		},
		{
			name: "duplicate port name",
			svc: Service{Project: "shop", Service: "web", VIP: "10.201.0.1",
				Ports: []ServicePort{{Name: "http", Port: 80}, {Name: "http", Port: 8080}}},
			want: "twice",
		},
		{
			name: "port out of range",
			svc: Service{Project: "shop", Service: "web", VIP: "10.201.0.1",
				Ports: []ServicePort{{Name: "http", Port: 70000}}},
			want: "out of range",
		},
		{
			name: "unsupported protocol",
			svc: Service{Project: "shop", Service: "web", VIP: "10.201.0.1",
				Ports: []ServicePort{{Name: "http", Port: 80, Protocol: "SCTP"}}},
			want: "want TCP or UDP",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.svc.validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("validate = %v, want nil", err)
			case tc.want == "":
			case err == nil:
				t.Fatalf("validate = nil, want an error mentioning %q", tc.want)
			case !strings.Contains(err.Error(), tc.want):
				t.Fatalf("validate = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// A rejected service must not leave a partial file behind — the agent would
// program whatever it found.
func TestSyncServicesWritesNothingWhenValidationFails(t *testing.T) {
	c, path := testLBWriter(t)

	err := c.SyncServices(t.Context(), []Service{webService("10.200.1.5"), {
		Project: "shop", Service: "broken", VIP: "not-an-ip",
		Ports: []ServicePort{{Name: "http", Port: 80}},
	}})
	if err == nil {
		t.Fatal("SyncServices = nil, want an error")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a rejected sync still wrote the state file")
	}
}

func TestSyncServicesLeavesNoVisibleTempFile(t *testing.T) {
	c, path := testLBWriter(t)
	if err := c.SyncServices(t.Context(), []Service{webService("10.200.1.5")}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("unexpected file left in the state directory: %q", e.Name())
		}
	}
}
