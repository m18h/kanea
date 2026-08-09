package api_test

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
)

func TestParsePortPolicy(t *testing.T) {
	tests := []struct {
		name, spec string
		allowed    []int
		refused    []int
		wantErr    string
	}{
		{
			name: "the default is unprivileged ports",
			spec: "", allowed: []int{1024, 8096, 65535}, refused: []int{22, 25, 53, 1023},
		},
		{
			name: "a single port",
			spec: "25565", allowed: []int{25565}, refused: []int{25564, 25566},
		},
		{
			name: "several spans",
			spec: "8000-9000,25565", allowed: []int{8000, 9000, 25565}, refused: []int{7999, 9001},
		},
		{
			// Privileged ports are the node's to give away, and an operator who
			// writes the range is doing exactly that.
			name: "an operator may open a privileged port",
			spec: "53,1024-65535", allowed: []int{53, 1024}, refused: []int{22},
		},
		{
			name: "off refuses everything",
			spec: "off", refused: []int{1024, 8096, 25565},
		},
		{name: "reversed", spec: "9000-8000", wantErr: "reversed"},
		{name: "out of range", spec: "0-70000", wantErr: "outside"},
		{name: "not a number", spec: "http", wantErr: "not a port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := api.ParsePortPolicy(tc.spec)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to name %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortPolicy(%q): %v", tc.spec, err)
			}
			for _, port := range tc.allowed {
				if !policy.Allows(port) {
					t.Errorf("port %d refused by %q", port, tc.spec)
				}
			}
			for _, port := range tc.refused {
				if policy.Allows(port) {
					t.Errorf("port %d allowed by %q", port, tc.spec)
				}
			}
		})
	}
}

// Kanea's own four are refused whatever the range says: an operator who writes
// 1-65535 has not agreed to let a spec take the port their API listens on.
func TestPortPolicyAlwaysRefusesReservedPorts(t *testing.T) {
	policy, err := api.ParsePortPolicy("1-65535")
	if err != nil {
		t.Fatalf("ParsePortPolicy: %v", err)
	}
	for port := range jobspec.ReservedPorts {
		if policy.Allows(port) {
			t.Errorf("port %d is reserved and was allowed", port)
		}
	}
}

// The zero value is publishing turned off, not publishing wide open: a server
// built without a policy must refuse rather than permit.
func TestZeroPortPolicyPublishesNothing(t *testing.T) {
	var policy api.PortPolicy
	if policy.Enabled() {
		t.Error("the zero policy reports itself enabled")
	}
	err := policy.Check(reconciler.Desired{
		Project: "media", Service: "jellyfin",
		Publish: []reconciler.PublishedPort{{Port: "http", Host: 8096}},
	})
	if err == nil {
		t.Fatal("the zero policy permitted a published port")
	}
	// And a service that publishes nothing is unaffected, so an existing
	// deployment is not refused by a field nobody set.
	if err := policy.Check(reconciler.Desired{Project: "shop", Service: "web"}); err != nil {
		t.Errorf("a service with no published ports was refused: %v", err)
	}
}

// The refusal has to say why. "Port 22 is not permitted" reads as a bug in
// Kanea; the actual reason reads as a decision somebody made.
func TestPortPolicyCheckNamesTheReason(t *testing.T) {
	policy, err := api.ParsePortPolicy(api.DefaultPublishRange)
	if err != nil {
		t.Fatalf("ParsePortPolicy: %v", err)
	}
	d := reconciler.Desired{
		Project: "shop", Service: "ssh",
		Publish: []reconciler.PublishedPort{{Port: "ssh", Host: 22}},
	}
	got := policy.Check(d)
	if got == nil {
		t.Fatal("port 22 was permitted")
	}
	if !strings.Contains(got.Error(), "belongs to whoever owns the machine") {
		t.Errorf("error = %v, want it to name the reason", got)
	}

	reserved := reconciler.Desired{
		Project: "shop", Service: "web",
		Publish: []reconciler.PublishedPort{{Port: "http", Host: 443}},
	}
	if got := policy.Check(reserved); got == nil || !strings.Contains(got.Error(), "kanea-edge") {
		t.Errorf("error = %v, want it to name the listener in the way", got)
	}
}

// The reserved set is a copy of numbers that live elsewhere, because
// internal/api imports internal/jobspec and cannot be imported back. This is
// where both are visible, so this is where they are kept honest.
func TestReservedPortsMatchTheRealListeners(t *testing.T) {
	for _, addr := range []struct {
		what, value string
	}{
		{"the API", api.DefaultListenAddr},
		{"the edge status endpoint", edge.DefaultStatusAddr},
		{"the edge's HTTP listener", edge.DefaultHTTPAddr},
		{"the edge's HTTPS listener", edge.DefaultHTTPSAddr},
	} {
		port := portOf(t, addr.value)
		if _, reserved := jobspec.ReservedPorts[port]; !reserved {
			t.Errorf("%s listens on %d, which no spec is stopped from claiming", addr.what, port)
		}
	}
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, port, found := strings.Cut(addr, ":")
	if !found {
		t.Fatalf("no port in %q", addr)
	}
	n := 0
	for _, r := range port {
		if r < '0' || r > '9' {
			t.Fatalf("port %q in %q is not a number", port, addr)
		}
		n = n*10 + int(r-'0')
	}
	return n
}
