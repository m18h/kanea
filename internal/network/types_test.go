package network

import (
	"fmt"
	"strings"
	"testing"
)

// webService is the canonical fixture: one service, one http port, and a
// backend per given address.
func webService(backendIPs ...string) Service {
	backends := make([]Backend, 0, len(backendIPs))
	for i, ip := range backendIPs {
		backends = append(backends, Backend{AllocID: fmt.Sprintf("shop-web-%d", i), IPv4: ip})
	}
	return Service{
		Project: "shop", Service: "web", VIP: "10.201.0.1",
		Ports:    []ServicePort{{Name: "http", Port: 8080, TargetPort: 8080}},
		Backends: backends,
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
			name: "backend with no alloc id",
			svc: Service{Project: "shop", Service: "web", VIP: "10.201.0.1",
				Ports:    []ServicePort{{Name: "http", Port: 8080}},
				Backends: []Backend{{IPv4: "10.200.1.5"}}},
			want: "no alloc id",
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

func TestValidateLabelValue(t *testing.T) {
	for _, bad := range []string{"", "a=b", "a:b", "a b", "a,b"} {
		if err := validateLabelValue("project", bad); err == nil {
			t.Errorf("validateLabelValue(%q) = nil, want error", bad)
		}
	}
	if err := validateLabelValue("project", "shop-eu"); err != nil {
		t.Errorf("validateLabelValue(shop-eu) = %v, want nil", err)
	}
}
