package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultLBStateFile is the agent's --lb-state-file (PRD §5.2.5).
const DefaultLBStateFile = "/var/run/cilium/lb-state.json"

// ServicePort is one named port on a service frontend.
type ServicePort struct {
	// Name is the port's name from the job spec, e.g. "http".
	Name string
	// Port is the port on the frontend VIP.
	Port int
	// TargetPort is the port inside the alloc.
	TargetPort int
	// Protocol is TCP or UDP; empty means TCP.
	Protocol string
}

// Service is one load-balanced service: a stable frontend and the set of
// backends currently fit to receive traffic.
type Service struct {
	Project string
	Service string
	// VIP is the frontend address. It is allocated and remembered by the
	// caller, not by this package: DNS answers with it and clients cache it, so
	// it has to survive an agent restart that rebuilds everything else.
	VIP string
	// Ports the frontend listens on.
	Ports []ServicePort
	// Backends are the alloc IPs that should receive traffic. Only allocs that
	// are actually running belong here — an alloc that is created, backing off
	// or mid-restart is not a backend, and listing it would send real requests
	// into a black hole.
	Backends []string
}

// lbState is the file the agent watches.
//
// The objects are Kubernetes-*shaped* — Service and EndpointSlice — because
// that is the schema Cilium's non-k8s data source reads. It is schema only:
// there is no API server, no CRDs and no client-go anywhere near this, which
// is what keeps it compatible with constraint #10.
type lbState struct {
	Services  []lbService       `json:"services"`
	Endpoints []lbEndpointSlice `json:"endpoints"`
}

type objectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type lbService struct {
	Metadata objectMeta    `json:"metadata"`
	Spec     lbServiceSpec `json:"spec"`
}

type lbServiceSpec struct {
	Type      string   `json:"type"`
	ClusterIP string   `json:"clusterIP"`
	Ports     []lbPort `json:"ports"`
}

type lbPort struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	TargetPort int    `json:"targetPort"`
}

type lbEndpointSlice struct {
	Metadata    objectMeta      `json:"metadata"`
	AddressType string          `json:"addressType"`
	Endpoints   []endpointEntry `json:"endpoints"`
	Ports       []endpointPort  `json:"ports"`
}

type endpointEntry struct {
	Addresses  []string           `json:"addresses"`
	Conditions endpointConditions `json:"conditions"`
}

type endpointConditions struct {
	Ready       bool `json:"ready"`
	Serving     bool `json:"serving"`
	Terminating bool `json:"terminating"`
}

type endpointPort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// LB constants.
const (
	serviceTypeClusterIP = "ClusterIP"
	addressTypeIPv4      = "IPv4"
	protocolTCP          = "TCP"
	protocolUDP          = "UDP"
	// serviceNameLabel is how an EndpointSlice is bound to its Service. Without
	// it the backends belong to nothing and the frontend has no endpoints.
	serviceNameLabel = "kubernetes.io/service-name"
	// endpointSliceSuffix names a service's slice. One slice per service is
	// enough at the scale a single node serves.
	endpointSliceSuffix = "-allocs"
)

// SyncServices rewrites the LB state file so it describes exactly the given
// services.
//
// The whole file is rewritten every time, and that is the design rather than a
// shortcut: a full rewrite *is* the batching primitive Cilium offers here
// (PRD §5.2.5). Twenty backends changing across five services is one write and
// one settle window, not twenty. The agent's --lb-state-file-interval is what
// bounds how long the datapath takes to catch up.
func (c *Cilium) SyncServices(_ context.Context, services []Service) error {
	state, err := buildLBState(services)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode lb state: %w", err)
	}
	body = append(body, '\n')

	changed, err := writeFileIfChanged(c.lbStateFile, body)
	if err != nil {
		return err
	}
	if changed {
		c.log.Info("updated service load balancing",
			"file", c.lbStateFile, "services", len(state.Services), "backends", countBackends(state))
	}
	return nil
}

// buildLBState converts Kanea's view into the agent's schema.
func buildLBState(services []Service) (lbState, error) {
	// Sorted so an unchanged set of services always produces identical bytes —
	// otherwise map iteration order alone would cause a rewrite every pass.
	sorted := make([]Service, len(services))
	copy(sorted, services)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Project != sorted[j].Project {
			return sorted[i].Project < sorted[j].Project
		}
		return sorted[i].Service < sorted[j].Service
	})

	// Non-nil slices: an empty state must marshal as [] rather than null, or
	// the agent sees a malformed document instead of "no services".
	state := lbState{Services: []lbService{}, Endpoints: []lbEndpointSlice{}}

	for _, svc := range sorted {
		if err := svc.validate(); err != nil {
			return lbState{}, err
		}
		if len(svc.Ports) == 0 {
			continue // nothing to load balance
		}

		ports := make([]lbPort, 0, len(svc.Ports))
		slicePorts := make([]endpointPort, 0, len(svc.Ports))
		for _, p := range svc.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = protocolTCP
			}
			target := p.TargetPort
			if target == 0 {
				target = p.Port
			}
			ports = append(ports, lbPort{Name: p.Name, Port: p.Port, Protocol: proto, TargetPort: target})
			slicePorts = append(slicePorts, endpointPort{Name: p.Name, Port: target, Protocol: proto})
		}

		state.Services = append(state.Services, lbService{
			Metadata: objectMeta{Name: svc.Service, Namespace: svc.Project},
			Spec: lbServiceSpec{
				Type:      serviceTypeClusterIP,
				ClusterIP: svc.VIP,
				Ports:     ports,
			},
		})

		backends := make([]string, len(svc.Backends))
		copy(backends, svc.Backends)
		sort.Strings(backends)

		entries := make([]endpointEntry, 0, len(backends))
		for _, ip := range backends {
			entries = append(entries, endpointEntry{
				Addresses:  []string{ip},
				Conditions: endpointConditions{Ready: true, Serving: true},
			})
		}
		state.Endpoints = append(state.Endpoints, lbEndpointSlice{
			Metadata: objectMeta{
				Name:      svc.Service + endpointSliceSuffix,
				Namespace: svc.Project,
				Labels:    map[string]string{serviceNameLabel: svc.Service},
			},
			AddressType: addressTypeIPv4,
			Endpoints:   entries,
			Ports:       slicePorts,
		})
	}
	return state, nil
}

// validate rejects a service the agent could not program.
func (s Service) validate() error {
	if err := validateLabelValue("project", s.Project); err != nil {
		return err
	}
	if err := validateLabelValue("service", s.Service); err != nil {
		return err
	}
	if len(s.Ports) > 0 && !validIP(s.VIP) {
		return fmt.Errorf("network: service %s/%s has no valid frontend address (%q)",
			s.Project, s.Service, s.VIP)
	}
	seen := make(map[string]bool, len(s.Ports))
	for _, p := range s.Ports {
		switch {
		case p.Name == "":
			return fmt.Errorf("network: service %s/%s has an unnamed port", s.Project, s.Service)
		case seen[p.Name]:
			return fmt.Errorf("network: service %s/%s declares port %q twice", s.Project, s.Service, p.Name)
		case p.Port < 1 || p.Port > 65535:
			return fmt.Errorf("network: service %s/%s port %q is out of range (%d)",
				s.Project, s.Service, p.Name, p.Port)
		case p.Protocol != "" && p.Protocol != protocolTCP && p.Protocol != protocolUDP:
			return fmt.Errorf("network: service %s/%s port %q has protocol %q, want TCP or UDP",
				s.Project, s.Service, p.Name, p.Protocol)
		}
		seen[p.Name] = true
	}
	for _, ip := range s.Backends {
		if !validIP(ip) {
			return fmt.Errorf("network: service %s/%s has an invalid backend address %q",
				s.Project, s.Service, ip)
		}
	}
	return nil
}

func countBackends(state lbState) int {
	var n int
	for _, slice := range state.Endpoints {
		n += len(slice.Endpoints)
	}
	return n
}

// writeFileIfChanged swaps a watched file in atomically, skipping the write
// when the content already matches. It reports whether it wrote.
//
// The temp file must not be visible to the watcher: it lives in the same
// directory (rename is only atomic within a filesystem) but carries a leading
// dot and a .tmp suffix, so neither the policy watcher nor the LB watcher will
// try to parse a half-written document.
func writeFileIfChanged(path string, body []byte) (bool, error) {
	if !strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".yaml") {
		// Guard against a caller pointing this at something unexpected: the
		// agent only watches these, and a typo'd path would silently do nothing.
		return false, fmt.Errorf("network: %q is not a watched state file", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("state dir %s: %w", dir, err)
	}

	// #nosec G304 — path comes from configuration, not from a request, and is
	// the same file this function is about to write.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return false, nil
	}

	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return false, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		if rmErr := os.Remove(tmp); rmErr != nil && !os.IsNotExist(rmErr) {
			return false, fmt.Errorf("install %s: %w (and temp file left behind: %w)", path, err, rmErr)
		}
		return false, fmt.Errorf("install %s: %w", path, err)
	}
	return true, nil
}
