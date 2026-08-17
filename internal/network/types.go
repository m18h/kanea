package network

import (
	"fmt"
	"net"
	"strings"
)

// This file is the driver-neutral vocabulary: the types the reconciler speaks
// to whatever network driver is behind its interfaces, and the validators they
// share. Nothing here knows how a service is programmed: only what one is.

// Port protocols. A service port is TCP unless it says otherwise; the datapath
// balances TCP only (PRD §5.2.5), and the jobspec has no field to declare UDP,
// so a UDP value can only arrive from a hand-built record and is rejected.
const (
	protocolTCP = "TCP"
	protocolUDP = "UDP"
)

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
	// it has to survive a restart that rebuilds everything else.
	VIP string
	// VIP6 is the dual-stack twin (v1.41), or empty on a v4-only node. It is
	// its own durable allocation (lb/vip6/…), never derived from VIP.
	VIP6 string
	// Ports the frontend listens on.
	Ports []ServicePort
	// Backends are the allocs that should receive traffic. Only allocs that are
	// actually running belong here: an alloc that is created, backing off or
	// mid-restart is not a backend, and listing it would send real requests
	// into a black hole.
	//
	// The alloc id travels with the address because two consumers need
	// different halves of it: load balancing wants the addresses, and DNS wants
	// to publish a per-alloc name for each one (PRD §7.1).
	Backends []Backend
}

// Backend is one alloc serving a service.
type Backend struct {
	AllocID string
	IPv4    string
	// IPv6 is empty on a v4-only node, and on a v4-only attachment adopted
	// across the dual-stack upgrade, which a v6 frontend then omits (v1.41).
	IPv6 string
}

// validate rejects a service no driver could program.
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
	if s.VIP6 != "" && !validIP(s.VIP6) {
		return fmt.Errorf("network: service %s/%s has an invalid v6 frontend address (%q)",
			s.Project, s.Service, s.VIP6)
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
	for _, b := range s.Backends {
		if !validIP(b.IPv4) {
			return fmt.Errorf("network: service %s/%s has an invalid backend address %q",
				s.Project, s.Service, b.IPv4)
		}
		if b.IPv6 != "" && !validIP(b.IPv6) {
			return fmt.Errorf("network: service %s/%s has an invalid v6 backend address %q",
				s.Project, s.Service, b.IPv6)
		}
		if b.AllocID == "" {
			return fmt.Errorf("network: service %s/%s has a backend with no alloc id", s.Project, s.Service)
		}
	}
	return nil
}

// Validate rejects a service no driver could program. It is the exported face
// of validate, so a driver outside this package (internal/datapath) checks the
// same rules the in-package validator does instead of growing a second one.
func (s Service) Validate() error { return s.validate() }

// ServiceRef identifies the service an attachment belongs to.
type ServiceRef struct {
	Project string
	Service string
}

// String renders the canonical "project/service" form used in logs and keys.
func (r ServiceRef) String() string { return r.Project + "/" + r.Service }

// ProjectPolicy is everything a driver needs to enforce for one project.
type ProjectPolicy struct {
	Project string
	// Services carries only the services that declare an ingress allowlist;
	// the rest are covered by the project isolation policy alone.
	Services []ServicePolicy
}

// ServicePolicy is one service's explicit ingress allowlist (PRD §6.2 R14).
type ServicePolicy struct {
	Service string
	// AllowFrom names the peers permitted to reach this service.
	AllowFrom []ServiceRef
}

// Attachment is one alloc's network attachment as Kanea sees it.
type Attachment struct {
	// AllocID is the alloc the attachment belongs to.
	AllocID string
	// EndpointID is the driver's own endpoint id, where the driver has one.
	EndpointID int64
	// IPv4 is the address the datapath assigned.
	IPv4 string
	// IPv6 is the dual-stack twin (v1.41), or empty on a v4-only node, and
	// on a v4-only attachment adopted across the dual-stack upgrade.
	IPv6 string
	// Service is the project/service the attachment's identity says it serves.
	Service ServiceRef
	// Ready reports a resolved identity fit to receive traffic.
	Ready bool
}

// validateLabelValue rejects values that would corrupt an identity. Project
// and service names are DNS-1123 labels by the time they reach here (jobspec
// R1 at parse, the apply seam's validateDesired for records that never saw
// the parser), so this is a last-line assertion rather than the real gate.
// The "/" refusal is load-bearing beyond identity text: the same names
// compose into filesystem paths (resolv.conf, volume directories, log files)
// that kanead writes as root.
func validateLabelValue(kind, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("network: empty %s name", kind)
	case strings.ContainsAny(value, "/=:;, \t\n"):
		return fmt.Errorf("network: %s name %q contains a character that is not valid in a label", kind, value)
	}
	return nil
}

// validIP reports whether s parses as an IP address: used to refuse an
// attachment whose address has not been filled in yet.
func validIP(s string) bool {
	return net.ParseIP(s) != nil
}
