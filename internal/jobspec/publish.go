package jobspec

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
)

// MaxPort is the highest number a TCP port can be.
const MaxPort = 65535

// ReservedPorts are node ports a spec may never claim (R22).
//
// These four are constants of the platform rather than configuration: 80 and
// 443 are what kanea-edge serves north-south traffic on, 8600 is the API's
// default listener (api.DefaultListenAddr) and 8601 is the edge's status
// endpoint (edge.DefaultStatusAddr). They are literals here because
// internal/api imports this package and cannot be imported back; the test that
// keeps them honest lives where both are visible.
//
// This is not the whole of R22. Which *other* ports may be claimed is the
// node's decision, enforced at the API — a spec that could claim 22 on this
// node's address would be deciding something that belongs to whoever owns the
// machine, and a plan-time list could not know what the operator allowed.
var ReservedPorts = map[int]string{
	80:   "kanea-edge serves HTTP here",
	443:  "kanea-edge serves HTTPS here",
	8600: "the Kanea API listens here by default",
	8601: "the kanea-edge status endpoint listens here by default",
}

// validatePublish enforces R21 for one service.
//
// Everything is a plan error rather than a runtime one for the reason R16
// gives: the edge is holding public traffic when it finds out, and a control
// that silently fails to apply is worse than one nobody wrote.
func validatePublish(svc *Service) hcl.Diagnostics {
	if svc.Network == nil || len(svc.Network.Publish) == 0 {
		return nil
	}
	var diags hcl.Diagnostics
	byHost := map[int]*Publish{}

	for _, p := range svc.Network.Publish {
		where := fmt.Sprintf("Service %q: publish %q", svc.Name, p.Port)
		rng := p.DefRange

		diags = append(diags, validatePublishPort(svc, p, where, rng)...)
		diags = append(diags, validatePublishHost(p, where, rng)...)
		mode, modeDiags := validatePublishMode(p, where, rng)
		diags = append(diags, modeDiags...)

		if prev, dup := byHost[p.Host]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Port published twice",
				Detail: fmt.Sprintf("%s and publish %q both bind node port %d. "+
					"One socket cannot serve two upstreams, and which one won would be "+
					"decided by whichever goroutine bound first.", where, prev.Port, p.Host),
				Subject: rng.Ptr(),
			})
		} else {
			byHost[p.Host] = p
		}

		// The middleware the mode can actually honour. ip_restriction works on
		// both — it is checked at accept time, before a byte is forwarded, and
		// on a tcp listener it is the *only* mitigation there is, because the
		// upstream sees the edge's address rather than the client's.
		diags = append(diags, validateIPRestriction(where, p.IPRestriction)...)
		if mode == PublishTCP {
			continue
		}
		diags = append(diags, validateRateLimit(where, p.RateLimit)...)
		diags = append(diags, validateExposeHeaders(where, p.Headers)...)
	}
	return diags
}

// validatePublishPort checks that the label names a port the service declared.
func validatePublishPort(svc *Service, p *Publish, where string, rng hcl.Range) hcl.Diagnostics {
	for _, declared := range svc.Network.Ports {
		if declared.Name == p.Port {
			return nil
		}
	}
	names := make([]string, 0, len(svc.Network.Ports))
	for _, declared := range svc.Network.Ports {
		names = append(names, declared.Name)
	}
	detail := fmt.Sprintf("%s forwards to a port named %q, which this service does not declare. ",
		where, p.Port)
	if len(names) == 0 {
		detail += "It declares no network { port … } at all, so there is nothing to forward to."
	} else {
		detail += fmt.Sprintf("It declares %s.", joinPortNames(names))
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Published port names no declared port",
		Detail:   detail,
		Subject:  rng.Ptr(),
	}}
}

// validatePublishHost checks the node port itself (R21, R22).
func validatePublishHost(p *Publish, where string, rng hcl.Range) hcl.Diagnostics {
	if p.Host < 1 || p.Host > MaxPort {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid published port",
			Detail: fmt.Sprintf("%s sets host = %d; a TCP port is 1 to %d.",
				where, p.Host, MaxPort),
			Subject: rng.Ptr(),
		}}
	}
	if reason, reserved := ReservedPorts[p.Host]; reserved {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Reserved port",
			Detail: fmt.Sprintf("%s binds node port %d, which Kanea holds: %s. "+
				"To serve this service on a name instead, write an expose block.",
				where, p.Host, reason),
			Subject: rng.Ptr(),
		}}
	}
	return nil
}

// validatePublishMode checks the listener kind and the settings only one of
// them can honour.
//
// A control the edge would silently drop is refused rather than ignored. That
// is R16's rule read the other way round: an ingress control that fails open is
// worse than one that is absent, so a rate_limit on a listener that cannot
// count requests has to be a plan error.
func validatePublishMode(p *Publish, where string, rng hcl.Range) (string, hcl.Diagnostics) {
	mode := p.ResolvedMode()
	if mode != PublishHTTP && mode != PublishTCP {
		return "", hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Unknown publish mode",
			Detail: fmt.Sprintf("%s sets mode = %q; it is %q or %q. "+
				"%q reads requests and keeps the whole middleware chain; %q relays bytes "+
				"and can only restrict who connects.",
				where, p.Mode, PublishHTTP, PublishTCP, PublishHTTP, PublishTCP),
			Subject: rng.Ptr(),
		}}
	}

	var diags hcl.Diagnostics
	if mode == PublishTCP {
		for _, unsupported := range []struct {
			name    string
			present bool
			why     string
		}{
			{"rate_limit", p.RateLimit != nil,
				"a rate limit counts requests, and a byte stream has none"},
			{"headers", p.Headers != nil,
				"there are no headers in a stream the edge does not parse"},
		} {
			if !unsupported.present {
				continue
			}
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Middleware a tcp listener cannot honour",
				Detail: fmt.Sprintf("%s is mode = %q and declares %s: %s. "+
					"Silently dropping it would leave the spec claiming a control that is "+
					"not being applied.", where, PublishTCP, unsupported.name, unsupported.why),
				Subject: rng.Ptr(),
			})
		}
	}
	if mode == PublishHTTP && p.MaxConns != 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "max_conns on an http listener",
			Detail: fmt.Sprintf("%s is mode = %q and sets max_conns. Connections are pooled "+
				"and reused by HTTP clients, so a connection ceiling there does not bound "+
				"work — the edge's own limits do. It is a tcp setting.",
				where, PublishHTTP),
			Subject: rng.Ptr(),
		})
	}
	if p.MaxConns < 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid connection limit",
			Detail:   fmt.Sprintf("%s sets max_conns = %d; it must not be negative.", where, p.MaxConns),
			Subject:  rng.Ptr(),
		})
	}
	return mode, diags
}

// validatePublishedPorts checks the whole applied set for a node port claimed
// twice (R21).
//
// A sibling of validateExposedDomains and called beside it, for the same
// reason: each spec is individually fine and the collision is between them. A
// node has one port 8096.
func validatePublishedPorts(spec *Spec) hcl.Diagnostics {
	type claim struct {
		service string
		rng     hcl.Range
	}
	claimed := map[int]claim{}
	// Sorted, so two services colliding produce the same message whichever
	// order the files were read in.
	services := make([]*Service, len(spec.Services))
	copy(services, spec.Services)
	sort.Slice(services, func(i, j int) bool {
		if services[i].Project != services[j].Project {
			return services[i].Project < services[j].Project
		}
		return services[i].Name < services[j].Name
	})

	var diags hcl.Diagnostics
	for _, svc := range services {
		if svc.Network == nil {
			continue
		}
		for _, p := range svc.Network.Publish {
			if p.Host < 1 || p.Host > MaxPort {
				continue // already reported, and not a real claim
			}
			name := svc.Project + "/" + svc.Name
			prev, taken := claimed[p.Host]
			if !taken {
				claimed[p.Host] = claim{service: name, rng: p.DefRange}
				continue
			}
			if prev.service == name {
				continue // reported per service already
			}
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Node port claimed twice",
				Detail: fmt.Sprintf("Services %q and %q both publish node port %d. "+
					"A node has one of each port, so only one of them could ever bind it.",
					prev.service, name, p.Host),
				Subject: p.DefRange.Ptr(),
			})
		}
	}
	return diags
}

// joinPortNames renders a port name list for a diagnostic.
func joinPortNames(names []string) string {
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	return joinWithAnd(quoteAll(sorted))
}

// joinWithAnd renders a short list the way a sentence would.
func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		out := ""
		for i, item := range items[:len(items)-1] {
			if i > 0 {
				out += ", "
			}
			out += item
		}
		return out + " and " + items[len(items)-1]
	}
}
