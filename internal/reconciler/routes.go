package reconciler

import (
	"context"
	"reflect"
	"slices"
	"strings"

	"github.com/m18h/kanea/internal/edge"
)

// syncEdgeRoutes publishes the route table kanea-edge serves from.
//
// The edge is a separate process and cannot read the Store — bbolt locks the
// whole file, so a second opener blocks until kanead exits. What it gets
// instead is this projection, written whenever the routes change (PRD §5.2.6).
//
// Only services with a frontend appear. A route's upstream is the service VIP,
// not an alloc address: the eBPF LB does the balancing, so scaling a service
// from one alloc to ten changes nothing here.
func (r *Reconciler) syncEdgeRoutes(ctx context.Context, w World, vips map[string]string) {
	if r.edgeSnapshot == "" {
		return
	}

	routes := r.buildRoutes(w, vips)
	if r.routesArePublished(routes) {
		// A steady-state pass must not rewrite the file. The edge polls it, and
		// republishing identical content every interval would turn every
		// reconcile into a log line about a reload that changed nothing.
		return
	}

	snap := edge.Snapshot{Routes: routes}
	if index, err := r.store.Index(ctx); err != nil {
		// The index is diagnostic, not load-bearing: publish without it rather
		// than leave the edge on a stale table because a read failed.
		r.log.Debug("cannot read store index for the edge snapshot", "error", err)
	} else {
		snap.Index = index
	}

	if err := edge.Publish(r.edgeSnapshot, snap); err != nil {
		// Not fatal to the pass. A stale route table keeps serving the traffic
		// it was already serving, which is strictly better than failing
		// convergence over it.
		r.log.Error("cannot publish edge routes", "path", r.edgeSnapshot, "error", err)
		return
	}
	r.log.Info("edge routes published",
		"path", r.edgeSnapshot, "routes", len(routes), "index", snap.Index)
}

// routesArePublished reports whether the file already holds this table.
//
// The comparison is against the *file*, not against what this process last
// wrote. Remembering would make kanead unable to repair its own output: a
// snapshot deleted on a reboot, truncated by a full disk, or hand-edited by an
// operator would never be rewritten, because nothing about desired state
// changed — and the edge would come back to an empty table and 404 the whole
// node. The snapshot is derived state, so it is rebuilt rather than remembered
// (constraint #9), at the cost of one small read per pass.
func (r *Reconciler) routesArePublished(routes []edge.Route) bool {
	published, err := edge.Load(r.edgeSnapshot)
	if err != nil {
		// Missing, unreadable or invalid all mean the same thing here: whatever
		// is on disk is not what the edge should be serving.
		return false
	}
	return routesEqual(routes, published.Routes)
}

// buildRoutes turns desired state into the edge's view of it.
func (r *Reconciler) buildRoutes(w World, vips map[string]string) []edge.Route {
	routes := make([]edge.Route, 0, len(w.Desired))
	claimed := map[string]string{}

	for _, d := range sortedDesired(w.Desired) {
		if d.Expose == nil {
			continue
		}
		vip := vips[d.Project+"/"+d.Service]
		if vip == "" {
			// No frontend yet — the service has no ports, or the LB has not
			// been programmed. Publishing a route with no upstream would be a
			// 502 generator.
			r.log.Debug("exposed service has no frontend yet",
				"service", d.Project+"/"+d.Service)
			continue
		}

		domains := r.domainsFor(d)
		if len(domains) == 0 {
			r.log.Warn("exposed service has no domain",
				"service", d.Project+"/"+d.Service,
				"detail", "declare expose.domains, or set the server's base domain")
			continue
		}

		// R16 rejects a collision at plan time, but plan sees one applied set
		// and this sees all of them — two projects applied separately can still
		// claim one host. First writer wins in a stable order, so the outcome
		// does not depend on map iteration, and the loser is named in the log
		// rather than silently dropped.
		kept := make([]string, 0, len(domains))
		for _, domain := range domains {
			if owner, taken := claimed[domain]; taken {
				r.log.Error("domain claimed by two services; ignoring the second",
					"domain", domain, "owner", owner, "ignored", d.Project+"/"+d.Service)
				continue
			}
			claimed[domain] = d.Project + "/" + d.Service
			kept = append(kept, domain)
		}
		if len(kept) == 0 {
			continue
		}

		routes = append(routes, edge.Route{
			Project:       d.Project,
			Service:       d.Service,
			Domains:       kept,
			Upstream:      vip,
			Port:          d.Expose.Port,
			IPRestriction: d.Expose.IPRestriction,
			RateLimit:     d.Expose.RateLimit,
			Headers:       d.Expose.Headers,
		})
	}
	return routes
}


// domainsFor resolves a service's hostnames against this agent's base domain.
func (r *Reconciler) domainsFor(d Desired) []string {
	return EdgeDomains(d, r.baseDomain)
}

// ResolveTLSMode resolves where this service's certificate comes from
// (PRD §6.2 R20). Named for the precedence it applies, not for the field it
// reads, which it shares a name with.
//
// Explicit beats the pre-v1.33 bool beats the node's default. The node default
// is applied here rather than at apply time so that changing --tls-default
// takes effect on the next pass instead of on the next `kanea run` of every
// service — and so that a stored record says what the *spec* asked for and
// nothing more.
//
// A service with no expose block gets "": there is nothing to serve.
func (e *Expose) ResolveTLSMode(nodeDefault string) string {
	switch {
	case e == nil:
		return ""
	case e.TLSMode != "":
		return e.TLSMode
	case e.LetsEncrypt:
		// A record written before v1.33. It meant ACME then and it means ACME
		// now, which is what makes the new field need no migration.
		return "acme"
	default:
		return nodeDefault
	}
}
// EdgeDomains resolves the hostnames a service answers on, generating the
// auto-FQDN when the spec declared none (PRD §7.2).
//
// Exported because certificate issuance has to ask the same question the route
// table does. Answering it twice, differently, would mean requesting a
// certificate for a name the edge does not route — an issuance guaranteed to
// fail validation, and to keep failing.
func EdgeDomains(d Desired, baseDomain string) []string {
	if d.Expose == nil {
		return nil
	}
	if len(d.Expose.Domains) > 0 {
		out := make([]string, 0, len(d.Expose.Domains))
		for _, domain := range d.Expose.Domains {
			if canonical := canonicalDomain(domain); canonical != "" {
				out = append(out, canonical)
			}
		}
		return out
	}
	baseDomain = strings.Trim(strings.TrimSpace(baseDomain), ".")
	if baseDomain == "" {
		return nil
	}
	return []string{canonicalDomain(d.Service + "." + d.Project + "." + baseDomain)}
}

// canonicalDomain matches the form the edge's route table is keyed by.
func canonicalDomain(d string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
}

// sortedDesired orders services so route building is deterministic — which is
// what makes "first writer wins" a rule rather than a coin flip.
func sortedDesired(desired []Desired) []Desired {
	out := make([]Desired, len(desired))
	copy(out, desired)
	slices.SortFunc(out, func(a, b Desired) int {
		return strings.Compare(a.Project+"/"+a.Service, b.Project+"/"+b.Service)
	})
	return out
}

// routesEqual reports whether two route tables are the same.
func routesEqual(a, b []edge.Route) bool {
	return slices.EqualFunc(a, b, func(x, y edge.Route) bool {
		return x.Project == y.Project && x.Service == y.Service &&
			x.Upstream == y.Upstream && x.Port == y.Port &&
			slices.Equal(x.Domains, y.Domains) &&
			reflect.DeepEqual(x.IPRestriction, y.IPRestriction) &&
			reflect.DeepEqual(x.RateLimit, y.RateLimit) &&
			reflect.DeepEqual(x.Headers, y.Headers)
	})
}
