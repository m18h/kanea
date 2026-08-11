package reconciler

import (
	"context"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/network"
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
func (r *Reconciler) syncEdgeRoutes(ctx context.Context, w World, vips map[string]string, attachments map[string]network.Attachment) {
	if r.edgeSnapshot == "" {
		return
	}

	routes := r.buildRoutes(w, vips)
	listeners := r.buildListeners(w, vips, attachments)
	functions := r.buildFunctionRoutes(w, vips)
	if r.snapshotIsPublished(routes, listeners, functions) {
		// A steady-state pass must not rewrite the file. The edge polls it, and
		// republishing identical content every interval would turn every
		// reconcile into a log line about a reload that changed nothing.
		return
	}

	snap := edge.Snapshot{Routes: routes, Listeners: listeners, Functions: functions}
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
		"path", r.edgeSnapshot, "routes", len(routes),
		"listeners", len(listeners), "functions", len(functions), "index", snap.Index)
}

// snapshotIsPublished reports whether the file already holds this projection.
//
// It compares *both* halves, and that is the whole reason it is not called
// routesArePublished any more. Adding listeners to the snapshot and not to this
// comparison would publish a listener edit exactly once and never again: a
// steady-state pass would find the routes equal, return early, and the edited
// listener would sit in memory forever. It is the easiest way to ship this
// feature broken, so the signature makes it impossible to forget.
//
// The comparison is against the *file*, not against what this process last
// wrote. Remembering would make kanead unable to repair its own output: a
// snapshot deleted on a reboot, truncated by a full disk, or hand-edited by an
// operator would never be rewritten, because nothing about desired state
// changed — and the edge would come back to an empty table and 404 the whole
// node. The snapshot is derived state, so it is rebuilt rather than remembered
// (constraint #9), at the cost of one small read per pass.
func (r *Reconciler) snapshotIsPublished(routes []edge.Route, listeners []edge.Listener, functions []edge.FunctionRoute) bool {
	published, err := edge.Load(r.edgeSnapshot)
	if err != nil {
		// Missing, unreadable or invalid all mean the same thing here: whatever
		// is on disk is not what the edge should be serving.
		return false
	}
	return routesEqual(routes, published.Routes) &&
		listenersEqual(listeners, published.Listeners) &&
		functionsEqual(functions, published.Functions)
}

// buildRoutes turns desired state into the edge's view of it.
func (r *Reconciler) buildRoutes(w World, vips map[string]string) []edge.Route {
	routes := make([]edge.Route, 0, len(w.Desired))
	claimed := map[string]string{}

	for _, d := range sortedDesired(w.Desired) {
		exposes := d.AllExposes()
		if len(exposes) == 0 {
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

		// One edge.Route per expose block (v1.50): each has its own domains,
		// port, middleware and marker, and the edge has routed a flat list by
		// domain since v1.15 — N routes naming one service are as ordinary as
		// N services.
		for _, e := range exposes {
			domains := EdgeDomainsFor(d, e, r.baseDomain)
			if len(domains) == 0 {
				if d.Function != nil || e != d.Expose {
					// A function with no resolvable name is not stranded: it
					// goes to the functions-port dispatch table (§7.2.3). An
					// extra block with no domains is R16-refused at plan and
					// generates nothing here by construction.
					continue
				}
				r.log.Warn("exposed service has no domain",
					"service", d.Project+"/"+d.Service,
					"detail", "declare expose.domains, or set the server's base domain")
				continue
			}

			// R16 rejects a collision at plan time, but plan sees one applied
			// set and this sees all of them — two projects applied separately
			// can still claim one host. First writer wins in a stable order, so
			// the outcome does not depend on map iteration, and the loser is
			// named in the log rather than silently dropped.
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
				Port:          e.Port,
				IPRestriction: e.IPRestriction,
				RateLimit:     e.RateLimit,
				Headers:       e.Headers,
				// Only the marker (R27): this file is world-readable, and the
				// verifier material travels in the restricted bundle.
				AuthRequired: e.Auth != nil,
				// R28 (v1.41): how the edge dials this upstream.
				Protocol: e.Protocol,
			})
		}
	}
	return routes
}

// buildListeners turns the published ports of desired state into the edge's
// view of them (PRD §7.2.2, R21).
//
// It mirrors buildRoutes: stable order, a service with no VIP is skipped, and a
// collision on a node port is first-writer-wins with the loser named. The
// upstream is the service frontend, so a rolling deploy never flaps a listener
// — a VIP is durable state, and only deleting the service removes it.
//
// udp listeners are the exception on both counts (v1.42): a udp port has no
// frontend to dial, so the listener carries the running backend addresses
// directly, and a service whose only ports are udp legitimately has no VIP. A
// scale event *does* change a udp listener — the projection republishes on
// backend churn, which is why listenersEqual compares the backend list.
func (r *Reconciler) buildListeners(w World, vips map[string]string, attachments map[string]network.Attachment) []edge.Listener {
	var listeners []edge.Listener
	type claimKey struct {
		udp  bool
		host int
	}
	claimed := map[claimKey]string{}

	for _, d := range sortedDesired(w.Desired) {
		if len(d.Publish) == 0 {
			continue
		}
		name := d.Project + "/" + d.Service
		vip := vips[name]
		for _, p := range d.Publish {
			mode := p.Mode
			if mode == "" {
				mode = edge.ListenerHTTP
			}
			if mode != edge.ListenerUDP && vip == "" {
				r.log.Debug("service publishes a port but has no frontend yet", "service", name)
				continue
			}
			upstream := d.portNumber(p.Port)
			if upstream == 0 {
				// The spec validator rejects this, so reaching it means a
				// record written by hand or by an older CLI. Binding a node
				// port that forwards nowhere would be a 502 generator with a
				// listening socket in front of it.
				r.log.Error("published port names a port the service does not declare",
					"service", name, "port", p.Port, "host", p.Host)
				continue
			}
			key := claimKey{udp: mode == edge.ListenerUDP, host: p.Host}
			if owner, taken := claimed[key]; taken {
				r.log.Error("node port claimed by two services; ignoring the second",
					"port", p.Host, "owner", owner, "ignored", name)
				continue
			}
			claimed[key] = name

			listener := edge.Listener{
				Project: d.Project, Service: d.Service,
				Port: p.Host, Mode: mode,
				MaxConns:      p.MaxConns,
				IPRestriction: p.IPRestriction,
			}
			switch mode {
			case edge.ListenerUDP:
				// Backends, not the VIP. An empty set is published as-is: a
				// listener that drops (and counts) is more honest than one
				// that vanishes while the service restarts.
				listener.UpstreamPort = upstream
				listener.Backends = backendAddrs(backendsFor(w, d, attachments))
			default:
				listener.Upstream, listener.UpstreamPort = vip, upstream
			}
			// A tcp or udp listener carries only what it can enforce. The spec
			// refuses the rest at plan time; dropping it here as well keeps a
			// hand-written record from producing an invalid snapshot.
			if mode == edge.ListenerHTTP {
				listener.RateLimit, listener.Headers = p.RateLimit, p.Headers
			}
			listeners = append(listeners, listener)
		}
	}
	return listeners
}

// backendAddrs is the sorted v4 address list of a backend set, for the udp
// listener projection.
func backendAddrs(backends []network.Backend) []string {
	out := make([]string, 0, len(backends))
	for _, b := range backends {
		if b.IPv4 != "" {
			out = append(out, b.IPv4)
		}
	}
	sort.Strings(out)
	return out
}

// buildFunctionRoutes is the functions-port dispatch table (PRD §7.2.3):
// http-triggered functions whose route resolved to no hostname — no declared
// domains and no base domain — reached as /<project>/<function>/… instead.
//
// Which mode a function gets is decided here, on the node, exactly as
// ResolveTLSMode decides a certificate source: the spec never encodes it, so
// one spec means the same thing on every node.
func (r *Reconciler) buildFunctionRoutes(w World, vips map[string]string) []edge.FunctionRoute {
	var out []edge.FunctionRoute
	for _, d := range sortedDesired(w.Desired) {
		if d.Function == nil || !d.Function.HTTP || d.Expose == nil {
			continue
		}
		if len(r.domainsFor(d)) > 0 {
			continue // host-routed; the FQDN table owns it
		}
		name := d.Project + "/" + d.Service
		vip := vips[name]
		if vip == "" {
			r.log.Debug("function has no frontend yet", "function", name)
			continue
		}
		// (project, service) is unique in desired state, so unlike domains and
		// node ports the prefix cannot collide — there is no claim map here
		// because there is nothing to claim.
		out = append(out, edge.FunctionRoute{
			Project: d.Project, Function: d.Service,
			Upstream: vip, UpstreamPort: d.Expose.Port,
			IPRestriction: d.Expose.IPRestriction,
			RateLimit:     d.Expose.RateLimit,
			Headers:       d.Expose.Headers,
			AuthRequired:  d.Expose.Auth != nil,
		})
	}
	return out
}

// functionsEqual is the functions half of snapshotIsPublished.
func functionsEqual(a, b []edge.FunctionRoute) bool {
	return slices.EqualFunc(a, b, func(x, y edge.FunctionRoute) bool {
		return x.Project == y.Project && x.Function == y.Function &&
			x.Upstream == y.Upstream && x.UpstreamPort == y.UpstreamPort &&
			x.AuthRequired == y.AuthRequired &&
			reflect.DeepEqual(x.IPRestriction, y.IPRestriction) &&
			reflect.DeepEqual(x.RateLimit, y.RateLimit) &&
			reflect.DeepEqual(x.Headers, y.Headers)
	})
}

// listenersEqual is the listener half of snapshotIsPublished.
func listenersEqual(a, b []edge.Listener) bool {
	return slices.EqualFunc(a, b, func(x, y edge.Listener) bool {
		return x.Project == y.Project && x.Service == y.Service &&
			x.Port == y.Port && x.Mode == y.Mode &&
			x.Upstream == y.Upstream && x.UpstreamPort == y.UpstreamPort &&
			// Backends are how a udp listener reaches anything, so backend
			// churn must republish — leaving them out is the exact mistake
			// routesArePublished made with listeners (PRD v1.33).
			slices.Equal(x.Backends, y.Backends) &&
			x.MaxConns == y.MaxConns &&
			reflect.DeepEqual(x.IPRestriction, y.IPRestriction) &&
			reflect.DeepEqual(x.RateLimit, y.RateLimit) &&
			reflect.DeepEqual(x.Headers, y.Headers)
	})
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
	var out []string
	for _, e := range d.AllExposes() {
		out = append(out, EdgeDomainsFor(d, e, baseDomain)...)
	}
	return out
}

// EdgeDomainsFor is EdgeDomains for one route (v1.50). Only the first block
// may generate the auto-FQDN — one generated name per service, R16's rule —
// so an extra block with no domains resolves to nothing.
func EdgeDomainsFor(d Desired, e *Expose, baseDomain string) []string {
	if e == nil {
		return nil
	}
	if len(e.Domains) > 0 {
		out := make([]string, 0, len(e.Domains))
		for _, domain := range e.Domains {
			if canonical := canonicalDomain(domain); canonical != "" {
				out = append(out, canonical)
			}
		}
		return out
	}
	if e != d.Expose {
		return nil
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
//
// Every field buildRoutes sets must be compared here, or an edit to it
// publishes exactly once and never again — the routesArePublished lesson
// (PRD v1.33).
func routesEqual(a, b []edge.Route) bool {
	return slices.EqualFunc(a, b, func(x, y edge.Route) bool {
		return x.Project == y.Project && x.Service == y.Service &&
			x.Upstream == y.Upstream && x.Port == y.Port &&
			x.AuthRequired == y.AuthRequired &&
			x.Protocol == y.Protocol &&
			slices.Equal(x.Domains, y.Domains) &&
			reflect.DeepEqual(x.IPRestriction, y.IPRestriction) &&
			reflect.DeepEqual(x.RateLimit, y.RateLimit) &&
			reflect.DeepEqual(x.Headers, y.Headers)
	})
}
