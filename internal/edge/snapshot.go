package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// DefaultSnapshotPath is where kanead projects the edge's state.
//
// Deliberately not under data_dir. The state directory is 0750 and holds the
// database, so an unprivileged kanea-edge user cannot even traverse into it —
// and widening it to hand one file over would be the wrong trade. This is
// derived, node-local state that is rebuilt from the Store on every start
// (constraint #9), which is what /run is for; it sits beside the Cilium file
// interfaces rather than beside the durable state.
const DefaultSnapshotPath = "/run/kanea-edge/routes.json"

// SnapshotName is the published file's name.
const SnapshotName = "routes.json"

// tempSuffix is used for the write-then-rename. It deliberately does not end in
// ".json": a reader that globs the directory must never pick up a half-written
// file (the same rule the Cilium file interfaces follow — PRD §5.2.5).
const tempSuffix = ".tmp"

// Snapshot is everything kanea-edge needs to serve traffic.
//
// It exists because the edge cannot read the Store. bbolt locks the whole
// database file, so a second process opening state.db — even read-only —
// blocks until kanead exits rather than returning stale data. The Store stays
// the source of truth and kanead stays its only opener; what the edge gets is
// this projection of it (PRD §5.2.6).
//
// The projection is one-directional. The edge never writes state, which is what
// lets it run as an unprivileged user with no database access at all: the
// process terminating untrusted public traffic cannot mutate the platform.
type Snapshot struct {
	// Index is the Store index this projection was built from. It makes a
	// reload loggable and a stale file recognisable.
	Index uint64 `json:"index"`
	// Routes is the full route table. It is a whole-file replacement, never a
	// delta: rebuilding from desired state is how every other derived thing in
	// Kanea works (constraint #9), and it means a missed update self-corrects.
	Routes []Route `json:"routes"`
	// Listeners are the node ports services publish (PRD §7.2.2, R21).
	//
	// omitempty is load-bearing: a node with no published ports writes a file
	// byte-identical to what it wrote before this field existed, so an older
	// edge parses it unchanged and no golden test moves.
	//
	// One file, not two. Two projections describing one service would raise an
	// ordering question — which one does the edge apply first, and what does it
	// serve in between — for no gain over one rename.
	Listeners []Listener `json:"listeners,omitempty"`
}

// Listener kinds (PRD §7.2.2).
const (
	// ListenerHTTP is an alternate-port HTTP listener. The edge reads requests
	// on it, so the whole §7.2.1 middleware chain applies.
	ListenerHTTP = "http"
	// ListenerTCP relays bytes. Only IPRestriction survives — there is nothing
	// else in a stream to apply a rule to.
	ListenerTCP = "tcp"
)

// Listener is one node port the edge binds on a service's behalf.
//
// It is reached by address rather than by name, which is why the route is fixed
// at bind time and never looked up per request: the Host header on a connection
// to 192.168.1.10:8096 is an IP literal that would match no domain.
//
// On a tcp listener the upstream sees the edge's address, not the client's.
// pg_hba.conf host rules and application-level IP bans stop meaning anything
// behind one, and IPRestriction — checked at accept time, before the upstream
// is dialled — is the whole mitigation.
type Listener struct {
	Project string `json:"project"`
	Service string `json:"service"`
	// Port is the node port to bind.
	Port int `json:"port"`
	// Mode is ListenerHTTP or ListenerTCP.
	Mode string `json:"mode"`
	// Upstream and UpstreamPort are the service frontend, exactly as a Route's
	// are: the eBPF LB balances, so a scale event changes nothing here.
	Upstream     string `json:"upstream"`
	UpstreamPort int    `json:"upstream_port"`
	// MaxConns bounds live connections. TCP only; zero means the edge's own
	// default.
	MaxConns int `json:"max_conns,omitempty"`

	IPRestriction *IPRestriction `json:"ip_restriction,omitempty"`
	// RateLimit and Headers are http only. A tcp listener carrying either is an
	// invalid snapshot, not a dropped control.
	RateLimit *RateLimit `json:"rate_limit,omitempty"`
	Headers   *Headers   `json:"headers,omitempty"`
}

// Name identifies a listener in logs and rate-limit keys.
func (l Listener) Name() string { return l.Project + "/" + l.Service }

// Address is the upstream host:port.
func (l Listener) Address() string { return fmt.Sprintf("%s:%d", l.Upstream, l.UpstreamPort) }

// Bind is the local address the listener binds.
//
// Every interface, deliberately: there is no `bind` field in the spec. A bound
// address is useful and costs a DHCP-renew failure mode plus a second dimension
// of collision detection, and ip_restriction already covers the intent.
func (l Listener) Bind() string { return fmt.Sprintf(":%d", l.Port) }

// asRoute is the listener seen as a routing decision, so the HTTP path can
// reuse the one middleware chain rather than growing a second.
func (l Listener) asRoute() Route {
	return Route{
		Project: l.Project, Service: l.Service,
		Upstream: l.Upstream, Port: l.UpstreamPort,
		IPRestriction: l.IPRestriction, RateLimit: l.RateLimit, Headers: l.Headers,
	}
}

// Route sends one or more hostnames to one service.
type Route struct {
	Project string `json:"project"`
	Service string `json:"service"`
	// Domains are the hostnames this service answers on, lowercased.
	Domains []string `json:"domains"`
	// Upstream is the service's Cilium frontend address (§7.1), not an alloc
	// address. The eBPF LB does the balancing, so the edge holds one address
	// per service and never a backend list — a scale event changes nothing here.
	Upstream string `json:"upstream"`
	// Port is the frontend port, chosen by the R16 rule: the port named "http",
	// or the only one declared.
	Port int `json:"port"`
	// IPRestriction, RateLimit and Headers are the per-service ingress chain
	// (§7.2.1), applied in that order. Nil means the middleware is not
	// configured for this service — which is not the same as configured to
	// allow everything, and the distinction matters when server-level defaults
	// (§15.1 `edge`) fill in the gaps.
	IPRestriction *IPRestriction `json:"ip_restriction,omitempty"`
	RateLimit     *RateLimit     `json:"rate_limit,omitempty"`
	Headers       *Headers       `json:"headers,omitempty"`
}

// IPRestriction is the first middleware: deny wins over allow, and an empty
// allow list means the world.
type IPRestriction struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// RateLimit is a token bucket keyed by Per.
type RateLimit struct {
	// Requests is the sustained allowance per Window.
	Requests int `json:"requests"`
	// Window is the period Requests is measured over, as a Go duration.
	Window string `json:"window"`
	// Per selects the bucket key: "ip", "service", or "header:<name>".
	Per string `json:"per,omitempty"`
	// Burst is the bucket's capacity above the sustained rate. Zero means
	// Requests, so a client may spend its whole allowance at once.
	Burst int `json:"burst,omitempty"`
}

// Headers rewrites request and response headers.
type Headers struct {
	RequestSet     map[string]string `json:"request_set,omitempty"`
	RequestRemove  []string          `json:"request_remove,omitempty"`
	ResponseSet    map[string]string `json:"response_set,omitempty"`
	ResponseRemove []string          `json:"response_remove,omitempty"`
}

// Name identifies the route in logs and errors.
func (r Route) Name() string { return r.Project + "/" + r.Service }

// Address is the upstream host:port.
func (r Route) Address() string { return fmt.Sprintf("%s:%d", r.Upstream, r.Port) }

// ErrInvalidSnapshot marks a projection that cannot be served.
var ErrInvalidSnapshot = errors.New("edge: invalid snapshot")

// Validate checks a snapshot before it is written or served.
//
// Validating on both sides is deliberate. On the write side it stops kanead
// publishing something the edge will reject; on the read side it stops a
// hand-edited or truncated file from taking routing down. The edge is the one
// process whose failure is directly visible to the public.
func (s Snapshot) Validate() error {
	seen := map[string]string{}
	for i, r := range s.Routes {
		where := fmt.Sprintf("route %d (%s)", i, r.Name())
		if r.Project == "" || r.Service == "" {
			return fmt.Errorf("%w: %s has no project or service", ErrInvalidSnapshot, where)
		}
		if _, err := netip.ParseAddr(r.Upstream); err != nil {
			return fmt.Errorf("%w: %s upstream %q is not an address", ErrInvalidSnapshot, where, r.Upstream)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("%w: %s port %d is out of range", ErrInvalidSnapshot, where, r.Port)
		}
		if len(r.Domains) == 0 {
			return fmt.Errorf("%w: %s claims no domain", ErrInvalidSnapshot, where)
		}
		for _, d := range r.Domains {
			if d != strings.ToLower(d) || strings.TrimSpace(d) != d {
				return fmt.Errorf("%w: %s domain %q is not canonical (lowercase, unpadded)",
					ErrInvalidSnapshot, where, d)
			}
			if first, dup := seen[d]; dup {
				// R16 catches this at plan time. Catching it again here is not
				// redundant: a snapshot assembled from several applies could
				// still collide, and last-writer-wins in a routing table is a
				// silent misdelivery.
				return fmt.Errorf("%w: domain %q is claimed by both %s and %s",
					ErrInvalidSnapshot, d, first, r.Name())
			}
			seen[d] = r.Name()
		}
		// Middleware is checked by compiling it, so the writer cannot publish a
		// rule the reader will refuse. A snapshot that passes here and fails at
		// the edge would freeze routing at the last good table while kanead
		// reports success — the worst of both.
		if _, err := compile(r); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
		}
	}
	return s.validateListeners()
}

// validateListeners checks the published ports.
//
// byPort is deliberately separate from the routes' `seen`: a domain and a port
// are different namespaces, and a service can legitimately be reachable as
// shop.example.com and on :8096 at once.
func (s Snapshot) validateListeners() error {
	byPort := map[int]string{}
	for i, l := range s.Listeners {
		where := fmt.Sprintf("listener %d (%s)", i, l.Name())
		if l.Project == "" || l.Service == "" {
			return fmt.Errorf("%w: %s has no project or service", ErrInvalidSnapshot, where)
		}
		if l.Mode != ListenerHTTP && l.Mode != ListenerTCP {
			return fmt.Errorf("%w: %s has mode %q, which is neither %q nor %q",
				ErrInvalidSnapshot, where, l.Mode, ListenerHTTP, ListenerTCP)
		}
		if _, err := netip.ParseAddr(l.Upstream); err != nil {
			return fmt.Errorf("%w: %s upstream %q is not an address",
				ErrInvalidSnapshot, where, l.Upstream)
		}
		for _, p := range []struct {
			field string
			value int
		}{{"port", l.Port}, {"upstream port", l.UpstreamPort}} {
			if p.value < 1 || p.value > 65535 {
				return fmt.Errorf("%w: %s %s %d is out of range",
					ErrInvalidSnapshot, where, p.field, p.value)
			}
		}
		if l.MaxConns < 0 {
			return fmt.Errorf("%w: %s has a negative connection limit %d",
				ErrInvalidSnapshot, where, l.MaxConns)
		}
		// Refused, not dropped. A snapshot that carried a rate limit onto a
		// listener that cannot count requests would leave the spec claiming a
		// control nothing is applying — R16's rule, in the reader.
		if l.Mode == ListenerTCP {
			if l.RateLimit != nil {
				return fmt.Errorf("%w: %s is a tcp listener carrying a rate limit, which it cannot apply",
					ErrInvalidSnapshot, where)
			}
			if l.Headers != nil {
				return fmt.Errorf("%w: %s is a tcp listener carrying header rules, which it cannot apply",
					ErrInvalidSnapshot, where)
			}
		}
		if first, dup := byPort[l.Port]; dup {
			// Caught at plan time too, and caught again here for the reason
			// duplicate domains are: a snapshot assembled from several applies
			// can still collide, and which of two listeners binds a port would
			// otherwise be decided by whichever goroutine got there first.
			return fmt.Errorf("%w: node port %d is claimed by both %s and %s",
				ErrInvalidSnapshot, l.Port, first, l.Name())
		}
		byPort[l.Port] = l.Name()

		// Compiled here for the same reason a route's middleware is: the writer
		// must not be able to publish a rule the reader will refuse.
		if _, err := compile(l.asRoute()); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
		}
	}
	return nil
}

// Publish writes the snapshot for the edge to read.
//
// Temp-then-rename, because the reader is a separate process polling the file:
// a partially written table must never be observable, and rename(2) is the only
// way to make the swap atomic.
func Publish(path string, snap Snapshot) error {
	if err := snap.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	body = append(body, '\n')

	// The directory and the file are world-readable, which is the point rather
	// than an oversight: kanea-edge runs as its own unprivileged user (§5.2.6)
	// and cannot read this otherwise. Nothing here is a secret — the domains
	// are in public DNS and the upstreams are node-local addresses — and the
	// alternative, a shared group, is a `kanea init` prerequisite this cannot
	// assume exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 — see above
		return fmt.Errorf("edge dir: %w", err)
	}

	// The temp file lives in the destination directory so the rename stays on
	// one filesystem; a cross-device rename is not atomic and is the whole
	// reason for doing this.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*"+tempSuffix)
	if err != nil {
		return fmt.Errorf("create temp snapshot: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// A no-op once the rename succeeded. A failure to clean up after a
		// failed publish would leave a temp file behind, which is untidy but
		// harmless — the name does not end in .json.
		if err := os.Remove(tmpName); err != nil && !os.IsNotExist(err) {
			slog.Default().Debug("cannot remove temp snapshot", "path", tmpName, "error", err)
		}
	}()

	if err := writeSnapshotFile(tmp, tmpName, body); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish snapshot: %w", err)
	}
	return nil
}

// writeSnapshotFile fills and closes the temp file the publish will rename.
func writeSnapshotFile(tmp *os.File, name string, body []byte) error {
	defer func() {
		if err := tmp.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			slog.Default().Debug("cannot close temp snapshot", "path", name, "error", err)
		}
	}()

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	// Durability before visibility: a snapshot that survives the rename but not
	// a power cut would leave the edge serving an empty table after a reboot.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { // #nosec G302 — readable by the edge user
		return fmt.Errorf("chmod snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	return nil
}

// Load reads a published snapshot.
func Load(path string) (Snapshot, error) {
	body, err := os.ReadFile(path) // #nosec G304 — the path is operator configuration
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
	}
	if err := snap.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// SnapshotPath is where the projection lives under a given directory.
func SnapshotPath(dir string) string {
	return filepath.Join(dir, SnapshotName)
}
