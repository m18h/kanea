// Package api is the control-plane API kanead serves and the CLI consumes.
//
// Every route is authenticated, deny-by-default, with exactly two exemptions
// (§5.2.1): health and login. A caller is one of three things: a bearer token,
// a session cookie, or the local root of §13.1 reaching the 0600 unix socket,
// where the socket's file mode *is* the credential. Mutations additionally
// require the admin role, a CSRF token when the credential is a cookie, and an
// entry in the audit log. See auth.go: the checks live in one wrapper that every
// route passes through, because "which routes are protected" should not be a
// question about string matching.
//
// The socket remains the CLI's transport, and is the only listener until an
// operator configures one: bbolt is single-writer (PRD §5.2.3), kanead holds the
// state file open, and so every CLI command is a request to the running agent.
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/reconciler"
)

// DefaultSocket is where kanead listens.
const DefaultSocket = "/run/kanea/kanead.sock"

// SocketGroup is the operator-created group whose members may use the CLI
// without sudo (PRD v1.48, §13.1). When it exists the socket is published
// root:kanea 0660 instead of 0600. Membership is root-equivalent (docker's
// model) and the group's absence, which is the default, changes nothing.
const SocketGroup = "kanea"

// Paths served by the API. Versioned from the start so the CLI and the daemon
// can disagree about their versions without silently misbehaving.
const (
	PathHealth   = "/v1/healthz"
	PathServices = "/v1/services"
	PathAllocs   = "/v1/allocs"
	PathLogs     = "/v1/logs"
	// PathMCP is the Model Context Protocol transport (§16.3). Deliberately not
	// under /v1: it is not this API's versioned surface, it is MCP's, and the
	// protocol carries its own version in the initialize handshake.
	PathMCP = "/mcp"
)

// Health is the readiness payload.
type Health struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	// StoreIndex is the latest applied store index: a cheap liveness signal
	// that also tells the CLI whether its write landed.
	StoreIndex uint64 `json:"store_index"`
	// WSConnections is how many live-data sockets are attached. It answers
	// "why is this daemon busy" and "did my dashboard actually connect"
	// without reading the log.
	WSConnections int `json:"ws_connections"`
	// OIDC describes the identity provider, when one is configured. It is here
	// rather than on a route of its own because §5.2.1 fixes the list of
	// unauthenticated routes, and a client needs this answer before it has a
	// credential to ask with.
	OIDC *OIDCStatus `json:"oidc,omitempty"`
	// Listen and TLS describe the network listener, for a client that reached
	// the daemon over the unix socket and needs somewhere to point a browser
	// (`kanea ui`). Empty when the socket is the only way in.
	//
	// Reported on the unauthenticated route for the same reason the issuer is:
	// it is needed before there is a credential to ask with, and it is not a
	// secret; a caller on the network already knows an address that works, and
	// a caller on the socket is the local root of §13.1.
	Listen string `json:"listen,omitempty"`
	TLS    bool   `json:"tls,omitempty"`
	// PID, StartedAt and UptimeSeconds describe the process (v1.38). Both the
	// start time and the elapsed seconds ride together so a client can render
	// "up 41d 6h" without trusting its own clock to agree with the daemon's.
	PID           int       `json:"pid"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
}

// ApplyRequest replaces the desired state of the services it names. Services
// not mentioned are untouched: `kanea run` on one file must not delete
// everything declared in another.
type ApplyRequest struct {
	Services []reconciler.Desired `json:"services"`
	// Pipelines carries the project-level `git` block and the per-service
	// `build` blocks from the same file (§10). They travel with the services
	// because they came from one spec: a service with a build block whose
	// source the daemon does not know is a service that can never be rebuilt,
	// and that is exactly what splitting them into two calls would allow.
	Pipelines []gitops.Config `json:"pipelines,omitempty"`
	// PruneProjects names the projects this request is authoritative for: a
	// stored service in one of them that the request does not name is deleted.
	// Empty (the default) keeps the additive behaviour above, which is why
	// every existing caller is unaffected.
	//
	// The scope is stated rather than inferred, and that is the whole design.
	// `kanea run app.hcl shop/web` filters the desired state before sending it,
	// so a server that derived "authoritative for" from the services present
	// could not tell a selector-scoped apply from a spec that declares exactly
	// those services — and would read the first as "delete everything else".
	PruneProjects []string `json:"prune_projects,omitempty"`
}

// ScaleRequest sets a service's replica count.
type ScaleRequest struct {
	Count int `json:"count"`
}

// ApplyResponse reports what the apply changed.
type ApplyResponse struct {
	Applied []string `json:"applied"`
	// Removed names the services a prune deleted, empty unless the request
	// carried PruneProjects.
	Removed []string `json:"removed,omitempty"`
	// Index is the store index the write was stamped with.
	Index uint64 `json:"index"`
}

// ServiceView is a Desired as the API serves it, with fields computed at
// projection time. SpecHash is reconciler.SpecHash over the record, never
// stored, so the hash material and the Store shape are untouched. A client
// compares it against AllocRecord.SpecHash (the planner's own staleness
// rule) to tell whether a deploy is in flight.
type ServiceView struct {
	reconciler.Desired
	SpecHash string `json:"spec_hash"`
}

// ServicesResponse lists the declared services.
type ServicesResponse struct {
	Services []ServiceView `json:"services"`
}

// serviceViews projects desired records for a response. Both the REST list
// and the websocket services feed go through it, so the two surfaces cannot
// disagree about what a service looks like on the wire.
func serviceViews(services []reconciler.Desired) []ServiceView {
	views := make([]ServiceView, len(services))
	for i, d := range services {
		views[i] = ServiceView{Desired: d, SpecHash: reconciler.SpecHash(d)}
	}
	return views
}

// elidedServiceViews is serviceViews with every file's content dropped, for the
// websocket feed (jobspec R35).
//
// The feed ships every service's whole record to every subscriber on every
// store-index change, so a service carrying the per-service maximum of file
// content would put that much into a send buffer whose overflow closes the
// connection - the v1.70 defect, in a new place. Content is the one field in a
// record that is bulk bytes and that nothing on a live dashboard reads.
//
// It is elided **always, never conditionally**: a client that sometimes gets
// content cannot tell an elided file from an empty one, and ContentBytes is
// what it renders instead.
//
// GET /v1/services deliberately keeps the content. There is no per-service GET,
// so `kanea deploy` round-trips the whole record through the list; eliding it
// there would make every deploy silently delete every config file on the node.
func elidedServiceViews(services []reconciler.Desired) []ServiceView {
	views := serviceViews(services)
	for i := range views {
		if len(views[i].Files) == 0 {
			continue
		}
		// Copied before it is stripped: Desired is embedded by value, but
		// Files is a slice and its backing array is the Store's.
		files := make([]reconciler.FileMount, len(views[i].Files))
		copy(files, views[i].Files)
		for j := range files {
			files[j].ContentBytes = len(files[j].Content)
			files[j].Content = nil
		}
		views[i].Files = files
	}
	return views
}

// AllocsResponse lists alloc records, newest state first.
type AllocsResponse struct {
	Allocs []reconciler.AllocRecord `json:"allocs"`
}

// Error is the error body. A single shape keeps the CLI's error handling
// honest: anything non-2xx carries this.
type Error struct {
	Error string `json:"error"`
}

// LogOptions selects a log stream.
type LogOptions struct {
	// Project and Service select allocs; AllocID selects exactly one.
	Project string
	Service string
	AllocID string
	// Follow keeps the stream open, tailing new output.
	Follow bool
	// Tail is how many trailing lines to send before following. Zero means all.
	Tail int
	// Container names an init container (R32) whose log to read instead of the
	// task's. It is a *step name*, resolved server-side against the service's
	// own declared sequence: no client ever names a container id.
	Container string
}

// PollInterval is how often a following log stream checks for new output.
// Files are the transport (PRD §17), so this is a tail, not a subscription.
const PollInterval = 250 * time.Millisecond

// decodeBody reads a bounded JSON request body.
//
// Bounded everywhere, without exception: an unbounded json.Decode on a request
// body is a memory-exhaustion vector that looks like ordinary parsing.
func decodeBody(r *http.Request, into any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes)).Decode(into); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	return nil
}

// maxRequestBytes bounds a JSON request body. Job specs go through their own
// larger limit on the apply route; everything else is small.
const maxRequestBytes = 1 << 20
