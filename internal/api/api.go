// Package api is the control-plane API kanead serves and the CLI consumes.
//
// Every route is authenticated, deny-by-default, with exactly two exemptions
// (§5.2.1): health and login. A caller is one of three things — a bearer token,
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
	"time"

	"github.com/kanea-dev/kanea/internal/gitops"
	"github.com/kanea-dev/kanea/internal/reconciler"
)

// DefaultSocket is where kanead listens.
const DefaultSocket = "/run/kanea/kanead.sock"

// Paths served by the API. Versioned from the start so the CLI and the daemon
// can disagree about their versions without silently misbehaving.
const (
	PathHealth   = "/v1/healthz"
	PathServices = "/v1/services"
	PathAllocs   = "/v1/allocs"
	PathLogs     = "/v1/logs"
)

// Health is the readiness payload.
type Health struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	// StoreIndex is the latest applied store index — a cheap liveness signal
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
}

// ScaleRequest sets a service's replica count.
type ScaleRequest struct {
	Count int `json:"count"`
}

// ApplyResponse reports what the apply changed.
type ApplyResponse struct {
	Applied []string `json:"applied"`
	// Index is the store index the write was stamped with.
	Index uint64 `json:"index"`
}

// ServicesResponse lists the declared services.
type ServicesResponse struct {
	Services []reconciler.Desired `json:"services"`
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
}

// PollInterval is how often a following log stream checks for new output.
// Files are the transport (PRD §17), so this is a tail, not a subscription.
const PollInterval = 250 * time.Millisecond
