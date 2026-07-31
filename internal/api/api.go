// Package api is the control-plane API kanead serves and the CLI consumes.
//
// M1 scope: a local HTTP API over a unix socket. The socket is the security
// boundary — it is created 0600, owned by the user running kanead (root), and
// there is no network listener at all. PRD §14 (A05) requires the API to be
// authenticated or localhost-only and never an unauthenticated public listener;
// a root-owned unix socket is the strongest form of that, and M5 adds the
// TCP listener with tokens/OIDC on the same handlers.
//
// The API exists because bbolt is single-writer (PRD §5.2.3): kanead holds the
// state file open, so the CLI cannot read or write it directly. Every CLI
// command is a request to the running agent.
package api

import (
	"time"

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
}

// ApplyRequest replaces the desired state of the services it names. Services
// not mentioned are untouched: `kanea run` on one file must not delete
// everything declared in another.
type ApplyRequest struct {
	Services []reconciler.Desired `json:"services"`
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
