package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
)

// PathStats serves a point-in-time metrics sample (PRD §9.1, §16.1).
//
// The live version of this is the websocket's stats topic, which is what the
// dashboard uses. This route exists for callers that want one sample and have
// nowhere to put a long-lived connection — the CLI, and the MCP server, whose
// tools are single request/response by construction.
const PathStats = "/v1/stats"

// NodeStats is the node's own summary: what is declared, what is running, and
// how the machine underneath is doing (§17).
type NodeStats struct {
	Version string `json:"version"`
	// Projects, Services and Allocs are what is declared.
	Projects int `json:"projects"`
	Services int `json:"services"`
	Allocs   int `json:"allocs"`
	// Running, Unhealthy and Failed break the allocs down by state, so "40
	// allocs" is not mistaken for "40 working allocs".
	Running   int `json:"running"`
	Unhealthy int `json:"unhealthy"`
	Failed    int `json:"failed"`
	// Metrics reports the time-series pipeline's own health. A dashboard that
	// sees zero series knows to say "no data" rather than "no load".
	Metrics *MetricsHealth `json:"metrics,omitempty"`
	// BreakerOpen reports the circuit breaker (§4.3): while it is open, scaling
	// and rollouts are paused, which explains a lot of otherwise puzzling
	// inaction.
	BreakerOpen bool `json:"breaker_open"`
	// EventsDropped counts notification events the dispatcher could not queue.
	EventsDropped int64 `json:"events_dropped,omitempty"`
	// Node is the machine's own CPU, memory and load. Absent when procfs cannot
	// be read — which is a different fact from an idle node, and the pointer
	// fields inside it say so individually.
	Node *scaling.NodeStats `json:"node,omitempty"`
	At   time.Time          `json:"at"`
}

// MetricsHealth describes the time series.
type MetricsHealth struct {
	Series  int   `json:"series"`
	Dropped int64 `json:"dropped"`
}

// handleStats serves one service's sample, or the node's when no service is
// named.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	project, service := q.Get("project"), q.Get("service")

	if project == "" && service == "" {
		stats, err := s.nodeStats(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, stats)
		return
	}
	if project == "" || service == "" {
		writeError(w, http.StatusBadRequest,
			errors.New("api: a service sample needs both project and service"))
		return
	}
	if s.metrics == nil {
		writeError(w, http.StatusServiceUnavailable, errNoMetrics)
		return
	}
	writeJSON(w, http.StatusOK, s.statsFor(r.Context(), project+"/"+service))
}

// nodeStats gathers the node summary.
func (s *Server) nodeStats(r *http.Request) (NodeStats, error) {
	out := NodeStats{Version: s.version, At: time.Now()}

	services, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		return out, err
	}
	allocs, err := listAll[reconciler.AllocRecord](r.Context(), s.store, store.KindAlloc)
	if err != nil {
		return out, err
	}

	projects := map[string]struct{}{}
	for _, svc := range services {
		projects[svc.Project] = struct{}{}
	}
	out.Projects, out.Services, out.Allocs = len(projects), len(services), len(allocs)
	for _, alloc := range allocs {
		switch {
		case alloc.State == reconciler.AllocFailed:
			out.Failed++
		case alloc.State == reconciler.AllocRunning && alloc.Probed() && !alloc.Healthy:
			// Running but failing its probe. Counted separately from running,
			// because a service whose allocs are all up and all unhealthy is
			// down, and one number that said "running: 3" would hide that.
			//
			// Probed() is the guard that matters: Healthy is only ever written
			// by a probe, so an alloc of a service that declares no check has it
			// false forever, and testing the field alone would report every such
			// alloc as unhealthy.
			out.Unhealthy++
		case alloc.State == reconciler.AllocRunning:
			out.Running++
		}
	}

	if s.metrics != nil {
		out.Metrics = &MetricsHealth{Series: s.metrics.Len(), Dropped: s.metrics.Dropped()}
	}
	if s.breaker != nil {
		out.BreakerOpen = s.breaker.Open()
	}
	if s.notifyStats != nil {
		out.EventsDropped = s.notifyStats().Dropped
	}
	if s.node != nil {
		reading := s.node.Read()
		out.Node = &reading
	}
	return out, nil
}

// NodeSource reads the machine's own statistics.
//
// An interface for one method, so the API depends on "hand me a reading" rather
// than on procfs — which is what lets a non-Linux build, and every test, omit
// it entirely rather than fake a filesystem.
type NodeSource interface {
	Read() scaling.NodeStats
}
