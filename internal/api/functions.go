package api

// GET /v1/functions (PRD v1.39, §12.2, §16.1): the functions view.
//
// A function IS a service — the marker is Desired.Function != nil (R25) — so
// this route is a filtered join over the same records the services list
// serves, plus what makes a function worth a page of its own: its triggers,
// the invoker's counters, and an invocation rate from the datapath's connect
// counters (§9.1). There are deliberately no mutation routes here: deploy and
// edit are the spec editor's, restart and scale are the service routes',
// inherited by construction.

import (
	"net/http"
	"sort"
	"time"

	"github.com/m18h/kanea/internal/functions"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
)

// PathFunctions lists wasm functions.
const PathFunctions = "/v1/functions"

// InvokerSource reports the event/cron invoker's per-function counters.
// Interface at the consumer; the implementation is *functions.Invoker.
type InvokerSource interface {
	Snapshot() map[string]functions.Stats
	Dropped() int64
}

// Function statuses (§12.2). Derived, never stored.
const (
	// FunctionActive: running, and healthy where a probe exists.
	FunctionActive = "active"
	// FunctionIdle: observed traffic present and zero over the window —
	// absent data renders active, never idle ("no data is never zero").
	FunctionIdle = "idle"
	// FunctionTrapping: the crash-loop condition wearing its wasm name — a
	// trap is a nonzero exit is a crash.
	FunctionTrapping = "trapping"
	// FunctionStopped: scaled to zero on purpose.
	FunctionStopped = "stopped"
)

// FunctionView is one function, as the dashboard and CLI see it.
type FunctionView struct {
	Project string `json:"project"`
	Service string `json:"service"`
	// Module is the declared reference; RunModule is what actually runs when
	// a pipeline or auto-update pinned a digest.
	Module    string `json:"module"`
	RunModule string `json:"run_module,omitempty"`
	Count     int    `json:"count"`
	Runtime   string `json:"runtime"`
	// MemoryBytes is the R11 cap — the MEM CAP column, real (cgroup).
	MemoryBytes int64 `json:"memory_bytes"`

	HTTP    bool                      `json:"http"`
	Domains []string                  `json:"domains,omitempty"`
	Events  []reconciler.EventTrigger `json:"events,omitempty"`
	Crons   []reconciler.CronTrigger  `json:"crons,omitempty"`

	Status  string `json:"status"`
	Running int    `json:"running"`
	Healthy int    `json:"healthy"`
	// Restarts sums crash-restarts across allocs; what makes "trapping"
	// explainable rather than a chip.
	Restarts int `json:"restarts"`

	// InvocationsPerMinute is derived from the datapath's per-VIP connect
	// counters (§9.1) — nil when no sample exists, never zero.
	InvocationsPerMinute *float64 `json:"invocations_per_minute,omitempty"`
	// Invoker is the event/cron invoker's own bookkeeping; absent until the
	// first invocation.
	Invoker *functions.Stats `json:"invoker,omitempty"`
}

// FunctionsResponse is the route's body.
type FunctionsResponse struct {
	Functions []FunctionView `json:"functions"`
	// InvokerDropped counts events the invoker's queue refused — a cap nobody
	// can see is indistinguishable from a leak.
	InvokerDropped int64 `json:"invoker_dropped,omitempty"`
}

func (s *Server) handleListFunctions(w http.ResponseWriter, r *http.Request) {
	services, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	allocs, err := listAll[reconciler.AllocRecord](r.Context(), s.store, store.KindAlloc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	byService := map[string][]reconciler.AllocRecord{}
	for _, a := range allocs {
		key := a.Project + "/" + a.Service
		byService[key] = append(byService[key], a)
	}

	var invoked map[string]functions.Stats
	var dropped int64
	if s.invoker != nil {
		invoked = s.invoker.Snapshot()
		dropped = s.invoker.Dropped()
	}

	out := FunctionsResponse{Functions: []FunctionView{}, InvokerDropped: dropped}
	for _, d := range services {
		if d.Function == nil {
			continue
		}
		key := d.Project + "/" + d.Service
		view := FunctionView{
			Project: d.Project, Service: d.Service,
			Module: d.Image, Count: d.Count, Runtime: d.Runtime,
			MemoryBytes: d.Resources.MemoryBytes,
			HTTP:        d.Function.HTTP,
			Events:      d.Function.Events,
			Crons:       d.Function.Crons,
		}
		if run := d.RunImage(); run != d.Image {
			view.RunModule = run
		}
		if d.Expose != nil {
			view.Domains = d.Expose.Domains
		}
		if st, ok := invoked[key]; ok {
			stats := st
			view.Invoker = &stats
		}
		view.InvocationsPerMinute = s.functionRate(key)
		records := byService[key]
		view.Running, view.Healthy, view.Restarts = countAllocs(d, records)
		view.Status = functionStatus(d, records, view.InvocationsPerMinute, view.Invoker)
		out.Functions = append(out.Functions, view)
	}
	sort.Slice(out.Functions, func(i, j int) bool {
		a, b := out.Functions[i], out.Functions[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Service < b.Service
	})
	writeJSON(w, http.StatusOK, out)
}

// functionRate reads the latest flows_per_second sample for a function —
// the datapath's connect counter, which sees edge, east-west and invoker
// traffic alike (§9.1). Nil when no sample exists: under --network netns
// there is no datapath, and "no data is never zero".
func (s *Server) functionRate(subject string) *float64 {
	if s.metrics == nil {
		return nil
	}
	point, ok := s.metrics.Latest(scaling.Key{Subject: subject, Metric: scaling.MetricFlows})
	if !ok {
		return nil
	}
	perMinute := point.Value * 60
	return &perMinute
}

// countAllocs reports running, healthy-where-probed, and total restarts.
func countAllocs(d reconciler.Desired, records []reconciler.AllocRecord) (running, healthy, restarts int) {
	for _, a := range records {
		restarts += a.Restarts
		if a.State != reconciler.AllocRunning {
			continue
		}
		running++
		// The Probed() discipline: Healthy is only ever written by a probe,
		// so a check-free function counts running allocs as its bar.
		if d.Check == nil || a.Healthy {
			healthy++
		}
	}
	return running, healthy, restarts
}

// functionStatus derives the §12.2 chip. Honest derivations only:
//
//   - trapping: an alloc exited recently or is waiting out restart backoff —
//     the existing crash-loop condition wearing its wasm name.
//   - stopped: count 0, on purpose.
//   - idle: an observed rate of zero AND an invoker that has recorded
//     nothing recently. Absent data is active, never idle.
//   - active: everything else that is up.
func functionStatus(d reconciler.Desired, records []reconciler.AllocRecord, rate *float64, invoked *functions.Stats) string {
	if d.Count == 0 {
		return FunctionStopped
	}
	for _, a := range records {
		if !a.NextRestartAt.IsZero() && time.Now().Before(a.NextRestartAt) {
			return FunctionTrapping
		}
		if a.State == reconciler.AllocRunning && a.Restarts > 0 &&
			!a.LastExitAt.IsZero() && time.Since(a.LastExitAt) < 5*time.Minute {
			return FunctionTrapping
		}
	}
	if rate != nil && *rate == 0 {
		recentInvoke := invoked != nil && time.Since(invoked.LastInvoked) < 15*time.Minute
		if !recentInvoke {
			return FunctionIdle
		}
	}
	return FunctionActive
}
