package edge

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// L7 metrics (PRD §9.1).
//
// The edge is the **primary autoscaling signal for exposed services**: it is
// already in the request path, so counting there costs nothing extra, while
// Hubble's L7 parsing costs CPU per request and drops flows exactly when
// traffic peaks — losing fidelity at the only moment the number matters.
//
// What is published is **cumulative counters**, never a rate or a percentile.
// The edge does not know the scrape interval, does not know how many scrapers
// there are, and must not hold a window that a missed scrape would silently
// reset. kanead differences two readings, which is the same thing it does with
// containerd's CPU counter, and a missed scrape becomes a wider interval rather
// than a lost measurement.

// latencyBounds are the histogram's upper edges in milliseconds.
//
// Log-spaced, and denser where a decision gets made: `p95_latency_ms` targets
// in the hundreds are what a real scaling rule is written against (§6.1), so
// resolution there is worth more than resolution at 10 ms or at 30 s. The last
// bucket is unbounded, because a request that takes a minute still has to be
// counted somewhere.
var latencyBounds = []float64{1, 2, 5, 10, 25, 50, 100, 200, 400, 800, 1500, 3000, 10000}

// serviceMetrics is one service's counters.
//
// Bounded by construction: a histogram of len(latencyBounds)+1 counters and
// four scalars per service, and the service set comes from the route table
// rather than from anything a client sends. There is no per-path or per-status
// cardinality here for exactly that reason — a label an attacker can choose is
// a memory leak with a metric's name on it.
type serviceMetrics struct {
	requests atomic.Uint64
	// buckets are cumulative counts per latency bound, plus one overflow.
	buckets []atomic.Uint64
	// durationSum is milliseconds, for a mean that does not need the histogram.
	durationSum atomic.Uint64
	// errors counts 5xx responses: the signal that a service is failing rather
	// than merely busy, which are opposite scaling decisions.
	errors atomic.Uint64
	// refused counts requests the middleware rejected before an upstream saw
	// them. They are not load on the service and must not scale it up.
	refused atomic.Uint64
}

func newServiceMetrics() *serviceMetrics {
	return &serviceMetrics{buckets: make([]atomic.Uint64, len(latencyBounds)+1)}
}

// observe records one completed request.
func (m *serviceMetrics) observe(duration time.Duration, status int) {
	m.requests.Add(1)
	ms := float64(duration.Microseconds()) / 1000
	m.durationSum.Add(uint64(ms))
	if status >= 500 {
		m.errors.Add(1)
	}

	// Cumulative buckets: bucket i counts everything at or below bound i, which
	// is what `le` means in the exposition format and what makes a percentile
	// computable from a difference of two scrapes.
	idx := sort.SearchFloat64s(latencyBounds, ms)
	for i := idx; i < len(m.buckets); i++ {
		m.buckets[i].Add(1)
	}
}

// Metrics collects per-service request counters.
type Metrics struct {
	mu       sync.RWMutex
	services map[string]*serviceMetrics
}

// NewMetrics builds an empty collector.
func NewMetrics() *Metrics {
	return &Metrics{services: map[string]*serviceMetrics{}}
}

// Observe records a completed request against a service.
func (m *Metrics) Observe(service string, duration time.Duration, status int) {
	if service == "" {
		return
	}
	m.counters(service).observe(duration, status)
}

// Refused records a request the middleware rejected.
//
// Counted separately and never as a request: a service being hammered by
// blocked addresses is not a service under load, and scaling it up would spend
// capacity on traffic the edge is already dropping.
func (m *Metrics) Refused(service string) {
	if service == "" {
		return
	}
	m.counters(service).refused.Add(1)
}

// Forget drops a service's counters when it leaves the route table.
func (m *Metrics) Forget(service string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, service)
}

// Retain drops every service not in the given set, which is how the collector
// follows a reloaded route table without leaking the services it dropped.
func (m *Metrics) Retain(keep map[string]bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	dropped := 0
	for service := range m.services {
		if !keep[service] {
			delete(m.services, service)
			dropped++
		}
	}
	return dropped
}

func (m *Metrics) counters(service string) *serviceMetrics {
	m.mu.RLock()
	sm, ok := m.services[service]
	m.mu.RUnlock()
	if ok {
		return sm
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check: two requests for a new service race here, and the loser must
	// use the winner's counters rather than replacing them.
	if sm, ok = m.services[service]; ok {
		return sm
	}
	sm = newServiceMetrics()
	m.services[service] = sm
	return sm
}

// WriteTo renders the Prometheus exposition format.
//
// The same format containerd's endpoint uses, so kanead scrapes both with one
// parser rather than inventing a projection file for what is already a solved
// wire format.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	m.mu.RLock()
	names := make([]string, 0, len(m.services))
	for name := range m.services {
		names = append(names, name)
	}
	sort.Strings(names)
	snapshot := make([]*serviceMetrics, len(names))
	for i, name := range names {
		snapshot[i] = m.services[name]
	}
	m.mu.RUnlock()

	out := &printer{w: w}
	out.line("# HELP kanea_edge_requests_total Requests proxied to a service.")
	out.line("# TYPE kanea_edge_requests_total counter")
	for i, name := range names {
		out.printf("kanea_edge_requests_total{service=%q} %d\n", name, snapshot[i].requests.Load())
	}

	out.line("# HELP kanea_edge_request_duration_ms Request duration histogram.")
	out.line("# TYPE kanea_edge_request_duration_ms histogram")
	for i, name := range names {
		sm := snapshot[i]
		for b, bound := range latencyBounds {
			out.printf("kanea_edge_request_duration_ms_bucket{service=%q,le=\"%g\"} %d\n",
				name, bound, sm.buckets[b].Load())
		}
		out.printf("kanea_edge_request_duration_ms_bucket{service=%q,le=\"+Inf\"} %d\n",
			name, sm.buckets[len(latencyBounds)].Load())
		out.printf("kanea_edge_request_duration_ms_sum{service=%q} %d\n", name, sm.durationSum.Load())
		out.printf("kanea_edge_request_duration_ms_count{service=%q} %d\n", name, sm.requests.Load())
	}

	out.line("# HELP kanea_edge_errors_total Responses with a 5xx status.")
	out.line("# TYPE kanea_edge_errors_total counter")
	for i, name := range names {
		out.printf("kanea_edge_errors_total{service=%q} %d\n", name, snapshot[i].errors.Load())
	}

	out.line("# HELP kanea_edge_refused_total Requests rejected by ingress middleware.")
	out.line("# TYPE kanea_edge_refused_total counter")
	for i, name := range names {
		out.printf("kanea_edge_refused_total{service=%q} %d\n", name, snapshot[i].refused.Load())
	}

	return out.n, out.err
}

// printer writes the exposition and holds the first failure.
//
// One place that checks the error, rather than fifty call sites each checking a
// write that cannot usefully fail differently: once the response is broken,
// every later line is broken the same way, and the caller has already sent the
// header so it cannot answer with a status either way.
type printer struct {
	w   io.Writer
	n   int64
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	n, err := fmt.Fprintf(p.w, format, args...)
	p.n += int64(n)
	p.err = err
}

func (p *printer) line(s string) { p.printf("%s\n", s) }
