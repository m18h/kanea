package api

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// PathMetrics is the Prometheus exporter (PRD §9.1).
//
// Authenticated like everything else. Request rates, replica counts and
// per-service resource use describe how a business is doing, and §5.2.1's list
// of unauthenticated routes has two entries on it — this is not one of them. A
// Prometheus server scrapes it with a viewer token.
const PathMetrics = "/v1/metrics"

// MetricsSource is the slice of the metrics store the exporter needs.
type MetricsSource interface {
	Subjects(metric string) []string
	Latest(key scaling.Key) (scaling.Point, bool)
	Len() int
	Dropped() int64
}

// BreakerSource reports the circuit breaker's state (§4.3).
type BreakerSource interface {
	Open() bool
	Trips() int
}

// exported lists the series the exporter publishes, with the Prometheus name
// and help text for each.
//
// A fixed list rather than everything in the store: the store's key space is
// open, and an exporter that published whatever it found would turn a new
// internal metric into a new public one nobody meant to promise.
var exported = []struct {
	metric string
	name   string
	help   string
}{
	{scaling.MetricCPU, "kanea_cpu_percent", "CPU use as a percentage of the declared limit."},
	{scaling.MetricMemory, "kanea_memory_percent", "Memory use as a percentage of the declared limit."},
	{scaling.MetricMemoryBytes, "kanea_memory_bytes", "Memory use in bytes."},
	{scaling.MetricPIDs, "kanea_pids", "Processes in the alloc's cgroup."},
	{scaling.MetricRPS, "kanea_requests_per_second", "Requests per second at the edge."},
	{scaling.MetricP50, "kanea_latency_p50_ms", "Median request latency at the edge."},
	{scaling.MetricP95, "kanea_latency_p95_ms", "95th percentile request latency at the edge."},
	{scaling.MetricP99, "kanea_latency_p99_ms", "99th percentile request latency at the edge."},
	{scaling.MetricErrorRate, "kanea_error_rate_percent", "Percentage of responses that were 5xx."},
}

// handleMetrics renders the exposition format.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.metrics == nil {
		writeError(w, http.StatusServiceUnavailable, errNoMetrics)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	out := &exposition{w: w}
	for _, series := range exported {
		subjects := s.metrics.Subjects(series.metric)
		if len(subjects) == 0 {
			continue
		}
		out.printf("# HELP %s %s\n", series.name, series.help)
		out.printf("# TYPE %s gauge\n", series.name)

		sort.Strings(subjects)
		for _, subject := range subjects {
			point, ok := s.metrics.Latest(scaling.Key{Subject: subject, Metric: series.metric})
			// Omitted rather than exported as zero, and omitted once it is
			// stale. Prometheus reads whatever is here as the current value, so
			// a sample from three scrapes ago is not something to publish — and
			// a zero would be a claim that the service is idle rather than an
			// admission that we do not know.
			if !ok || time.Since(point.At) > metricStaleAfter {
				continue
			}
			out.printf("%s{%s} %g\n", series.name, subjectLabels(subject), point.Value)
		}
	}

	// Platform internals. They are the answers to "is the platform itself
	// healthy", which is a different question from "are the workloads", and the
	// one an operator asks when the numbers above look wrong.
	out.printf("# HELP kanea_metric_series Series held in the in-memory store.\n")
	out.printf("# TYPE kanea_metric_series gauge\n")
	out.printf("kanea_metric_series %d\n", s.metrics.Len())
	out.printf("# HELP kanea_metric_series_dropped_total Series refused at the cardinality cap.\n")
	out.printf("# TYPE kanea_metric_series_dropped_total counter\n")
	out.printf("kanea_metric_series_dropped_total %d\n", s.metrics.Dropped())
	out.printf("# HELP kanea_audit_write_failures_total Audit entries that could not be recorded.\n")
	out.printf("# TYPE kanea_audit_write_failures_total counter\n")
	out.printf("kanea_audit_write_failures_total %d\n", AuditFailures())
	out.printf("# HELP kanea_requests_rate_limited_total API requests refused by the rate limiter.\n")
	out.printf("# TYPE kanea_requests_rate_limited_total counter\n")
	out.printf("kanea_requests_rate_limited_total %d\n", RateLimited())
	out.printf("# HELP kanea_websocket_connections Live-data sockets attached.\n")
	out.printf("# TYPE kanea_websocket_connections gauge\n")
	out.printf("kanea_websocket_connections %d\n", s.ws.count())

	if s.breaker != nil {
		open := 0
		if s.breaker.Open() {
			open = 1
		}
		out.printf("# HELP kanea_circuit_breaker_open Whether scale actions are paused (PRD §4.3).\n")
		out.printf("# TYPE kanea_circuit_breaker_open gauge\n")
		out.printf("kanea_circuit_breaker_open %d\n", open)
		out.printf("# HELP kanea_circuit_breaker_trips_total Times the breaker has opened.\n")
		out.printf("# TYPE kanea_circuit_breaker_trips_total counter\n")
		out.printf("kanea_circuit_breaker_trips_total %d\n", s.breaker.Trips())
	}

	if out.err != nil {
		s.log.Debug("write metrics", "error", out.err)
	}
}

// subjectLabels turns a series subject into Prometheus labels.
//
// "shop/web" becomes project and service; "shop/web/alloc-0" adds the alloc.
// Splitting here rather than storing three fields keeps the metrics store's key
// one comparable string, which is what makes it a cheap map key.
func subjectLabels(subject string) string {
	parts := strings.SplitN(subject, "/", 3)
	switch len(parts) {
	case 2:
		return fmt.Sprintf("project=%q,service=%q", parts[0], parts[1])
	case 3:
		return fmt.Sprintf("project=%q,service=%q,alloc=%q", parts[0], parts[1], parts[2])
	default:
		return fmt.Sprintf("subject=%q", subject)
	}
}

// exposition writes the response and holds the first failure, so the many
// writes above do not each need checking — the header is already sent, so a
// failure partway cannot become a status code either way.
type exposition struct {
	w   io.Writer
	err error
}

func (e *exposition) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

// metricStaleAfter is how old a sample may be and still be published.
//
// Three scrape intervals: enough that one missed scrape does not blank a
// dashboard, short enough that a dead scraper stops producing numbers someone
// would act on.
const metricStaleAfter = 3 * scaling.RawInterval

var errNoMetrics = fmt.Errorf("api: the metrics pipeline is not configured")
