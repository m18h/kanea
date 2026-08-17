package scaling

import (
	"strings"
	"sync"
	"time"
)

// Edge metric passthrough (PRD §9.1.1).
//
// The edge publishes two families. The aggregate one: one series per service;
// is differenced into the rings by EdgeScraper and is the autoscaler's input.
// The labelled one carries {code,method,protocol} and is **not** differenced,
// not stored in the time series, and not aggregated: it is held here as the
// bytes the edge produced and republished by the exporter unchanged.
//
// Retaining raw text rather than a parsed model is deliberate. There is nothing
// to compute, so a parse-and-re-serialise round trip could only introduce a
// discrepancy between what the edge measured and what an operator reads. It
// also means a new counter in internal/edge reaches /v1/metrics by adding one
// prefix below, instead of by writing a second renderer that has to be kept in
// step with the first.

// passthroughPrefixes are the families the exporter republishes.
//
// An allowlist, not "everything that is not the aggregate". §9.1's exporter
// already holds this line for the time series and it holds here for the same
// reason: a metric that becomes public because someone added it internally is a
// promise nobody decided to make.
var passthroughPrefixes = []string{
	"kanea_edge_service_",
	"kanea_edge_entrypoint_",
	"kanea_edge_tcp_",
	"kanea_edge_tls_certs_not_after",
	"kanea_edge_config_",
	"kanea_edge_refused_total",
	"kanea_edge_series_dropped_total",
}

// The aggregate families are deliberately absent from the list above.
//
// kanea_edge_requests_total and its histogram are the same traffic the labelled
// family already counts, so republishing both would double every sum() a user
// writes over them. Anyone who wants the per-service total can ask for it:
// sum without(code,method,protocol) (kanea_edge_service_requests_total).

// maxRetainedBytes bounds the exposition held between scrapes.
//
// The edge caps its own cardinality per service (edge.maxSeriesPerService), so
// this is a backstop against a version skew rather than against ordinary
// growth: kanead must not grow without limit because an edge it does not
// supervise started producing something unexpected.
const maxRetainedBytes = 4 << 20

// Breakdown families the scraper folds into a structured per-service view.
const (
	breakdownRequests      = "kanea_edge_service_requests_total"
	breakdownRequestBytes  = "kanea_edge_service_requests_bytes_total"
	breakdownResponseBytes = "kanea_edge_service_responses_bytes_total"
)

// ServiceBreakdown is one service's labelled totals in a shape the dashboard
// and the CLI can render without parsing an exposition.
//
// Cumulative, like the counters it comes from: these are lifetime totals for
// the edge process, not a rate. A consumer that wants "errors in the last
// hour" wants Prometheus, and a consumer that wants "has this service ever
// served a 502" wants exactly this.
type ServiceBreakdown struct {
	// Codes maps a status code to the requests answered with it.
	Codes map[string]float64 `json:"codes,omitempty"`
	// RequestBytes and ResponseBytes are body bytes moved.
	RequestBytes  float64 `json:"request_bytes"`
	ResponseBytes float64 `json:"response_bytes"`
}

// breakdowns accumulates one scrape's structured view.
type breakdowns map[string]*ServiceBreakdown

func (b breakdowns) at(service string) *ServiceBreakdown {
	if sb, ok := b[service]; ok {
		return sb
	}
	sb := &ServiceBreakdown{Codes: map[string]float64{}}
	b[service] = sb
	return sb
}

// observe folds one exposition sample into the structured view. Names outside
// the three breakdown families are ignored.
func (b breakdowns) observe(name, service, code string, value float64) {
	if service == "" {
		return
	}
	switch name {
	case breakdownRequests:
		if code != "" {
			// Summed across method and protocol: a status-code breakdown is what
			// a dashboard shows, and the finer split is available in Prometheus
			// for anyone who wants it.
			b.at(service).Codes[code] += value
		}
	case breakdownRequestBytes:
		b.at(service).RequestBytes = value
	case breakdownResponseBytes:
		b.at(service).ResponseBytes = value
	}
}

// EdgeExposition holds the labelled families between a scrape and an export.
//
// It is the seam between the two: internal/scaling writes it and internal/api
// reads it, and neither imports the other. The alternative (handing the API
// server a *EdgeScraper) would make the exporter's availability depend on the
// scrape loop having been started, which is a startup-ordering bug waiting to
// be written.
type EdgeExposition struct {
	mu        sync.RWMutex
	body      string
	at        time.Time
	truncate  bool
	byService breakdowns
}

// NewEdgeExposition builds an empty holder.
func NewEdgeExposition() *EdgeExposition {
	return &EdgeExposition{byService: breakdowns{}}
}

// Set replaces the retained exposition and its structured view.
//
// Replaces, never merges. A service that stopped being exposed produces no
// samples in the next scrape, and merging would leave its last totals visible
// for the life of the process: the same leak edge.Metrics.Retain exists to
// prevent on the other side of the wire.
func (e *EdgeExposition) Set(body string, at time.Time, byService breakdowns) {
	if e == nil {
		return
	}
	truncated := false
	if len(body) > maxRetainedBytes {
		body, truncated = body[:maxRetainedBytes], true
	}
	if byService == nil {
		byService = breakdowns{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.body, e.at, e.truncate, e.byService = body, at, truncated, byService
}

// Breakdown returns one service's labelled totals, if the last scrape saw it.
func (e *EdgeExposition) Breakdown(service string) (ServiceBreakdown, bool) {
	if e == nil {
		return ServiceBreakdown{}, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	sb, ok := e.byService[service]
	if !ok {
		return ServiceBreakdown{}, false
	}
	// Copied out: the caller marshals it or renders it, and handing back the
	// live map would let a JSON encoder read it while the next scrape replaces
	// what it points at.
	out := ServiceBreakdown{
		Codes:         make(map[string]float64, len(sb.Codes)),
		RequestBytes:  sb.RequestBytes,
		ResponseBytes: sb.ResponseBytes,
	}
	for code, n := range sb.Codes {
		out.Codes[code] = n
	}
	return out, true
}

// Snapshot returns the retained exposition and when it was scraped. ok is false
// before the first successful scrape.
func (e *EdgeExposition) Snapshot() (body string, at time.Time, ok bool) {
	if e == nil {
		return "", time.Time{}, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.body, e.at, !e.at.IsZero()
}

// Truncated reports whether the last retained exposition hit the byte cap.
func (e *EdgeExposition) Truncated() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.truncate
}

// keepInPassthrough reports whether an exposition line belongs in the retained
// body. Both comments and samples: HELP and TYPE travel with their family
// because Prometheus uses them; a counter exported without its TYPE is read as
// untyped, and rate() will not compute over an untyped series.
func keepInPassthrough(line string) bool {
	if line == "" {
		return false
	}
	name, ok := metricNameOf(line)
	return ok && isPassthrough(name)
}

// metricNameOf reads the family a line belongs to, for both comments and
// samples.
func metricNameOf(line string) (string, bool) {
	if strings.HasPrefix(line, "#") {
		// "# HELP <name> ..." or "# TYPE <name> ...". Anything else is a bare
		// comment and belongs to no family.
		fields := strings.Fields(line)
		if len(fields) < 3 || (fields[1] != "HELP" && fields[1] != "TYPE") {
			return "", false
		}
		return fields[2], true
	}
	// "<name>{labels} <value>" or "<name> <value>".
	name := line
	if i := strings.IndexAny(name, "{ "); i >= 0 {
		name = name[:i]
	}
	if name == "" {
		return "", false
	}
	return name, true
}

func isPassthrough(name string) bool {
	for _, prefix := range passthroughPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
