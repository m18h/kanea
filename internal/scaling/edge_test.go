package scaling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/scaling"
)

// edgeHarness runs a real edge collector behind an HTTP server, and scrapes it.
//
// The collector persists across scrapes because the real one does: its counters
// are cumulative for the life of the process, and a harness that rebuilt them
// per scrape would be testing a wire format the edge never emits. Restarting the
// edge is then something a test does deliberately, by replacing it.
type edgeHarness struct {
	edge    *edge.Metrics
	scraper *scaling.EdgeScraper
	metrics *scaling.Metrics
	clock   *clock
}

func newEdgeHarness(t *testing.T) *edgeHarness {
	t.Helper()
	h := &edgeHarness{clock: newClock(), edge: edge.NewMetrics()}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := h.edge.WriteTo(w); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	h.metrics = scaling.NewMetrics(scaling.MetricsConfig{Now: h.clock.now})
	scraper, err := scaling.NewEdgeScraper(scaling.EdgeConfig{
		URL: server.URL, Metrics: h.metrics, Now: h.clock.now,
	})
	if err != nil {
		t.Fatalf("NewEdgeScraper: %v", err)
	}
	h.scraper = scraper
	return h
}

func (h *edgeHarness) scrape(t *testing.T) {
	t.Helper()
	if _, err := h.scraper.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
}

// observe records n requests of a given latency and status against a service.
func (h *edgeHarness) observe(service string, n int, latency time.Duration, status int) {
	for range n {
		h.edge.Observe(service, latency, status)
	}
}

// latest reads one metric the scraper produced.
func (h *edgeHarness) latest(t *testing.T, service, metric string) (float64, bool) {
	t.Helper()
	point, ok := h.metrics.Latest(scaling.Key{Subject: service, Metric: metric})
	return point.Value, ok
}

func TestEdgeRPSIsADeltaOverElapsedTime(t *testing.T) {
	h := newEdgeHarness(t)

	h.observe("shop/web", 100, 10*time.Millisecond, 200)
	h.scrape(t)
	// One reading of a cumulative counter is uptime, not a rate.
	if _, ok := h.latest(t, "shop/web", scaling.MetricRPS); ok {
		t.Fatal("a rate was reported from a single reading")
	}

	// 50 more requests in the next 5 seconds: 10 rps.
	h.clock.advance(5 * time.Second)
	h.observe("shop/web", 50, 10*time.Millisecond, 200)
	h.scrape(t)

	rps, ok := h.latest(t, "shop/web", scaling.MetricRPS)
	if !ok {
		t.Fatal("no rps after two readings")
	}
	if rps < 9.9 || rps > 10.1 {
		t.Fatalf("rps = %v, want 10", rps)
	}
}

func TestEdgePercentilesDescribeTheInterval(t *testing.T) {
	h := newEdgeHarness(t)

	// A slow first interval that the second must not inherit: a service that
	// was slow an hour ago and is fast now should read as fast, which is what
	// differencing the histograms buys.
	h.observe("shop/web", 100, 2*time.Second, 200)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.observe("shop/web", 100, 3*time.Millisecond, 200)
	h.scrape(t)

	p95, ok := h.latest(t, "shop/web", scaling.MetricP95)
	if !ok {
		t.Fatal("no p95")
	}
	// Every request in this interval was ~3 ms, so the p95 belongs in the
	// single-digit millisecond buckets — not up with the previous interval's
	// two-second requests, which the cumulative histogram still contains.
	if p95 > 25 {
		t.Fatalf("p95 = %v ms; the previous interval's slow requests leaked in", p95)
	}
}

func TestEdgePercentilesOrderCorrectly(t *testing.T) {
	h := newEdgeHarness(t)
	// A baseline first: a service the edge has never reported has nothing to
	// difference against, which is the same reason the first scrape yields no
	// rate.
	h.observe("shop/web", 1, 5*time.Millisecond, 200)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	// A long tail: most requests fast, a few slow. This is the shape a
	// percentile exists to describe.
	h.observe("shop/web", 90, 5*time.Millisecond, 200)
	h.observe("shop/web", 9, 300*time.Millisecond, 200)
	h.observe("shop/web", 1, 5*time.Second, 200)
	h.scrape(t)

	get := func(metric string) float64 {
		t.Helper()
		value, ok := h.latest(t, "shop/web", metric)
		if !ok {
			t.Fatalf("no %s", metric)
		}
		return value
	}
	p50, p95, p99 := get(scaling.MetricP50), get(scaling.MetricP95), get(scaling.MetricP99)
	if p50 > p95 || p95 > p99 {
		t.Fatalf("percentiles out of order: p50=%v p95=%v p99=%v", p50, p95, p99)
	}
	if p50 > 25 {
		t.Errorf("p50 = %v ms, want the fast majority", p50)
	}
	if p95 < 25 {
		t.Errorf("p95 = %v ms, want the slow tail to move it", p95)
	}
}

func TestEdgeNoTrafficIsNotZeroLatency(t *testing.T) {
	h := newEdgeHarness(t)
	h.observe("shop/web", 1, 10*time.Millisecond, 200)
	h.scrape(t)

	// An interval with no requests at all. Reporting a p95 of zero would tell
	// the autoscaler the service is answering instantly, which is the opposite
	// of "it is answering nothing".
	h.clock.advance(5 * time.Second)
	h.scrape(t)

	if value, ok := h.latest(t, "shop/web", scaling.MetricP95); ok {
		t.Fatalf("p95 = %v reported for an interval with no requests", value)
	}
	// The request rate, however, is a real zero: no requests is a rate.
	rps, ok := h.latest(t, "shop/web", scaling.MetricRPS)
	if !ok || rps != 0 {
		t.Fatalf("rps = %v, %v; want a recorded zero", rps, ok)
	}
}

func TestEdgeErrorRateIsAPercentageOfRequests(t *testing.T) {
	h := newEdgeHarness(t)
	h.observe("shop/web", 1, time.Millisecond, 200)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.observe("shop/web", 80, time.Millisecond, 200)
	h.observe("shop/web", 20, time.Millisecond, 503)
	h.scrape(t)

	rate, ok := h.latest(t, "shop/web", scaling.MetricErrorRate)
	if !ok || rate < 19.9 || rate > 20.1 {
		t.Fatalf("error rate = %v, %v; want 20%%", rate, ok)
	}
}

func TestEdgeRestartRebaselines(t *testing.T) {
	h := newEdgeHarness(t)
	h.observe("shop/web", 1000, time.Millisecond, 200)
	h.scrape(t)

	// The edge restarted: a fresh collector, counters from zero. A naive delta
	// is negative, and reporting it would show a busy service as idle.
	h.clock.advance(5 * time.Second)
	h.edge = edge.NewMetrics()
	h.observe("shop/web", 1, time.Millisecond, 200)
	h.scrape(t)

	if value, ok := h.latest(t, "shop/web", scaling.MetricRPS); ok {
		t.Fatalf("rps = %v recorded across a counter reset", value)
	}
}

func TestEdgeForgetsServicesItNoLongerReports(t *testing.T) {
	h := newEdgeHarness(t)
	h.observe("shop/web", 1, time.Millisecond, 200)
	h.observe("shop/gone", 1, time.Millisecond, 200)
	h.scrape(t)

	// shop/gone stops being exposed, so the edge drops it from the table and
	// from its exposition.
	h.clock.advance(5 * time.Second)
	h.edge.Retain(map[string]bool{"shop/web": true})
	h.scrape(t)

	// It comes back much later. Its baseline was dropped with it, so this is a
	// first reading again rather than a rate against a stale timestamp.
	h.clock.advance(time.Hour)
	h.observe("shop/gone", 1, time.Millisecond, 200)
	h.scrape(t)

	if _, ok := h.latest(t, "shop/gone", scaling.MetricRPS); ok {
		t.Fatal("a rate was computed against a baseline from before the service left")
	}
}

func TestEdgeScrapeReportsAFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	c := newClock()
	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, err := scaling.NewEdgeScraper(scaling.EdgeConfig{URL: server.URL, Metrics: m, Now: c.now})
	if err != nil {
		t.Fatalf("NewEdgeScraper: %v", err)
	}
	if _, err := s.Scrape(context.Background()); err == nil {
		t.Fatal("a 502 was reported as a successful scrape")
	}
}

func TestNewEdgeScraperRequiresAStore(t *testing.T) {
	if _, err := scaling.NewEdgeScraper(scaling.EdgeConfig{}); err == nil {
		t.Fatal("a scraper with nowhere to record was accepted")
	}
}

// The two packages agree on a wire format. This asserts the names the scraper
// looks for are the names the edge emits, which is the kind of coupling that
// silently rots when one side is renamed.
func TestEdgeExpositionNamesMatchWhatTheScraperReads(t *testing.T) {
	m := edge.NewMetrics()
	m.Observe("shop/web", time.Millisecond, 200)
	var builder strings.Builder
	if _, err := m.WriteTo(&builder); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	body := builder.String()
	for _, name := range []string{
		"kanea_edge_requests_total",
		"kanea_edge_request_duration_ms_bucket",
		"kanea_edge_errors_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("the edge no longer emits %q, which the scraper reads:\n%s", name, body)
		}
	}
	if !strings.Contains(body, `service="shop/web"`) {
		t.Error(`the scraper keys on a "service" label the edge no longer sets`)
	}
	if !strings.Contains(body, `le="+Inf"`) {
		t.Error("no +Inf bucket; percentiles need a total to rank against")
	}
}
