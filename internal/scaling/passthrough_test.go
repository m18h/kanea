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

// The passthrough (PRD §9.1.1). Its one hard requirement is that it changes
// nothing about the family the autoscaler reads.

// servedBy stands an edge collector up behind an HTTP server and drives two
// rounds of traffic through it, scraping after each.
//
// Two rounds, with traffic in *both*. The first reading of a counter measures
// nothing but uptime, and a second reading with no traffic between measures a
// genuinely empty interval: the scraper then records no percentile and no
// error rate, correctly, because "no requests" is not "requests that were
// fast". A harness that scraped twice back to back would be asserting on that
// emptiness while looking like it was asserting on the traffic.
func servedBy(t *testing.T, m *edge.Metrics, traffic func()) (*scaling.EdgeExposition, *scaling.Metrics) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := m.WriteTo(w); err != nil {
			t.Errorf("WriteTo: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	held := scaling.NewEdgeExposition()
	metrics := scaling.NewMetrics(scaling.MetricsConfig{})
	scraper, err := scaling.NewEdgeScraper(scaling.EdgeConfig{
		URL: srv.URL, Metrics: metrics, Exposition: held,
	})
	if err != nil {
		t.Fatalf("NewEdgeScraper: %v", err)
	}
	for range 2 {
		traffic()
		if _, err := scraper.Scrape(context.Background()); err != nil {
			t.Fatalf("Scrape: %v", err)
		}
	}
	return held, metrics
}

// TestTheLabelledFamiliesNeverReachTheTimeSeries is the regression that
// matters. §9.1.1's whole design rests on it: the rings are capped and
// footprint-tested for the autoscaler's five series per service, and a
// per-code series in there would break the cap, break the footprint, and hand
// the evaluator forty numbers where its rule names one.
func TestTheLabelledFamiliesNeverReachTheTimeSeries(t *testing.T) {
	m := edge.NewMetrics()
	_, metrics := servedBy(t, m, func() {
		for code := 200; code < 230; code++ {
			m.Observe(edge.Observation{
				Service: "shop/web", Entrypoint: edge.EntrypointWebSecure,
				Status: code, Method: http.MethodGet, Protocol: edge.ProtocolHTTPS,
				Duration: time.Millisecond, RequestBytes: 10, ResponseBytes: 100,
			})
		}
	})

	// Exactly the five §9.1 metrics, and one subject each: the service. Not
	// one subject per status code, and no metric named after a label.
	for _, metric := range []string{
		scaling.MetricRPS, scaling.MetricP50, scaling.MetricP95,
		scaling.MetricP99, scaling.MetricErrorRate,
	} {
		subjects := metrics.Subjects(metric)
		if len(subjects) != 1 || subjects[0] != "shop/web" {
			t.Errorf("%s subjects = %v, want exactly [shop/web]", metric, subjects)
		}
	}
	// Thirty status codes produced thirty labelled series in the edge and must
	// have produced no extra series at all here.
	if got := metrics.Len(); got != 5 {
		t.Errorf("time series = %d, want 5: a labelled dimension leaked into the rings", got)
	}
}

func TestTheAggregateFamilyIsUnchangedByThePassthrough(t *testing.T) {
	m := edge.NewMetrics()
	_, metrics := servedBy(t, m, func() {
		for range 4 {
			m.Observe(edge.Observation{
				Service: "shop/web", Status: 200, Method: http.MethodGet,
				Protocol: edge.ProtocolHTTP, Duration: 10 * time.Millisecond,
			})
		}
		m.Observe(edge.Observation{
			Service: "shop/web", Status: 503, Method: http.MethodGet,
			Protocol: edge.ProtocolHTTP, Duration: 10 * time.Millisecond,
		})
	})

	// One 5xx in five requests. The evaluator reads this number directly, and
	// it must mean the same thing it did before the labels existed.
	point, ok := metrics.Latest(scaling.Key{Subject: "shop/web", Metric: scaling.MetricErrorRate})
	if !ok {
		t.Fatal("no error_rate recorded")
	}
	if point.Value != 20 {
		t.Errorf("error_rate = %v, want 20", point.Value)
	}
}

func TestRetainedBodyCarriesTheLabelledFamiliesAndNotTheAggregate(t *testing.T) {
	m := edge.NewMetrics()
	held, _ := servedBy(t, m, func() {
		m.Observe(edge.Observation{
			Service: "shop/web", Entrypoint: edge.EntrypointWeb,
			Status: 404, Method: http.MethodGet, Protocol: edge.ProtocolHTTP,
		})
	})

	body, at, ok := held.Snapshot()
	if !ok || at.IsZero() {
		t.Fatal("nothing was retained after a successful scrape")
	}
	for _, want := range []string{
		`kanea_edge_service_requests_total{service="shop/web",code="404"`,
		`kanea_edge_entrypoint_requests_total{entrypoint="web",code="404"}`,
		"# TYPE kanea_edge_service_requests_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("retained body is missing %q:\n%s", want, body)
		}
	}
	// The aggregate is the same traffic already counted once. Republishing
	// both would double every sum() a user writes over them.
	for _, unwanted := range []string{
		"kanea_edge_requests_total{",
		"kanea_edge_request_duration_ms_bucket{",
		"kanea_edge_errors_total{",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the aggregate family %q was republished, double-counting it:\n%s",
				unwanted, body)
		}
	}
}

func TestTypeCommentsTravelWithTheirFamily(t *testing.T) {
	m := edge.NewMetrics()
	m.Observe(edge.Observation{
		Service: "shop/web", Status: 200, Method: http.MethodGet, Protocol: edge.ProtocolHTTP,
	})
	held, _ := servedBy(t, m, func() {}) // traffic above; the passthrough is not differenced

	body, _, _ := held.Snapshot()
	// A counter exported without its TYPE is read as untyped, and rate() will
	// not compute over an untyped series: the metric would be present and
	// useless.
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, "kanea_edge_service_requests_total{") {
			continue
		}
		if !strings.Contains(body, "# TYPE kanea_edge_service_requests_total") {
			t.Fatal("a sample was retained without its TYPE comment")
		}
		return
	}
	t.Fatal("no labelled samples were retained at all")
}

func TestBreakdownFoldsAcrossMethodAndProtocol(t *testing.T) {
	m := edge.NewMetrics()
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		m.Observe(edge.Observation{
			Service: "shop/web", Status: 200, Method: method,
			Protocol: edge.ProtocolHTTPS, RequestBytes: 8, ResponseBytes: 64,
		})
	}
	m.Observe(edge.Observation{
		Service: "shop/web", Status: 502, Method: http.MethodGet, Protocol: edge.ProtocolHTTPS,
	})
	held, _ := servedBy(t, m, func() {}) // traffic above; the passthrough is not differenced

	breakdown, ok := held.Breakdown("shop/web")
	if !ok {
		t.Fatal("no breakdown for a service the edge reported")
	}
	// Three methods, one code: a status-code breakdown is what a dashboard
	// shows, and the finer split stays available in Prometheus.
	if breakdown.Codes["200"] != 3 {
		t.Errorf("200s = %v, want 3", breakdown.Codes["200"])
	}
	if breakdown.Codes["502"] != 1 {
		t.Errorf("502s = %v, want 1", breakdown.Codes["502"])
	}
	if breakdown.RequestBytes != 24 || breakdown.ResponseBytes != 192 {
		t.Errorf("bytes = %v/%v, want 24/192", breakdown.RequestBytes, breakdown.ResponseBytes)
	}
}

func TestBreakdownForgetsAServiceTheEdgeStoppedReporting(t *testing.T) {
	m := edge.NewMetrics()
	m.Observe(edge.Observation{
		Service: "shop/gone", Status: 200, Method: http.MethodGet, Protocol: edge.ProtocolHTTP,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := m.WriteTo(w); err != nil {
			t.Errorf("WriteTo: %v", err)
		}
	}))
	defer srv.Close()

	held := scaling.NewEdgeExposition()
	scraper, err := scaling.NewEdgeScraper(scaling.EdgeConfig{
		URL: srv.URL, Metrics: scaling.NewMetrics(scaling.MetricsConfig{}), Exposition: held,
	})
	if err != nil {
		t.Fatalf("NewEdgeScraper: %v", err)
	}
	if _, err := scraper.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if _, ok := held.Breakdown("shop/gone"); !ok {
		t.Fatal("the first scrape recorded no breakdown")
	}

	// The service leaves the route table. Set replaces rather than merges, or
	// its totals stay visible for the life of the process: the same leak
	// edge.Metrics.Retain prevents on the other side of the wire.
	m.Retain(map[string]bool{})
	if _, err := scraper.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if _, ok := held.Breakdown("shop/gone"); ok {
		t.Error("a departed service's breakdown survived the next scrape")
	}
}

func TestSnapshotIsNotOkBeforeTheFirstScrape(t *testing.T) {
	// The exporter turns this into kanea_edge_up 0. Without it a gap in the
	// labelled families has two causes (the edge is down, or nothing is
	// exposed) and they are indistinguishable.
	held := scaling.NewEdgeExposition()
	if _, _, ok := held.Snapshot(); ok {
		t.Error("an unscraped holder reported a snapshot")
	}
	if _, ok := held.Breakdown("shop/web"); ok {
		t.Error("an unscraped holder reported a breakdown")
	}
}

// A nil holder is what a node with no exporter has. Every method must tolerate
// it, or wiring the exporter becomes mandatory to run the autoscaler.
func TestANilExpositionIsUsable(t *testing.T) {
	var held *scaling.EdgeExposition
	held.Set("", time.Now(), nil)
	if _, _, ok := held.Snapshot(); ok {
		t.Error("a nil holder reported a snapshot")
	}
	if _, ok := held.Breakdown("shop/web"); ok {
		t.Error("a nil holder reported a breakdown")
	}
	if held.Truncated() {
		t.Error("a nil holder reported truncation")
	}
}
