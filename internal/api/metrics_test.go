package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/scaling"
	"github.com/kanea-dev/kanea/internal/store"
)

// withMetrics gives the harness a metrics store seeded by the test.
func withMetrics(seed func(*scaling.Metrics)) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		seed(m)
		cfg.Metrics = m
	}
}

func scrapeMetrics(t *testing.T, h *authHarness) string {
	t.Helper()
	req := h.request(t, http.MethodGet, api.PathMetrics, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET metrics = %d: %s", resp.StatusCode, body)
	}
	return body
}

func TestExporterRendersServiceAndAllocSeries(t *testing.T) {
	now := time.Now()
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 42)
		m.Record(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricCPU}, now, 43)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricRPS}, now, 120)
	}))

	body := scrapeMetrics(t, h)
	// A service subject and an alloc subject produce different label sets, so
	// a query can aggregate or drill down without parsing a compound string.
	if !strings.Contains(body, `kanea_cpu_percent{project="shop",service="web"} 42`) {
		t.Errorf("no service-level CPU sample:\n%s", body)
	}
	if !strings.Contains(body, `kanea_cpu_percent{project="shop",service="web",alloc="alloc-0"} 43`) {
		t.Errorf("no alloc-level CPU sample:\n%s", body)
	}
	if !strings.Contains(body, `kanea_requests_per_second{project="shop",service="web"} 120`) {
		t.Errorf("no rps sample:\n%s", body)
	}
	// Every family carries HELP and TYPE, which is what makes a scrape
	// self-describing rather than a wall of numbers.
	if !strings.Contains(body, "# HELP kanea_cpu_percent") ||
		!strings.Contains(body, "# TYPE kanea_cpu_percent gauge") {
		t.Errorf("missing HELP/TYPE:\n%s", body)
	}
}

func TestExporterOmitsSeriesWithNoRecentValue(t *testing.T) {
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		// Recorded long enough ago to have fallen out of the raw window.
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU},
			time.Now().Add(-2*scaling.RawWindow), 99)
	}))

	body := scrapeMetrics(t, h)
	// Prometheus treats a missing sample as missing; exporting a zero would be
	// a claim that the service is idle.
	if strings.Contains(body, "kanea_cpu_percent{") {
		t.Fatalf("a stale series was exported:\n%s", body)
	}
}

func TestExporterPublishesPlatformInternals(t *testing.T) {
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, time.Now(), 1)
	}))

	body := scrapeMetrics(t, h)
	// "Is the platform healthy" is a different question from "are the
	// workloads", and it is the one asked when the other numbers look wrong.
	for _, want := range []string{
		"kanea_metric_series ",
		"kanea_metric_series_dropped_total ",
		"kanea_audit_write_failures_total ",
		"kanea_requests_rate_limited_total ",
		"kanea_websocket_connections ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
}

func TestExporterReportsTheCircuitBreaker(t *testing.T) {
	b := reconciler.NewBreaker(reconciler.BreakerConfig{Threshold: 2})
	h := newAuthHarness(t,
		withMetrics(func(*scaling.Metrics) {}),
		func(cfg *api.ServerConfig) { cfg.Breaker = b })

	if body := scrapeMetrics(t, h); !strings.Contains(body, "kanea_circuit_breaker_open 0") {
		t.Fatalf("a closed breaker is not reported as closed:\n%s", body)
	}

	b.RecordFailure("shop/web")
	b.RecordFailure("shop/api")

	body := scrapeMetrics(t, h)
	if !strings.Contains(body, "kanea_circuit_breaker_open 1") {
		t.Errorf("an open breaker is not visible in the scrape:\n%s", body)
	}
	if !strings.Contains(body, "kanea_circuit_breaker_trips_total 1") {
		t.Errorf("trips are not counted:\n%s", body)
	}
}

func TestExporterNeedsAuthentication(t *testing.T) {
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}))

	// Request rates and replica counts describe how a business is doing.
	// §5.2.1's exemption list has two entries and this is not one of them.
	resp, body := h.do(t, h.request(t, http.MethodGet, api.PathMetrics, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", resp.StatusCode, body)
	}
}

func TestExporterIsUnavailableWithoutAPipeline(t *testing.T) {
	h := newAuthHarness(t) // no metrics configured
	req := h.request(t, http.MethodGet, api.PathMetrics, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))

	if resp, body := h.do(t, req); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", resp.StatusCode, body)
	}
}

func TestStatsTopicStreamsAServiceAndItsAllocs(t *testing.T) {
	now := time.Now()
	h := newHarness(t, func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 55)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricRPS}, now, 300)
		m.Record(scaling.Key{Subject: "shop/web/shop-web-0", Metric: scaling.MetricCPU}, now, 60)
		cfg.Metrics = m
	})
	// An alloc with a record but no samples yet: it must still appear, or a
	// freshly started alloc looks like it does not exist.
	rec := reconciler.AllocRecord{
		ID: "shop-web-0", Project: "shop", Service: "web", Index: 0,
		State: reconciler.AllocRunning,
	}
	if _, err := store.PutValue(context.Background(), h.store, store.KindAlloc, rec.Key(), rec); err != nil {
		t.Fatal(err)
	}
	second := reconciler.AllocRecord{
		ID: "shop-web-1", Project: "shop", Service: "web", Index: 1,
		State: reconciler.AllocPending,
	}
	if _, err := store.PutValue(context.Background(), h.store, store.KindAlloc, second.Key(), second); err != nil {
		t.Fatal(err)
	}

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicStats, Project: "shop", Service: "web"})

	frame := receive(t, conn)
	var sample api.StatsSample
	if err := json.Unmarshal(frame.Data, &sample); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if sample.CPU == nil || *sample.CPU != 55 {
		t.Errorf("service cpu = %v, want 55", sample.CPU)
	}
	if sample.RPS == nil || *sample.RPS != 300 {
		t.Errorf("service rps = %v, want 300", sample.RPS)
	}
	// "No data" is a gap, not a zero: a chart that draws them the same way
	// tells an operator a stopped scraper is an idle service.
	if sample.Memory != nil {
		t.Errorf("memory = %v, want absent — nothing was recorded", *sample.Memory)
	}
	if len(sample.Allocs) != 2 {
		t.Fatalf("allocs = %+v, want both records", sample.Allocs)
	}
	for _, alloc := range sample.Allocs {
		switch alloc.AllocID {
		case "shop-web-0":
			if alloc.CPU == nil || *alloc.CPU != 60 {
				t.Errorf("alloc cpu = %v, want 60", alloc.CPU)
			}
		case "shop-web-1":
			if alloc.CPU != nil {
				t.Errorf("an alloc with no samples reported cpu = %v", *alloc.CPU)
			}
		}
	}
}

func TestStatsTopicNeedsAServiceAndAPipeline(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.Metrics = scaling.NewMetrics(scaling.MetricsConfig{})
	})
	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()

	// Unscoped: the topic is per service, and a subscription for "everything"
	// would be every alloc on the node every five seconds.
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicStats})
	if frame := receive(t, conn); frame.Type != "error" {
		t.Fatalf("frame = %+v, want an error for an unscoped stats subscription", frame)
	}
}
