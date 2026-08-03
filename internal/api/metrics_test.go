package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/scaling"
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
