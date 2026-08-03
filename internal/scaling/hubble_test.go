package scaling_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/scaling"
)

// hubbleHarness serves a body a test can swap between scrapes.
type hubbleHarness struct {
	body    string
	scraper *scaling.HubbleScraper
	metrics *scaling.Metrics
	clock   *clock
}

func newHubbleHarness(t *testing.T) *hubbleHarness {
	t.Helper()
	h := &hubbleHarness{clock: newClock()}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(h.body)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	h.metrics = scaling.NewMetrics(scaling.MetricsConfig{Now: h.clock.now})
	scraper, err := scaling.NewHubbleScraper(scaling.HubbleConfig{
		URL: server.URL, Metrics: h.metrics, Now: h.clock.now,
	})
	if err != nil {
		t.Fatalf("NewHubbleScraper: %v", err)
	}
	h.scraper = scraper
	return h
}

func (h *hubbleHarness) scrape(t *testing.T) {
	t.Helper()
	if _, err := h.scraper.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
}

func (h *hubbleHarness) latest(t *testing.T, subject, metric string) (float64, bool) {
	t.Helper()
	point, ok := h.metrics.Latest(scaling.Key{Subject: subject, Metric: metric})
	return point.Value, ok
}

// flowLine renders one hubble_flows_processed_total series. The destination
// label carries the identity's labels comma-joined, which is how Hubble renders
// a label context — and where Kanea's own project/service labels appear.
func flowLine(destination string, verdict string, value float64) string {
	return fmt.Sprintf(
		"hubble_flows_processed_total{destination=%q,protocol=\"TCP\",subtype=\"to-endpoint\","+
			"type=\"Trace\",verdict=%q} %g\n", destination, verdict, value)
}

func dropLine(destination string, value float64) string {
	return fmt.Sprintf("hubble_drop_total{destination=%q,reason=\"POLICY_DENIED\"} %g\n",
		destination, value)
}

// kaneaLabels is the label set the network driver attaches to an endpoint.
const kaneaLabels = "k8s:io.kubernetes.pod.namespace=shop,managed=true,project=shop,service=web"

func TestHubbleFlowsBecomeARate(t *testing.T) {
	h := newHubbleHarness(t)

	h.body = flowLine(kaneaLabels, "FORWARDED", 1000)
	h.scrape(t)
	// One reading of a cumulative counter is uptime, not a rate.
	if _, ok := h.latest(t, "shop/web", scaling.MetricFlows); ok {
		t.Fatal("a rate was reported from a single reading")
	}

	// 500 more flows over 5 seconds: 100 per second.
	h.clock.advance(5 * time.Second)
	h.body = flowLine(kaneaLabels, "FORWARDED", 1500)
	h.scrape(t)

	rate, ok := h.latest(t, "shop/web", scaling.MetricFlows)
	if !ok {
		t.Fatal("no flow rate after two readings")
	}
	if rate < 99.9 || rate > 100.1 {
		t.Fatalf("flows = %v/s, want 100", rate)
	}
}

func TestHubbleSumsTheSeriesOfOneService(t *testing.T) {
	h := newHubbleHarness(t)

	// Hubble emits one series per label combination. A service's traffic is the
	// sum across them, or a busy service looks idle because its flows were
	// split across four verdicts.
	h.body = flowLine(kaneaLabels, "FORWARDED", 100) + flowLine(kaneaLabels, "DROPPED", 100)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.body = flowLine(kaneaLabels, "FORWARDED", 200) + flowLine(kaneaLabels, "DROPPED", 150)
	h.scrape(t)

	// 100 + 50 new flows over 5 s = 30/s.
	rate, ok := h.latest(t, "shop/web", scaling.MetricFlows)
	if !ok || rate < 29.9 || rate > 30.1 {
		t.Fatalf("flows = %v, %v; want 30/s summed across verdicts", rate, ok)
	}
}

func TestHubbleAttributesByDestination(t *testing.T) {
	h := newHubbleHarness(t)
	other := "k8s:io.kubernetes.pod.namespace=shop,managed=true,project=shop,service=api"

	// A service is loaded by what arrives at it, not by what it sends.
	h.body = flowLine(kaneaLabels, "FORWARDED", 100) + flowLine(other, "FORWARDED", 100)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.body = flowLine(kaneaLabels, "FORWARDED", 200) + flowLine(other, "FORWARDED", 100)
	h.scrape(t)

	web, ok := h.latest(t, "shop/web", scaling.MetricFlows)
	if !ok || web < 19.9 || web > 20.1 {
		t.Fatalf("shop/web flows = %v, %v; want 20/s", web, ok)
	}
	api, ok := h.latest(t, "shop/api", scaling.MetricFlows)
	if !ok || api != 0 {
		t.Fatalf("shop/api flows = %v, %v; want a recorded zero", api, ok)
	}
}

func TestHubbleUnattributableTrafficLandsOnTheNode(t *testing.T) {
	h := newHubbleHarness(t)

	// Traffic to the world, or an agent configured with no label context. A
	// number nobody can break down is still worth having, so it is not dropped.
	h.body = flowLine("reserved:world", "FORWARDED", 100)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.body = flowLine("reserved:world", "FORWARDED", 600)
	h.scrape(t)

	rate, ok := h.latest(t, "node", scaling.MetricFlows)
	if !ok || rate < 99.9 || rate > 100.1 {
		t.Fatalf("node flows = %v, %v; want 100/s", rate, ok)
	}
}

func TestHubbleNodeTotalIncludesAttributedTraffic(t *testing.T) {
	h := newHubbleHarness(t)

	h.body = flowLine(kaneaLabels, "FORWARDED", 0) + flowLine("reserved:world", "FORWARDED", 0)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.body = flowLine(kaneaLabels, "FORWARDED", 250) + flowLine("reserved:world", "FORWARDED", 250)
	h.scrape(t)

	// The node figure is what the whole datapath did, not just the leftovers.
	node, ok := h.latest(t, "node", scaling.MetricFlows)
	if !ok || node < 99.9 || node > 100.1 {
		t.Fatalf("node flows = %v, %v; want 100/s across both", node, ok)
	}
}

func TestHubbleDropsAreRecorded(t *testing.T) {
	h := newHubbleHarness(t)

	h.body = flowLine(kaneaLabels, "FORWARDED", 100) + dropLine(kaneaLabels, 10)
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.body = flowLine(kaneaLabels, "FORWARDED", 200) + dropLine(kaneaLabels, 60)
	h.scrape(t)

	// Policy drops are their own signal: a service being denied is not a
	// service under load, and scaling it would add replicas that are denied too.
	drops, ok := h.latest(t, "shop/web", scaling.MetricDrops)
	if !ok || drops < 9.9 || drops > 10.1 {
		t.Fatalf("drops = %v, %v; want 10/s", drops, ok)
	}
}

// The failure M0 spike ① went out of its way to document: `--hubble-metrics`
// takes a space-separated list inside one value, and both a comma-separated
// list and a repeated flag are accepted silently — leaving an endpoint that
// serves 200 OK with nothing in it.
func TestHubbleReportsAnEndpointWithNoFlowData(t *testing.T) {
	h := newHubbleHarness(t)
	// What a misconfigured agent actually serves: its own process metrics, and
	// no flow family at all.
	h.body = "# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines 41\n"

	_, err := h.scraper.Scrape(context.Background())
	if !errors.Is(err, scaling.ErrHubbleNoFlows) {
		t.Fatalf("err = %v, want ErrHubbleNoFlows — a 200 with no flows is the silent case", err)
	}
	// Distinguishable from a dead endpoint, because the remedies are opposite:
	// one is "start Hubble", the other is "fix the flag you already set".
	if err != nil && strings.Contains(err.Error(), "connection refused") {
		t.Error("a misconfiguration was reported as an unreachable endpoint")
	}
}

func TestHubbleDropsOnlyIsStillFlowless(t *testing.T) {
	h := newHubbleHarness(t)
	// `--hubble-metrics=drop` alone is a legitimate configuration but not one
	// this scraper can compute a flow rate from, and saying so beats reporting
	// zero traffic on a busy node.
	h.body = dropLine(kaneaLabels, 5)

	if _, err := h.scraper.Scrape(context.Background()); !errors.Is(err, scaling.ErrHubbleNoFlows) {
		t.Fatalf("err = %v, want ErrHubbleNoFlows", err)
	}
}

func TestHubbleAgentRestartRebaselines(t *testing.T) {
	h := newHubbleHarness(t)

	h.body = flowLine(kaneaLabels, "FORWARDED", 100000)
	h.scrape(t)

	// cilium-agent restarted and its counters began again.
	h.clock.advance(5 * time.Second)
	h.body = flowLine(kaneaLabels, "FORWARDED", 12)
	h.scrape(t)

	if rate, ok := h.latest(t, "shop/web", scaling.MetricFlows); ok {
		t.Fatalf("flows = %v recorded across a counter reset", rate)
	}
}

func TestHubbleScrapeReportsAFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	c := newClock()
	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, err := scaling.NewHubbleScraper(scaling.HubbleConfig{URL: server.URL, Metrics: m, Now: c.now})
	if err != nil {
		t.Fatalf("NewHubbleScraper: %v", err)
	}
	if _, err := s.Scrape(context.Background()); err == nil {
		t.Fatal("a 503 was reported as a successful scrape")
	}
}

func TestNewHubbleScraperRequiresAStore(t *testing.T) {
	if _, err := scaling.NewHubbleScraper(scaling.HubbleConfig{}); err == nil {
		t.Fatal("a scraper with nowhere to record was accepted")
	}
}
