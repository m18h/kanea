package scaling_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// fakeFlows is a FlowSource a test can repoint between scrapes.
type fakeFlows struct {
	connects map[string]uint64
	drops    map[string]uint64
	err      error
}

func (f *fakeFlows) ServiceConnects(context.Context) (map[string]uint64, error) {
	return f.connects, f.err
}

func (f *fakeFlows) Drops(context.Context) (map[string]uint64, error) {
	return f.drops, f.err
}

// datapathHarness pairs the scraper with a source and a clock.
type datapathHarness struct {
	source  *fakeFlows
	scraper *scaling.DatapathScraper
	metrics *scaling.Metrics
	clock   *clock
}

func newDatapathHarness(t *testing.T) *datapathHarness {
	t.Helper()
	h := &datapathHarness{clock: newClock(), source: &fakeFlows{}}
	h.metrics = scaling.NewMetrics(scaling.MetricsConfig{Now: h.clock.now})
	scraper, err := scaling.NewDatapathScraper(scaling.DatapathConfig{
		Source: h.source, Metrics: h.metrics, Now: h.clock.now,
	})
	if err != nil {
		t.Fatalf("NewDatapathScraper: %v", err)
	}
	h.scraper = scraper
	return h
}

func (h *datapathHarness) scrape(t *testing.T) {
	t.Helper()
	if _, err := h.scraper.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
}

func (h *datapathHarness) latest(t *testing.T, subject, metric string) (float64, bool) {
	t.Helper()
	point, ok := h.metrics.Latest(scaling.Key{Subject: subject, Metric: metric})
	return point.Value, ok
}

func TestDatapathConnectsBecomeARate(t *testing.T) {
	h := newDatapathHarness(t)

	h.source.connects = map[string]uint64{"shop/web": 1000}
	h.scrape(t)
	// One reading of a cumulative counter is uptime, not a rate.
	if _, ok := h.latest(t, "shop/web", scaling.MetricFlows); ok {
		t.Fatal("a rate was reported from a single reading")
	}

	// 500 more connects over 5 seconds: 100 per second.
	h.clock.advance(5 * time.Second)
	h.source.connects = map[string]uint64{"shop/web": 1500}
	h.scrape(t)

	rate, ok := h.latest(t, "shop/web", scaling.MetricFlows)
	if !ok {
		t.Fatal("no flow rate after two readings")
	}
	if rate < 99.9 || rate > 100.1 {
		t.Fatalf("flows = %v/s, want 100", rate)
	}
}

func TestDatapathAttributesPerService(t *testing.T) {
	h := newDatapathHarness(t)

	h.source.connects = map[string]uint64{"shop/web": 100, "shop/api": 100}
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.source.connects = map[string]uint64{"shop/web": 200, "shop/api": 100}
	h.scrape(t)

	web, ok := h.latest(t, "shop/web", scaling.MetricFlows)
	if !ok || web < 19.9 || web > 20.1 {
		t.Fatalf("shop/web flows = %v, %v; want 20/s", web, ok)
	}
	// An idle service reads as a recorded zero, not a gap: "no data is never
	// zero" cuts both ways, and this service does have data.
	api, ok := h.latest(t, "shop/api", scaling.MetricFlows)
	if !ok || api != 0 {
		t.Fatalf("shop/api flows = %v, %v; want a recorded zero", api, ok)
	}
}

func TestDatapathUnattributableTrafficLandsOnTheNode(t *testing.T) {
	h := newDatapathHarness(t)

	// A source folds what it cannot attribute (a counter surviving from
	// before a pin rebuild, a drop toward no alloc) into the node subject. A
	// number nobody can break down is still worth having, so it is not lost.
	h.source.drops = map[string]uint64{scaling.NodeSubject: 100}
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.source.drops = map[string]uint64{scaling.NodeSubject: 600}
	h.scrape(t)

	rate, ok := h.latest(t, scaling.NodeSubject, scaling.MetricDrops)
	if !ok || rate < 99.9 || rate > 100.1 {
		t.Fatalf("node drops = %v, %v; want 100/s", rate, ok)
	}
}

func TestDatapathNodeTotalIncludesAttributedTraffic(t *testing.T) {
	h := newDatapathHarness(t)

	h.source.connects = map[string]uint64{"shop/web": 0, scaling.NodeSubject: 0}
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.source.connects = map[string]uint64{"shop/web": 250, scaling.NodeSubject: 250}
	h.scrape(t)

	// The node figure is what the whole datapath did, not just the leftovers.
	node, ok := h.latest(t, scaling.NodeSubject, scaling.MetricFlows)
	if !ok || node < 99.9 || node > 100.1 {
		t.Fatalf("node flows = %v, %v; want 100/s across both", node, ok)
	}
}

func TestDatapathDropsAreRecorded(t *testing.T) {
	h := newDatapathHarness(t)

	h.source.connects = map[string]uint64{"shop/web": 100}
	h.source.drops = map[string]uint64{"shop/web": 10}
	h.scrape(t)

	h.clock.advance(5 * time.Second)
	h.source.connects = map[string]uint64{"shop/web": 200}
	h.source.drops = map[string]uint64{"shop/web": 60}
	h.scrape(t)

	// Drops are their own signal: a service being denied is not a service
	// under load, and scaling it would add replicas that are denied too.
	drops, ok := h.latest(t, "shop/web", scaling.MetricDrops)
	if !ok || drops < 9.9 || drops > 10.1 {
		t.Fatalf("drops = %v, %v; want 10/s", drops, ok)
	}
}

func TestDatapathCounterResetRebaselines(t *testing.T) {
	h := newDatapathHarness(t)

	h.source.connects = map[string]uint64{"shop/web": 100000}
	h.scrape(t)

	// The pinned maps were recreated (a schema rebuild) and the counters
	// began again. There is no rate across that discontinuity.
	h.clock.advance(5 * time.Second)
	h.source.connects = map[string]uint64{"shop/web": 12}
	h.scrape(t)

	if rate, ok := h.latest(t, "shop/web", scaling.MetricFlows); ok {
		t.Fatalf("flows = %v recorded across a counter reset", rate)
	}
}

func TestDatapathScrapeReportsAFailure(t *testing.T) {
	h := newDatapathHarness(t)
	h.source.err = errors.New("map read failed")

	if _, err := h.scraper.Scrape(context.Background()); err == nil {
		t.Fatal("a failed counter read was reported as a successful scrape")
	}
}

func TestNewDatapathScraperRequiresItsInputs(t *testing.T) {
	m := scaling.NewMetrics(scaling.MetricsConfig{})
	if _, err := scaling.NewDatapathScraper(scaling.DatapathConfig{Metrics: m}); err == nil {
		t.Fatal("a scraper with nothing to read from was accepted")
	}
	if _, err := scaling.NewDatapathScraper(scaling.DatapathConfig{Source: &fakeFlows{}}); err == nil {
		t.Fatal("a scraper with nowhere to record was accepted")
	}
}
