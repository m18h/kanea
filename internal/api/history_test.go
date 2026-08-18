package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/scaling"
)

func getHistory(t *testing.T, h *authHarness, query string) (int, api.HistoryResponse) {
	t.Helper()
	req := h.request(t, http.MethodGet, api.PathStatsHistory+query, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)
	var out api.HistoryResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("history response: %v\n%s", err, body)
		}
	}
	return resp.StatusCode, out
}

func TestHistoryServesAServiceRange(t *testing.T) {
	now := time.Now()
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now.Add(-10*time.Second), 40)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 42)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricRPS}, now, 120)
	}))

	status, out := getHistory(t, h, "?project=shop&service=web")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if out.Subject != "shop/web" {
		t.Errorf("subject = %q", out.Subject)
	}
	if out.IntervalSeconds != int(scaling.RawInterval/time.Second) {
		t.Errorf("interval = %d, want the raw tier's", out.IntervalSeconds)
	}
	if got := len(out.Series["cpu"]); got != 2 {
		t.Errorf("cpu points = %d, want 2", got)
	}
	if got := len(out.Series["rps"]); got != 1 {
		t.Errorf("rps points = %d, want 1", got)
	}
	// p95 was never recorded: the key must still be present (a chart needs to
	// know it was asked for) and empty (nothing was measured).
	if got := len(out.Series["p95_latency_ms"]); got != 0 {
		t.Errorf("p95 points = %d, want 0", got)
	}
}

func TestHistoryServesAGapAsAbsentNeverZero(t *testing.T) {
	// Two samples two slots apart: the slot between them was never written,
	// and the response must simply not contain it; a zero there would be a
	// claim that the service went idle for five seconds.
	now := time.Now()
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU},
			now.Add(-2*scaling.RawInterval), 40)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 44)
	}))

	status, out := getHistory(t, h, "?project=shop&service=web")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	points := out.Series["cpu"]
	if len(points) != 2 {
		t.Fatalf("cpu points = %d, want 2 (the gap must be absent)", len(points))
	}
	for _, p := range points {
		if p.Value == 0 {
			t.Errorf("a gap was serialised as zero at %v", p.At)
		}
	}
}

func TestHistoryNodeViewSumsAcrossServices(t *testing.T) {
	// Two services with rps at the same instant sum; a slot only one has is
	// that one's value alone, not "the other was zero". Alloc-level subjects
	// must not leak into the sum.
	now := time.Now().Truncate(scaling.RawInterval)
	earlier := now.Add(-2 * scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricRPS}, earlier, 100)
		m.Record(scaling.Key{Subject: "shop/api", Metric: scaling.MetricRPS}, earlier, 20)
		m.Record(scaling.Key{Subject: "shop/api", Metric: scaling.MetricRPS}, now, 30)
		m.Record(scaling.Key{Subject: "shop/api/alloc-0", Metric: scaling.MetricRPS}, now, 999)
	}))

	status, out := getHistory(t, h, "")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if out.Subject != scaling.NodeSubject {
		t.Errorf("subject = %q", out.Subject)
	}
	points := out.Series["rps"]
	if len(points) != 2 {
		t.Fatalf("rps points = %d, want 2: %+v", len(points), points)
	}
	if points[0].Value != 120 {
		t.Errorf("summed slot = %v, want 120", points[0].Value)
	}
	if points[1].Value != 30 {
		t.Errorf("lone slot = %v, want 30 (not a sum with an invented zero)", points[1].Value)
	}
}

func TestHistoryNodeViewServesTheRecordedNodeSeries(t *testing.T) {
	now := time.Now()
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		cpu, mem, vram := 38.0, 61.5, 42.0
		scaling.RecordNode(m, scaling.NodeStats{
			CPUPercent: &cpu, MemoryPercent: &mem, GPUVRAMPercent: &vram, At: now,
		})
	}))

	status, out := getHistory(t, h, "")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if got := len(out.Series["cpu"]); got != 1 {
		t.Errorf("node cpu points = %d, want 1", got)
	}
	if got := len(out.Series["memory"]); got != 1 {
		t.Errorf("node memory points = %d, want 1", got)
	}
	if got := len(out.Series["gpu_vram"]); got != 1 {
		t.Errorf("node gpu points = %d, want 1", got)
	}
}

func TestHistoryRefusesBadParameters(t *testing.T) {
	// One harness for all three refusals: the harness is the expensive part
	// (bcrypt under -race), and these cases share everything but the query.
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}))
	if status, _ := getHistory(t, h, "?project=shop"); status != http.StatusBadRequest {
		t.Errorf("project without service = %d, want 400", status)
	}
	if status, _ := getHistory(t, h, "?service=web"); status != http.StatusBadRequest {
		t.Errorf("service without project = %d, want 400", status)
	}
	if status, _ := getHistory(t, h, "?window=yesterday"); status != http.StatusBadRequest {
		t.Errorf("garbage window = %d, want 400", status)
	}
}

func TestHistoryAnswers503WithoutAMetricsStore(t *testing.T) {
	h := newAuthHarness(t)
	if status, _ := getHistory(t, h, ""); status != http.StatusServiceUnavailable {
		t.Errorf("no metrics store = %d, want 503", status)
	}
}

func TestNodeRecorderRecordsOnlyWhatWasRead(t *testing.T) {
	m := scaling.NewMetrics(scaling.MetricsConfig{})
	// A first read has no CPU delta: nothing must be recorded for it.
	mem := 40.0
	scaling.RecordNode(m, scaling.NodeStats{MemoryPercent: &mem, At: time.Now()})

	now := time.Now()
	cpuKey := scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeCPU}
	memKey := scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeMemory}
	if points := m.Range(cpuKey, now.Add(-time.Minute), now); len(points) != 0 {
		t.Errorf("a nil cpu reading was recorded: %+v", points)
	}
	if points := m.Range(memKey, now.Add(-time.Minute), now.Add(time.Minute)); len(points) != 1 {
		t.Errorf("memory points = %d, want 1", len(points))
	}
}

func TestAnHourWindowDoesNotAdvertiseFiveSecondPoints(t *testing.T) {
	// The v1.79 regression, and it needs a real clock: the handler captured
	// `to` and Range then read the clock again, so a window of exactly
	// RawWindow missed the raw tier by however long the handler had taken.
	// The rollup answered at a minute while interval_seconds promised five,
	// and the client placed every point in the wrong slot.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		// Two hours of samples so both tiers hold something and the choice of
		// tier is visible in the spacing rather than in an empty answer.
		for at := now.Add(-2 * time.Hour); !at.After(now); at = at.Add(scaling.RawInterval) {
			m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, at, 50)
		}
	}))

	status, out := getHistory(t, h, "?project=shop&service=web&window=1h")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}

	points := out.Series["cpu"]
	if len(points) < 2 {
		t.Fatalf("cpu points = %d; too few to measure a spacing", len(points))
	}
	spacing := points[1].At.Sub(points[0].At)
	if want := time.Duration(out.IntervalSeconds) * time.Second; spacing != want {
		t.Fatalf("advertised interval_seconds=%d (%v) but the points are %v apart: "+
			"a client rebuilding slots against the advertised interval draws the "+
			"chart at the wrong scale", out.IntervalSeconds, want, spacing)
	}
}

func TestTheHistoryRangeIsSlotAligned(t *testing.T) {
	// Untruncated, every response covered a different fraction of a slot at
	// each end, so no two were comparable and the aggregate cache could not be
	// keyed on the range at all (v1.79).
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, time.Now(), 1)
	}))

	status, out := getHistory(t, h, "?project=shop&service=web")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if !out.To.Equal(out.To.Truncate(scaling.RawInterval)) {
		t.Errorf("to = %v is not on a raw slot boundary", out.To)
	}
	if !out.From.Equal(out.From.Truncate(scaling.RawInterval)) {
		t.Errorf("from = %v is not on a raw slot boundary", out.From)
	}
}

// countingMetrics wraps a real store and counts the calls the node aggregates
// are expensive in: the key-space scan and the per-series ring walk.
type countingMetrics struct {
	*scaling.Metrics
	mu       sync.Mutex
	subjects int
	ranges   int
}

func (c *countingMetrics) Subjects(metric string) []string {
	c.mu.Lock()
	c.subjects++
	c.mu.Unlock()
	return c.Metrics.Subjects(metric)
}

func (c *countingMetrics) Range(key scaling.Key, from, to time.Time) []scaling.Point {
	c.mu.Lock()
	c.ranges++
	c.mu.Unlock()
	return c.Metrics.Range(key, from, to)
}

func (c *countingMetrics) counts() (subjects, ranges int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.subjects, c.ranges
}

func TestTheNodeAggregatesAreComputedOncePerSlot(t *testing.T) {
	// Every node-view request summed rps across every service and walked every
	// series twice more for the weighted p95, plus two scans of the whole key
	// space (v1.79). One Overview subscriber per five seconds is fine; N of
	// them is the cost K-18 removed from the stats feed, reappearing here.
	now := time.Now().Truncate(scaling.RawInterval)
	real := scaling.NewMetrics(scaling.MetricsConfig{})
	for i := range 20 {
		subject := fmt.Sprintf("shop/svc-%d", i)
		for at := now.Add(-10 * time.Minute); !at.After(now); at = at.Add(scaling.RawInterval) {
			real.Record(scaling.Key{Subject: subject, Metric: scaling.MetricRPS}, at, 10)
			real.Record(scaling.Key{Subject: subject, Metric: scaling.MetricP95}, at, 20)
		}
	}
	counting := &countingMetrics{Metrics: real}
	h := newAuthHarness(t, func(cfg *api.ServerConfig) { cfg.Metrics = counting })

	// Warm the memo, then measure only what the repeats cost.
	if status, _ := getHistory(t, h, ""); status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	subjectsAfterFirst, rangesAfterFirst := counting.counts()

	for range 9 {
		if status, _ := getHistory(t, h, ""); status != http.StatusOK {
			t.Fatal("history failed on a repeat")
		}
	}
	subjects, ranges := counting.counts()

	// The node's own three series are read directly and are not aggregates, so
	// they are expected to repeat; the aggregates are not.
	if grew := ranges - rangesAfterFirst; grew > 9*3 {
		t.Errorf("nine repeat requests cost %d extra ring walks (first request: %d); "+
			"the aggregates are being recomputed per request", grew, rangesAfterFirst)
	}
	if grew := subjects - subjectsAfterFirst; grew != 0 {
		t.Errorf("nine repeat requests cost %d extra key-space scans; the subject "+
			"set cannot change without the series epoch moving", grew)
	}
}

func TestForgettingASeriesInvalidatesTheSubjectCache(t *testing.T) {
	// The epoch is what makes the subject cache safe to hold: a service that
	// goes away must stop being summed, and nothing about time says it has.
	now := time.Now().Truncate(scaling.RawInterval)
	real := scaling.NewMetrics(scaling.MetricsConfig{})
	for _, subject := range []string{"shop/web", "shop/api"} {
		real.Record(scaling.Key{Subject: subject, Metric: scaling.MetricRPS}, now, 10)
	}
	h := newAuthHarness(t, func(cfg *api.ServerConfig) { cfg.Metrics = real })

	status, out := getHistory(t, h, "")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if len(out.Series["rps"]) == 0 || out.Series["rps"][0].Value != 20 {
		t.Fatalf("rps = %+v, want a single summed point of 20", out.Series["rps"])
	}

	real.Forget("shop/api")

	// A different slot, so this is the subject cache being invalidated rather
	// than the aggregate memo simply expiring.
	_, out = getHistory(t, h, "?window=2m")
	if len(out.Series["rps"]) == 0 || out.Series["rps"][0].Value != 10 {
		t.Fatalf("rps = %+v after forgetting one service, want 10: a forgotten "+
			"series is still being summed", out.Series["rps"])
	}
}
