package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
)

// allocSeedWindowForTest mirrors the unexported allocSeedWindow: the tests are
// in package api_test, and the budget behaviour is only reachable by filling
// that window.
const allocSeedWindowForTest = 5 * time.Minute

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
	store := scaling.NewMetrics(scaling.MetricsConfig{})
	for i := range 20 {
		subject := fmt.Sprintf("shop/svc-%d", i)
		for at := now.Add(-10 * time.Minute); !at.After(now); at = at.Add(scaling.RawInterval) {
			store.Record(scaling.Key{Subject: subject, Metric: scaling.MetricRPS}, at, 10)
			store.Record(scaling.Key{Subject: subject, Metric: scaling.MetricP95}, at, 20)
		}
	}
	counting := &countingMetrics{Metrics: store}
	// A frozen clock, because the cache is keyed on the slot the range ends at
	// and a real one rolls the slot over mid-test under -race: the recompute
	// that follows is correct behaviour and would read here as a broken cache.
	h := newAuthHarness(t, func(cfg *api.ServerConfig) {
		cfg.Metrics = counting
		cfg.Now = func() time.Time { return now }
	})

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
	store := scaling.NewMetrics(scaling.MetricsConfig{})
	for _, subject := range []string{"shop/web", "shop/api"} {
		store.Record(scaling.Key{Subject: subject, Metric: scaling.MetricRPS}, now, 10)
	}
	h := newAuthHarness(t, func(cfg *api.ServerConfig) { cfg.Metrics = store })

	status, out := getHistory(t, h, "")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if len(out.Series["rps"]) == 0 || out.Series["rps"][0].Value != 20 {
		t.Fatalf("rps = %+v, want a single summed point of 20", out.Series["rps"])
	}

	store.Forget("shop/api")

	// A different slot, so this is the subject cache being invalidated rather
	// than the aggregate memo simply expiring.
	_, out = getHistory(t, h, "?window=2m")
	if len(out.Series["rps"]) == 0 || out.Series["rps"][0].Value != 10 {
		t.Fatalf("rps = %+v after forgetting one service, want 10: a forgotten "+
			"series is still being summed", out.Series["rps"])
	}
}

func TestThePreV179RequestIsUnchanged(t *testing.T) {
	// The v1.79 additions are a series selector and a per-alloc half, both
	// opt-in. A request that names neither must produce exactly the keys it
	// always did: the default sets are what v1.38 and v1.42 shipped, and the
	// embedded block is embedded precisely so the field order does not move.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 1)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricFlows}, now, 9)
		m.Record(scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeLoad1}, now, 2)
	}))

	for _, tc := range []struct {
		name  string
		query string
		want  []string
	}{
		{"node view", "", []string{"cpu", "gpu_vram", "memory", "p95_latency_ms", "rps"}},
		{"service view", "?project=shop&service=web", []string{"cpu", "memory", "p95_latency_ms", "rps"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, out := getHistory(t, h, tc.query)
			if status != http.StatusOK {
				t.Fatalf("history = %d", status)
			}
			var got []string
			for name := range out.Series {
				got = append(got, name)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("series = %v, want %v: the default set moved, so a client "+
					"that named nothing is getting different bytes", got, tc.want)
			}
			if out.Allocs != nil || out.AllocsOmitted {
				t.Error("the alloc half appeared without being asked for")
			}
		})
	}
}

func TestHistoryServesTheSelectedSeries(t *testing.T) {
	// The selector is what makes the six recorded-but-unexposed series
	// reachable without enlarging the frame everyone else gets (v1.79).
	now := time.Now().Truncate(scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricErrorRate}, now, 3)
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricFlows}, now, 7)
	}))

	status, out := getHistory(t, h, "?project=shop&service=web&series=error_rate,flows_per_second")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if len(out.Series) != 2 {
		t.Fatalf("series = %v, want exactly the two named", out.Series)
	}
	if len(out.Series["error_rate"]) == 0 || out.Series["error_rate"][0].Value != 3 {
		t.Errorf("error_rate = %+v, want a point of 3", out.Series["error_rate"])
	}
	if len(out.Series["flows_per_second"]) == 0 || out.Series["flows_per_second"][0].Value != 7 {
		t.Errorf("flows_per_second = %+v, want a point of 7", out.Series["flows_per_second"])
	}
}

func TestHistoryRefusesAnUnknownSeriesByName(t *testing.T) {
	// Refused rather than dropped: a chart seeded with nothing looks exactly
	// like a service that has served nothing, so a typo would read as an outage.
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}))

	req := h.request(t, http.MethodGet,
		api.PathStatsHistory+"?project=shop&service=web&series=cpu,cpu_percent", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("history = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "cpu_percent") {
		t.Errorf("the refusal does not name the series that was wrong: %s", body)
	}
}

func TestTheNodeViewSumsUnattributedTrafficIntoTheTotal(t *testing.T) {
	// The datapath records east-west traffic it cannot attribute under the node
	// subject. A node total that summed only services would be missing exactly
	// the traffic nobody could account for.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricFlows}, now, 10)
		m.Record(scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricFlows}, now, 5)
	}))

	status, out := getHistory(t, h, "?series=flows_per_second")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	points := out.Series["flows_per_second"]
	if len(points) == 0 || points[0].Value != 15 {
		t.Fatalf("flows = %+v, want 15 (10 attributed + 5 not)", points)
	}
}

// putAlloc seeds one alloc record.
func putAlloc(t *testing.T, h *authHarness, id, project, service string, index int) {
	t.Helper()
	rec := reconciler.AllocRecord{
		ID: id, Project: project, Service: service, Index: index,
		State: reconciler.AllocRunning,
	}
	if _, err := store.PutValue(context.Background(), h.store, store.KindAlloc, rec.Key(), rec); err != nil {
		t.Fatalf("put alloc: %v", err)
	}
}

func TestHistorySeedsThePerAllocSeries(t *testing.T) {
	// The allocs table's sparklines had no seedable route at all before v1.79:
	// the ranged read served service-level subjects while the rings key allocs
	// as project/service/<alloc>, so every row accumulated from empty.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		m.Record(scaling.Key{Subject: "shop/web/shop-web-0", Metric: scaling.MetricCPU}, now, 60)
		m.Record(scaling.Key{Subject: "shop/web/shop-web-0", Metric: scaling.MetricMemoryBytes}, now, 1024)
	}))
	putAlloc(t, h, "shop-web-0", "shop", "web", 0)

	status, out := getHistory(t, h, "?project=shop&service=web&allocs=true")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	block, ok := out.Allocs["shop-web-0"]
	if !ok {
		t.Fatalf("no alloc block: %+v", out.Allocs)
	}
	if len(block.Series["cpu"]) == 0 || block.Series["cpu"][0].Value != 60 {
		t.Errorf("alloc cpu = %+v, want a point of 60", block.Series["cpu"])
	}
	if len(block.Series["memory_bytes"]) == 0 {
		t.Error("alloc memory_bytes was not seeded")
	}
}

func TestAnAllocWithNoSamplesStillAppearsInTheSeed(t *testing.T) {
	// The alloc set comes from the Store, not from the ring's key space, for
	// the reason statsFor already gives: an alloc that started a second ago has
	// a record and no samples. It also keeps the seed's alloc set identical to
	// the live sample's, so nothing seeds a row the live frames never feed.
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}))
	putAlloc(t, h, "shop-web-0", "shop", "web", 0)

	status, out := getHistory(t, h, "?project=shop&service=web&allocs=true")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if _, ok := out.Allocs["shop-web-0"]; !ok {
		t.Fatalf("an alloc with a record and no samples was left out: %+v", out.Allocs)
	}
}

func TestTheAllocHalfIsOmittedWholeNeverTruncated(t *testing.T) {
	// Truncating it to a shorter window would put two windows in one payload,
	// and a client rebuilding slots against the wrong interval draws a *wrong*
	// chart rather than no chart. Dropped whole, and said to be dropped.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		for i := range 40 {
			subject := fmt.Sprintf("shop/web/shop-web-%d", i)
			for at := now.Add(-allocSeedWindowForTest); !at.After(now); at = at.Add(scaling.RawInterval) {
				m.Record(scaling.Key{Subject: subject, Metric: scaling.MetricCPU}, at, 1)
			}
		}
	}))
	for i := range 40 {
		putAlloc(t, h, fmt.Sprintf("shop-web-%d", i), "shop", "web", i)
	}

	status, out := getHistory(t, h, "?project=shop&service=web&allocs=true")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if !out.AllocsOmitted {
		t.Fatalf("forty allocs fit the budget without being flagged: %d blocks", len(out.Allocs))
	}
	if len(out.Allocs) != 0 {
		t.Errorf("the alloc half was truncated to %d blocks rather than dropped whole", len(out.Allocs))
	}
	// The service half is unaffected: the budget drops the extra, not the ask.
	if len(out.Series) == 0 {
		t.Error("the service series went missing with the alloc half")
	}
}

func TestTheNodeViewHasNoAllocHalf(t *testing.T) {
	// A node view has no service to break down, so the flag is meaningless
	// there rather than an error: nothing is dropped, so nothing is flagged.
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}))
	putAlloc(t, h, "shop-web-0", "shop", "web", 0)

	status, out := getHistory(t, h, "?allocs=true")
	if status != http.StatusOK {
		t.Fatalf("history = %d", status)
	}
	if out.Allocs != nil || out.AllocsOmitted {
		t.Errorf("the node view produced an alloc half: %+v", out.Allocs)
	}
}
