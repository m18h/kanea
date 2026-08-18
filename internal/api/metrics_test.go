package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
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
		t.Errorf("memory = %v, want absent; nothing was recorded", *sample.Memory)
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

// The passthrough and backend health (PRD §9.1.1).

// fakeEdgeExposition stands in for scaling.EdgeExposition.
type fakeEdgeExposition struct {
	body      string
	at        time.Time
	ok        bool
	breakdown map[string]scaling.ServiceBreakdown
}

func (f *fakeEdgeExposition) Snapshot() (string, time.Time, bool) {
	return f.body, f.at, f.ok
}

func (f *fakeEdgeExposition) Breakdown(service string) (scaling.ServiceBreakdown, bool) {
	b, ok := f.breakdown[service]
	return b, ok
}

func withEdgeMetrics(f *fakeEdgeExposition) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.EdgeMetrics = f }
}

func TestExporterRepublishesTheEdgesLabelledFamilies(t *testing.T) {
	held := &fakeEdgeExposition{
		ok: true, at: time.Now(),
		body: `# TYPE kanea_edge_service_requests_total counter
kanea_edge_service_requests_total{service="shop/web",code="502",method="GET",protocol="https"} 3
`,
	}
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}), withEdgeMetrics(held))

	body := scrapeMetrics(t, h)
	// Verbatim. There is nothing to compute, so a parse-and-re-serialise round
	// trip could only introduce a discrepancy between what the edge measured
	// and what an operator reads.
	if !strings.Contains(body, held.body) {
		t.Errorf("the retained exposition was not republished as-is:\n%s", body)
	}
	if !strings.Contains(body, "kanea_edge_up 1") {
		t.Errorf("a fresh scrape did not report the edge as up:\n%s", body)
	}
}

func TestExporterReportsTheEdgeDown(t *testing.T) {
	for _, tc := range []struct {
		name string
		held *fakeEdgeExposition
	}{
		{"never scraped", &fakeEdgeExposition{}},
		{"stale", &fakeEdgeExposition{ok: true, at: time.Now().Add(-time.Hour), body: "x 1\n"}},
		{"not configured", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []func(*api.ServerConfig){withMetrics(func(*scaling.Metrics) {})}
			if tc.held != nil {
				opts = append(opts, withEdgeMetrics(tc.held))
			}
			h := newAuthHarness(t, opts...)

			// Published unconditionally. A gap in kanea_edge_service_* has two
			// causes (the edge is down, or nothing is exposed) and without
			// this they are indistinguishable.
			if body := scrapeMetrics(t, h); !strings.Contains(body, "kanea_edge_up 0") {
				t.Errorf("expected kanea_edge_up 0:\n%s", body)
			}
		})
	}
}

func TestServerUpIsOnlyPublishedForProbedAllocs(t *testing.T) {
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}))
	ctx := context.Background()

	records := []reconciler.AllocRecord{
		// Probed and passing.
		{
			ID: "shop-web-0", Project: "shop", Service: "web", Index: 0,
			State: reconciler.AllocRunning, Healthy: true, LastProbeAt: time.Now(),
		},
		// Probed and failing.
		{
			ID: "shop-web-1", Project: "shop", Service: "web", Index: 1,
			State: reconciler.AllocRunning, Healthy: false, LastProbeAt: time.Now(),
		},
		// Never probed; the service declares no `check` block. Healthy is
		// written solely by a probe, so this record's false is not a fact
		// about the alloc, and publishing it would report every check-free
		// service as entirely down.
		{
			ID: "blog-cms-0", Project: "blog", Service: "cms", Index: 0,
			State: reconciler.AllocRunning, Healthy: false,
		},
	}
	for _, rec := range records {
		if _, err := store.PutValue(ctx, h.store, store.KindAlloc, rec.Key(), rec); err != nil {
			t.Fatalf("seed alloc: %v", err)
		}
	}

	body := scrapeMetrics(t, h)
	for _, want := range []string{
		`kanea_edge_server_up{project="shop",service="web",alloc="shop/web/0"} 1`,
		`kanea_edge_server_up{project="shop",service="web",alloc="shop/web/1"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `service="cms"`) {
		t.Errorf("an unprobed alloc was published as down:\n%s", body)
	}
}

func TestStatsCarriesTheEdgeBreakdown(t *testing.T) {
	held := &fakeEdgeExposition{
		ok: true, at: time.Now(),
		breakdown: map[string]scaling.ServiceBreakdown{
			"shop/web": {
				Codes:         map[string]float64{"200": 41, "502": 1},
				RequestBytes:  1024,
				ResponseBytes: 8192,
			},
		},
	}
	h := newAuthHarness(t, withMetrics(func(*scaling.Metrics) {}), withEdgeMetrics(held))

	req := h.request(t, http.MethodGet, api.PathStats+"?project=shop&service=web", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET stats = %d: %s", resp.StatusCode, body)
	}

	var sample api.StatsSample
	if err := json.Unmarshal([]byte(body), &sample); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sample.Edge == nil {
		t.Fatal("no edge breakdown in the sample")
	}
	if sample.Edge.Codes["502"] != 1 || sample.Edge.ResponseBytes != 8192 {
		t.Errorf("breakdown = %+v", *sample.Edge)
	}

	// A service the edge has never reported gets no breakdown at all, rather
	// than one full of zeroes: "not exposed" and "served nothing" are
	// different facts and the dashboard renders them differently.
	req = h.request(t, http.MethodGet, api.PathStats+"?project=blog&service=cms", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	_, body = h.do(t, req)

	// A fresh target: json.Unmarshal leaves a pointer field alone when the key
	// is absent, so decoding into the struct above would report the previous
	// service's breakdown and pass.
	var unexposed api.StatsSample
	if err := json.Unmarshal([]byte(body), &unexposed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if unexposed.Edge != nil {
		t.Errorf("an unreported service carried a breakdown: %+v", *unexposed.Edge)
	}
}

func TestTheNodeOnlySeriesNeverReachTheExporter(t *testing.T) {
	// The v1.38 rule turned into a tripwire (v1.79). Node series are recorded
	// into the time series under names the exporter's fixed list does not carry,
	// so the Prometheus surface is unchanged by their existence. `exported` is
	// what enforces it, and this fails the moment someone adds the sixth name
	// to it without meaning to promise it publicly.
	now := time.Now()
	nodeOnly := []string{
		scaling.MetricNodeCPU,
		scaling.MetricNodeMemory,
		scaling.MetricNodeGPU,
		scaling.MetricNodeLoad1,
		scaling.MetricNodeAllocsRunning,
	}

	h := newAuthHarness(t, withMetrics(func(m *scaling.Metrics) {
		for i, metric := range nodeOnly {
			m.Record(scaling.Key{Subject: scaling.NodeSubject, Metric: metric}, now, float64(i+1))
		}
		// One published series, so a body that is empty for an unrelated reason
		// cannot pass this test by accident.
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 42)
	}))

	body := scrapeMetrics(t, h)
	if !strings.Contains(body, "kanea_cpu_percent") {
		t.Fatalf("the exposition is missing the series that should be there:\n%s", body)
	}
	for _, metric := range nodeOnly {
		if strings.Contains(body, metric) {
			t.Errorf("%q reached /v1/metrics; node series are recorded under names "+
				"the exporter does not publish, so the Prometheus surface stays "+
				"unchanged:\n%s", metric, body)
		}
	}
	// The subject would be the other way in: a bare "node" rendered as a label.
	if strings.Contains(body, `project="node"`) || strings.Contains(body, `service="node"`) {
		t.Errorf("the node subject was rendered as a label:\n%s", body)
	}
}

func TestAStatsSubscriptionSeedsOnlyItsFirstFrame(t *testing.T) {
	// The seed is on the first frame and no frame after it (v1.79), which is
	// what keeps §12.1's rule true: a frame stays a superset of the one it
	// supersedes, so a client merges the seed under its live samples instead of
	// replacing its state every tick.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newHarness(t, func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		for at := now.Add(-5 * time.Minute); !at.After(now); at = at.Add(scaling.RawInterval) {
			m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, at, 55)
		}
		cfg.Metrics = m
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicStats,
		Project: "shop", Service: "web", History: true,
	})

	var first api.StatsSample
	if err := json.Unmarshal(receive(t, conn).Data, &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first.History == nil {
		t.Fatal("the first frame carried no seed")
	}
	if len(first.History.Series["cpu"]) < 2 {
		t.Fatalf("the seed carries %d cpu points, want a window of them",
			len(first.History.Series["cpu"]))
	}
	if first.History.IntervalSeconds == 0 {
		t.Error("the seed has no interval; a client cannot rebuild its slots")
	}

	// Resubscribing is a replace, and it re-seeds: that is the property that
	// makes a reconnect cost nothing extra.
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicStats,
		Project: "shop", Service: "web", History: true,
	})
	var again api.StatsSample
	if err := json.Unmarshal(receive(t, conn).Data, &again); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if again.History == nil {
		t.Error("a resubscribe did not re-seed; a reconnecting client would start blank")
	}
}

func TestASubscriptionThatAsksForNoHistoryEmitsNoHistoryKey(t *testing.T) {
	// The omitempty pin. Every pre-v1.79 client subscribes without the field
	// and must keep getting exactly the frames it always got.
	now := time.Now()
	h := newHarness(t, func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 55)
		cfg.Metrics = m
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicStats, Project: "shop", Service: "web",
	})

	body := string(receive(t, conn).Data)
	if strings.Contains(body, "history") {
		t.Errorf("a subscription that asked for no history got one: %s", body)
	}
}

func TestHistoryIsNotPartOfTheSubscriptionKey(t *testing.T) {
	// Keying on it would double the subscriptions a page holds against
	// maxSubscriptions and make an ordinary remount cost a second live feed.
	// The seed is purely additive, so the key stays topic+project+service.
	now := time.Now()
	h := newHarness(t, func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		m.Record(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU}, now, 55)
		cfg.Metrics = m
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	seeded := api.ClientFrame{
		Type: "subscribe", Topic: api.TopicStats,
		Project: "shop", Service: "web", History: true,
	}
	send(t, conn, seeded)
	first := receive(t, conn)
	send(t, conn, seeded)
	second := receive(t, conn)

	if first.Key != second.Key {
		t.Fatalf("keys differ: %q then %q", first.Key, second.Key)
	}
	if want := api.TopicStats + ":shop/web"; first.Key != want {
		t.Errorf("key = %q, want %q: the history request leaked into it", first.Key, want)
	}
}

func TestTheSeedBudgetRefusesResubscribeAmplification(t *testing.T) {
	// A subscribe frame is about a hundred bytes and the seed it asks for is
	// orders of magnitude larger, and a subscribe is a replace, so
	// subscribe/unsubscribe in a loop would re-seed without limit. Over budget
	// the seed is omitted and *says so*, and the live samples keep flowing:
	// stats is not a lossy topic, so failing by dropping the frame would cost
	// the socket every other panel is riding on.
	now := time.Now().Truncate(scaling.RawInterval)
	h := newHarness(t, func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		for at := now.Add(-time.Hour); !at.After(now); at = at.Add(scaling.RawInterval) {
			for _, metric := range []string{
				scaling.MetricCPU, scaling.MetricMemory, scaling.MetricRPS, scaling.MetricP95,
			} {
				m.Record(scaling.Key{Subject: "shop/web", Metric: metric}, at, 1)
			}
		}
		cfg.Metrics = m
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	frame := api.ClientFrame{
		Type: "subscribe", Topic: api.TopicStats,
		// Just inside the raw tier: a full hour falls to the 60s rollup and is
		// twelve times cheaper, which is not what this bound is about.
		Project: "shop", Service: "web", History: true, HistoryWindow: "55m",
	}

	omitted := false
	for range 8 {
		send(t, conn, frame)
		var sample api.StatsSample
		if err := json.Unmarshal(receive(t, conn).Data, &sample); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if sample.HistoryOmitted {
			omitted = true
			if sample.History != nil {
				t.Error("a seed was both omitted and sent")
			}
			// The live half is unaffected: the budget drops the seed, not the
			// subscription.
			if sample.Service != "shop/web" {
				t.Errorf("the live sample went missing with the seed: %+v", sample)
			}
			break
		}
	}
	if !omitted {
		t.Fatal("eight raw-tier seeds were served without the budget refusing one")
	}
}

func TestTheNodeTopicStreamsAndSeeds(t *testing.T) {
	now := time.Now().Truncate(scaling.RawInterval)
	h := newHarness(t, func(cfg *api.ServerConfig) {
		m := scaling.NewMetrics(scaling.MetricsConfig{})
		for at := now.Add(-5 * time.Minute); !at.After(now); at = at.Add(scaling.RawInterval) {
			m.Record(scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeCPU}, at, 12)
			m.Record(scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeLoad1}, at, 0.5)
		}
		cfg.Metrics = m
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicNode,
		History: true, HistorySeries: []string{"cpu", "load1"},
	})

	var sample api.NodeSample
	if err := json.Unmarshal(receive(t, conn).Data, &sample); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sample.History == nil {
		t.Fatal("the node topic's first frame carried no seed")
	}
	// load1 is exactly what the Overview's panel could never seed before: no
	// such series was recorded, so it accumulated from empty every visit.
	if len(sample.History.Series["load1"]) < 2 {
		t.Errorf("load1 seed = %+v, want a window of points", sample.History.Series["load1"])
	}
	if len(sample.History.Series["cpu"]) < 2 {
		t.Errorf("cpu seed = %+v, want a window of points", sample.History.Series["cpu"])
	}
}

func TestTheNodeTopicRefusesAProjectOrService(t *testing.T) {
	// There is one node. A scoped subscription would be a request for something
	// that does not exist, answered with an error frame rather than a feed that
	// quietly ignores the scope.
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.Metrics = scaling.NewMetrics(scaling.MetricsConfig{})
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicNode, Project: "shop", Service: "web",
	})

	frame := receive(t, conn)
	if frame.Type != "error" {
		t.Fatalf("frame type = %q, want error", frame.Type)
	}
	if !strings.Contains(frame.Error, "node") {
		t.Errorf("the refusal does not name the topic: %q", frame.Error)
	}
}

func TestAnUnknownSeedSeriesIsRefusedAtSubscribe(t *testing.T) {
	// At subscribe rather than at the first emit: a typo answers with an error
	// naming it, instead of a live subscription that quietly seeds nothing and
	// reads as a service with no traffic.
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.Metrics = scaling.NewMetrics(scaling.MetricsConfig{})
	})

	conn := dialWS(t, h, "")
	defer func() { _ = conn.CloseNow() }()
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicStats, Project: "shop", Service: "web",
		History: true, HistorySeries: []string{"cpu_percent"},
	})

	frame := receive(t, conn)
	if frame.Type != "error" {
		t.Fatalf("frame type = %q, want error", frame.Type)
	}
	if !strings.Contains(frame.Error, "cpu_percent") {
		t.Errorf("the refusal does not name the series: %q", frame.Error)
	}
}
