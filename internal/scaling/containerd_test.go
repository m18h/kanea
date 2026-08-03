package scaling_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/scaling"
)

// allocMap resolves container ids the way the daemon does from the Store.
type allocMap map[string]scaling.AllocInfo

func (a allocMap) Alloc(id string) (scaling.AllocInfo, bool) {
	info, ok := a[id]
	return info, ok
}

// exposition renders containerd's metrics the way M0 spike ② measured them:
// the real names, the real label set, and enough neighbouring families that a
// parser which is not selective would trip over them.
func exposition(samples map[string]map[string]float64) string {
	var b strings.Builder
	b.WriteString("# HELP container_cpu_usage_usec_microseconds Total CPU time\n")
	b.WriteString("# TYPE container_cpu_usage_usec_microseconds counter\n")
	for id, values := range samples {
		for name, value := range values {
			fmt.Fprintf(&b, "%s{container_id=%q,namespace=\"kanea\",runtime=\"io.containerd.runc.v2\"} %g\n",
				name, id, value)
		}
		// Families the scraper must skip without being confused by them.
		fmt.Fprintf(&b, "container_blkio_io_service_bytes_recursive_bytes{container_id=%q,op=\"read\"} 4096\n", id)
		fmt.Fprintf(&b, "container_memory_cache_bytes{container_id=%q} 12345\n", id)
	}
	b.WriteString("go_goroutines 42\n")
	return b.String()
}

func newScraper(t *testing.T, body string, allocs allocMap, c *clock) (*scaling.ContainerdScraper, *scaling.Metrics) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, err := scaling.NewContainerdScraper(scaling.ContainerdConfig{
		URL: server.URL, Metrics: m, Allocs: allocs, Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewContainerdScraper: %v", err)
	}
	return s, m
}

const oneCore = 1000 // millicores

func TestScrapeRecordsMemoryAndPIDs(t *testing.T) {
	c := newClock()
	allocs := allocMap{"alloc-0": {
		Subject: "shop/web/alloc-0", Service: "shop/web",
		CPUMillis: oneCore, MemoryBytes: 256 << 20,
	}}
	body := exposition(map[string]map[string]float64{
		"alloc-0": {
			"container_memory_usage_bytes": float64(128 << 20),
			"container_pids_current":       17,
		},
	})
	s, m := newScraper(t, body, allocs, c)

	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}

	bytes, ok := m.Latest(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricMemoryBytes})
	if !ok || bytes.Value != float64(128<<20) {
		t.Fatalf("memory bytes = %+v, %v", bytes, ok)
	}
	// 128 MiB of a 256 MiB limit is half of it, and half is what a rule
	// written as `metric "memory" { target = 80 }` compares against.
	percent, ok := m.Latest(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricMemory})
	if !ok || percent.Value != 50 {
		t.Fatalf("memory percent = %+v, %v; want 50", percent, ok)
	}
	pids, ok := m.Latest(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricPIDs})
	if !ok || pids.Value != 17 {
		t.Fatalf("pids = %+v, %v; want 17", pids, ok)
	}
}

func TestFirstScrapeRecordsNoCPU(t *testing.T) {
	c := newClock()
	allocs := allocMap{"alloc-0": {
		Subject: "shop/web/alloc-0", Service: "shop/web", CPUMillis: oneCore, MemoryBytes: 1 << 20,
	}}
	s, m := newScraper(t, exposition(map[string]map[string]float64{
		"alloc-0": {"container_cpu_usage_usec_microseconds": 1_000_000},
	}), allocs, c)

	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	// containerd reports CPU as a cumulative counter, so one reading says
	// nothing about load. Recording a number here would report a container
	// that has been up for an hour as permanently pinned.
	if _, ok := m.Latest(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricCPU}); ok {
		t.Fatal("a CPU percentage was recorded from a single counter reading")
	}
}

func TestCPUIsARateBetweenScrapes(t *testing.T) {
	c := newClock()
	allocs := allocMap{"alloc-0": {
		Subject: "shop/web/alloc-0", Service: "shop/web",
		CPUMillis: oneCore, MemoryBytes: 1 << 20,
	}}

	// Two scrapes five seconds apart. Between them the container used 2.5 s of
	// CPU against a one-core limit: 50%.
	first := exposition(map[string]map[string]float64{
		"alloc-0": {"container_cpu_usage_usec_microseconds": 1_000_000},
	})
	second := exposition(map[string]map[string]float64{
		"alloc-0": {"container_cpu_usage_usec_microseconds": 3_500_000},
	})

	body := first
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, err := scaling.NewContainerdScraper(scaling.ContainerdConfig{
		URL: server.URL, Metrics: m, Allocs: allocs, Now: c.now,
	})
	if err != nil {
		t.Fatalf("NewContainerdScraper: %v", err)
	}

	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("first scrape: %v", err)
	}
	c.advance(5 * time.Second)
	body = second
	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("second scrape: %v", err)
	}

	cpu, ok := m.Latest(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricCPU})
	if !ok {
		t.Fatal("no CPU sample after two scrapes")
	}
	if cpu.Value < 49.9 || cpu.Value > 50.1 {
		t.Fatalf("cpu = %v%%, want 50%% (2.5 s of CPU in 5 s against one core)", cpu.Value)
	}
	// And the service-level mean is recorded alongside, because a scaling rule
	// is a statement about the service rather than about one alloc.
	svc, ok := m.Latest(scaling.Key{Subject: "shop/web", Metric: scaling.MetricCPU})
	if !ok || svc.Value < 49.9 || svc.Value > 50.1 {
		t.Fatalf("service cpu = %+v, %v; want the mean", svc, ok)
	}
}

func TestServiceMeanAveragesItsAllocs(t *testing.T) {
	c := newClock()
	allocs := allocMap{
		"alloc-0": {Subject: "shop/web/alloc-0", Service: "shop/web", CPUMillis: oneCore, MemoryBytes: 100},
		"alloc-1": {Subject: "shop/web/alloc-1", Service: "shop/web", CPUMillis: oneCore, MemoryBytes: 100},
	}
	// One alloc at 90% of its memory, one at 10%: the service is at 50%, and
	// one hot alloc among two is not a service that needs doubling.
	body := exposition(map[string]map[string]float64{
		"alloc-0": {"container_memory_usage_bytes": 90},
		"alloc-1": {"container_memory_usage_bytes": 10},
	})
	s, m := newScraper(t, body, allocs, c)

	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	mean, ok := m.Latest(scaling.Key{Subject: "shop/web", Metric: scaling.MetricMemory})
	if !ok || mean.Value != 50 {
		t.Fatalf("service memory = %+v, %v; want 50", mean, ok)
	}
}

func TestUnknownContainersAreIgnored(t *testing.T) {
	c := newClock()
	// A container on the same containerd that Kanea does not run. Attributing
	// its load to a service would scale something that is not busy.
	body := exposition(map[string]map[string]float64{
		"someone-elses": {"container_memory_usage_bytes": 1 << 30},
	})
	s, m := newScraper(t, body, allocMap{}, c)

	recorded, err := s.Scrape(context.Background())
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if recorded != 0 || m.Len() != 0 {
		t.Fatalf("recorded %d samples into %d series for an unknown container", recorded, m.Len())
	}
}

func TestCounterResetRebaselinesInsteadOfSpiking(t *testing.T) {
	c := newClock()
	allocs := allocMap{"alloc-0": {
		Subject: "shop/web/alloc-0", Service: "shop/web", CPUMillis: oneCore, MemoryBytes: 1 << 20,
	}}

	body := exposition(map[string]map[string]float64{
		"alloc-0": {"container_cpu_usage_usec_microseconds": 9_000_000},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, _ := scaling.NewContainerdScraper(scaling.ContainerdConfig{
		URL: server.URL, Metrics: m, Allocs: allocs, Now: c.now,
	})

	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("scrape: %v", err)
	}
	// The container was replaced and the counter restarted. A naive delta is
	// negative; recording it would report a nonsensical CPU figure at exactly
	// the moment a service is restarting.
	c.advance(5 * time.Second)
	body = exposition(map[string]map[string]float64{
		"alloc-0": {"container_cpu_usage_usec_microseconds": 1_000},
	})
	if _, err := s.Scrape(context.Background()); err != nil {
		t.Fatalf("scrape: %v", err)
	}

	if point, ok := m.Latest(scaling.Key{Subject: "shop/web/alloc-0", Metric: scaling.MetricCPU}); ok {
		t.Fatalf("a CPU value of %v was recorded across a counter reset", point.Value)
	}
}

func TestScrapeReportsATransportFailure(t *testing.T) {
	c := newClock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, _ := scaling.NewContainerdScraper(scaling.ContainerdConfig{
		URL: server.URL, Metrics: m, Allocs: allocMap{}, Now: c.now,
	})

	if _, err := s.Scrape(context.Background()); err == nil {
		t.Fatal("a 503 was reported as a successful scrape")
	}
}

func TestNewContainerdScraperRequiresItsCollaborators(t *testing.T) {
	if _, err := scaling.NewContainerdScraper(scaling.ContainerdConfig{Allocs: allocMap{}}); err == nil {
		t.Error("a scraper with nowhere to record was accepted")
	}
	if _, err := scaling.NewContainerdScraper(scaling.ContainerdConfig{
		Metrics: scaling.NewMetrics(scaling.MetricsConfig{}),
	}); err == nil {
		t.Error("a scraper that cannot resolve containers was accepted")
	}
}

// The parser is the hot path — tens of megabytes every five seconds at the §21
// target — so it is worth knowing what one pass over a realistic body costs.
func BenchmarkScrapeParse(b *testing.B) {
	c := newClock()
	allocs := allocMap{}
	samples := map[string]map[string]float64{}
	for i := range 2000 {
		id := fmt.Sprintf("alloc-%d", i)
		allocs[id] = scaling.AllocInfo{
			Subject:   fmt.Sprintf("shop/svc%d/%s", i/4, id),
			Service:   fmt.Sprintf("shop/svc%d", i/4),
			CPUMillis: oneCore, MemoryBytes: 256 << 20,
		}
		samples[id] = map[string]float64{
			"container_cpu_usage_usec_microseconds": float64(i * 1000),
			"container_memory_usage_bytes":          float64(i * 1024),
			"container_pids_current":                float64(i % 50),
		}
	}
	body := exposition(samples)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			b.Errorf("write: %v", err)
		}
	}))
	b.Cleanup(server.Close)

	m := scaling.NewMetrics(scaling.MetricsConfig{Now: c.now})
	s, err := scaling.NewContainerdScraper(scaling.ContainerdConfig{
		URL: server.URL, Metrics: m, Allocs: allocs, Now: c.now,
	})
	if err != nil {
		b.Fatal(err)
	}

	// Two warm-up scrapes before measuring: the first allocates every series'
	// rings (~26 MiB, amortised into the average if it lands inside the loop)
	// and the second establishes the CPU baselines. Steady state is what runs
	// every five seconds for the life of the node, and it is the only number
	// worth tuning against.
	for range 2 {
		if _, err := s.Scrape(context.Background()); err != nil {
			b.Fatal(err)
		}
		c.advance(5 * time.Second)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		c.advance(5 * time.Second)
		if _, err := s.Scrape(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
