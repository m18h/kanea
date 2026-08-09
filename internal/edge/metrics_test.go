package edge

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// render collects the exposition into a string.
func render(t *testing.T, m *Metrics) string {
	t.Helper()
	var b strings.Builder
	if _, err := m.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return b.String()
}

// obs is the ordinary GET/plaintext observation these tests are about.
//
// The label dimensions §9.1.1 added are exercised in their own tests below;
// spelling them out at every call site here would bury what each of these is
// actually checking.
func obs(service string, d time.Duration, status int) Observation {
	return Observation{
		Service:  service,
		Status:   status,
		Method:   http.MethodGet,
		Protocol: ProtocolHTTP,
		Duration: d,
	}
}

// sample finds one metric line's value.
//
// Split on the *last* space, not the first: a label value may contain one —
// `tls_version="TLS 1.3"` does — and cutting at the first would return the
// tail of the label set instead of the number.
func sample(t *testing.T, body, want string) string {
	t.Helper()
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, want) {
			if i := strings.LastIndex(line, " "); i >= 0 {
				return line[i+1:]
			}
			return ""
		}
	}
	t.Fatalf("no sample matching %q in:\n%s", want, body)
	return ""
}

func TestObserveCountsRequestsAndErrors(t *testing.T) {
	m := NewMetrics()

	m.Observe(obs("shop/web", 10*time.Millisecond, 200))
	m.Observe(obs("shop/web", 20*time.Millisecond, 200))
	m.Observe(obs("shop/web", 30*time.Millisecond, 503))

	body := render(t, m)
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/web"}`); got != "3" {
		t.Errorf("requests = %s, want 3", got)
	}
	// A 5xx is counted apart from the request that produced it: "busy" and
	// "failing" call for opposite scaling decisions.
	if got := sample(t, body, `kanea_edge_errors_total{service="shop/web"}`); got != "1" {
		t.Errorf("errors = %s, want 1", got)
	}
}

func TestRefusedIsNotARequest(t *testing.T) {
	m := NewMetrics()
	m.Refused("shop/web", ReasonIPRestriction)
	m.Refused("shop/web", ReasonIPRestriction)
	m.Refused("shop/web", ReasonRateLimit)

	body := render(t, m)
	// A service being hammered by blocked addresses is not a service under
	// load. Counting refusals as requests would scale up to serve traffic the
	// edge is already dropping.
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/web"}`); got != "0" {
		t.Errorf("requests = %s, want 0", got)
	}
	// Split by reason, because they are different operator problems: policy
	// working as written versus a service that has run out of allowance.
	if got := sample(t, body,
		`kanea_edge_refused_total{service="shop/web",reason="ip_restriction"}`); got != "2" {
		t.Errorf("ip_restriction refusals = %s, want 2", got)
	}
	if got := sample(t, body,
		`kanea_edge_refused_total{service="shop/web",reason="rate_limit"}`); got != "1" {
		t.Errorf("rate_limit refusals = %s, want 1", got)
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	m := NewMetrics()
	m.Observe(obs("shop/web", 3*time.Millisecond, 200))   // ≤ 5
	m.Observe(obs("shop/web", 150*time.Millisecond, 200)) // ≤ 200
	m.Observe(obs("shop/web", 5*time.Second, 200))        // ≤ 10000

	body := render(t, m)
	// `le` means at-or-below, so each bound includes everything faster. A
	// percentile computed from these depends on it.
	for _, tc := range []struct{ bound, want string }{
		{"5", "1"},
		{"100", "1"},
		{"200", "2"},
		{"3000", "2"},
		{"10000", "3"},
		{"+Inf", "3"},
	} {
		got := sample(t, body,
			`kanea_edge_request_duration_ms_bucket{service="shop/web",le="`+tc.bound+`"}`)
		if got != tc.want {
			t.Errorf("le=%s bucket = %s, want %s", tc.bound, got, tc.want)
		}
	}
	if got := sample(t, body, `kanea_edge_request_duration_ms_count{service="shop/web"}`); got != "3" {
		t.Errorf("count = %s, want 3", got)
	}
}

func TestSlowRequestLandsInTheOverflowBucket(t *testing.T) {
	m := NewMetrics()
	// Past the last bound. It still has to be counted somewhere, or a service
	// whose requests all take a minute would look like it served none.
	m.Observe(obs("shop/web", time.Minute, 200))

	body := render(t, m)
	if got := sample(t, body, `kanea_edge_request_duration_ms_bucket{service="shop/web",le="10000"}`); got != "0" {
		t.Errorf("le=10000 = %s, want 0", got)
	}
	if got := sample(t, body, `kanea_edge_request_duration_ms_bucket{service="shop/web",le="+Inf"}`); got != "1" {
		t.Errorf("+Inf = %s, want 1", got)
	}
}

func TestCountersAreCumulativeAcrossScrapes(t *testing.T) {
	m := NewMetrics()
	m.Observe(obs("shop/web", time.Millisecond, 200))
	first := render(t, m)

	m.Observe(obs("shop/web", time.Millisecond, 200))
	second := render(t, m)

	// Reading must not reset anything: kanead differences two readings, and a
	// scrape that consumed the counters would make a second reader — or a
	// retried scrape — see traffic that never happened.
	if sample(t, first, `kanea_edge_requests_total{service="shop/web"}`) != "1" {
		t.Error("first scrape did not report the request")
	}
	if got := sample(t, second, `kanea_edge_requests_total{service="shop/web"}`); got != "2" {
		t.Errorf("second scrape = %s, want the cumulative 2", got)
	}
}

func TestRetainDropsDepartedServices(t *testing.T) {
	m := NewMetrics()
	m.Observe(obs("shop/web", time.Millisecond, 200))
	m.Observe(obs("shop/gone", time.Millisecond, 200))

	if dropped := m.Retain(map[string]bool{"shop/web": true}); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	body := render(t, m)
	if strings.Contains(body, "shop/gone") {
		t.Error("a service removed from the route table is still being exported")
	}
	if !strings.Contains(body, "shop/web") {
		t.Error("a service still in the table was dropped")
	}
}

func TestExportIsSortedAndStable(t *testing.T) {
	m := NewMetrics()
	for _, name := range []string{"shop/zulu", "shop/alpha", "shop/mike"} {
		m.Observe(obs(name, time.Millisecond, 200))
	}

	// Map iteration order must not reach the output: a diff between two scrapes
	// should show what changed, not what moved.
	first, second := render(t, m), render(t, m)
	if first != second {
		t.Fatal("two identical scrapes produced different output")
	}
	alpha := strings.Index(first, "shop/alpha")
	mike := strings.Index(first, "shop/mike")
	zulu := strings.Index(first, "shop/zulu")
	if alpha >= mike || mike >= zulu {
		t.Errorf("services are not sorted: alpha=%d mike=%d zulu=%d", alpha, mike, zulu)
	}
}

func TestObserveIgnoresAnEmptyService(t *testing.T) {
	m := NewMetrics()
	m.Observe(obs("", time.Millisecond, 200))
	m.Refused("", ReasonRateLimit)
	if body := render(t, m); strings.Contains(body, `service=""`) {
		t.Fatalf("an unnamed service was exported:\n%s", body)
	}
}

func TestMetricsAreConcurrencySafe(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup

	// Several services and a reader, which is the real shape: the proxy writes
	// from every request goroutine while kanead scrapes.
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				m.Observe(obs("shop/svc", time.Duration(i)*time.Millisecond, 200))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			var b strings.Builder
			if _, err := m.WriteTo(&b); err != nil {
				t.Errorf("WriteTo: %v", err)
			}
		}
	}()
	wg.Wait()

	body := render(t, m)
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/svc"}`); got != "1600" {
		t.Errorf("requests = %s, want 1600 — a counter was lost to a race", got)
	}
}

// The collector is only useful if the request path actually feeds it, which is
// wiring no unit test of Metrics can check.

func TestProxyObservesProxiedRequests(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	p := newTestProxy(t, route)

	for range 3 {
		resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
		_ = resp.Body.Close()
	}

	body := render(t, p.Metrics())
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/web"}`); got != "3" {
		t.Fatalf("requests = %s, want 3", got)
	}
}

func TestProxyRecordsTheUpstreamStatus(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	_ = resp.Body.Close()

	// The status the upstream returned, not the 200 a naive recorder defaults
	// to: a service failing every request must not read as healthy.
	if got := sample(t, render(t, p.Metrics()), `kanea_edge_errors_total{service="shop/web"}`); got != "1" {
		t.Fatalf("errors = %s, want 1", got)
	}
}

func TestProxyCountsARefusedAddressAsRefusedNotServed(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// httptest.NewRequest peers from 192.0.2.1, which this denies.
	route.IPRestriction = &IPRestriction{Deny: []string{"192.0.2.0/24"}}
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	body := render(t, p.Metrics())
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/web"}`); got != "0" {
		t.Errorf("requests = %s; a blocked request never reached the service", got)
	}
	if got := sample(t, body,
		`kanea_edge_refused_total{service="shop/web",reason="ip_restriction"}`); got != "1" {
		t.Errorf("refused = %s, want 1", got)
	}
}

func TestReloadingTheTableDropsDepartedServices(t *testing.T) {
	_, route := upstream(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	p := newTestProxy(t, route)

	resp := request(p, http.MethodGet, "web.shop.example.com", "/", nil)
	_ = resp.Body.Close()

	// The service is removed from the projection. Its counters go with it: the
	// route table is the only bound on this map.
	empty, err := NewTable(Snapshot{})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(empty)

	if body := render(t, p.Metrics()); strings.Contains(body, "shop/web") {
		t.Fatalf("counters survived the service leaving the table:\n%s", body)
	}
}
