package edge

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// requestFrom drives one request through the proxy from a given peer address.
func requestFrom(p *Proxy, host, remoteAddr string, header http.Header) *http.Response {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	for name, values := range header {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w.Result()
}

// proxyWith wires a proxy to one route with the given middleware.
func proxyWith(t *testing.T, cfg ProxyConfig, mutate func(*Route), handler http.Handler) *Proxy {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	_, route := upstream(t, handler)
	if mutate != nil {
		mutate(&route)
	}
	cfg.Logger = slog.New(slog.DiscardHandler)

	p := NewProxy(cfg)
	table, err := NewTable(Snapshot{Routes: []Route{route}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(table)
	return p
}

const testHost = "web.shop.example.com"

func TestIPRestriction(t *testing.T) {
	tests := []struct {
		name       string
		allow      []string
		deny       []string
		remoteAddr string
		want       int
	}{
		{"no rules is the world", nil, nil, "203.0.113.9:1", http.StatusOK},
		{"empty allow is the world", []string{}, nil, "203.0.113.9:1", http.StatusOK},
		{"inside the allowed prefix", []string{"10.0.0.0/8"}, nil, "10.1.2.3:1", http.StatusOK},
		{"outside the allowed prefix", []string{"10.0.0.0/8"}, nil, "203.0.113.9:1", http.StatusForbidden},
		{"bare address as a host rule", []string{"203.0.113.9"}, nil, "203.0.113.9:1", http.StatusOK},
		{"denied outright", nil, []string{"203.0.113.9/32"}, "203.0.113.9:1", http.StatusForbidden},
		// Deny wins: an operator carving one host out of an allowed range must
		// not have to reason about which list was checked first.
		{"deny beats allow", []string{"10.0.0.0/8"}, []string{"10.1.2.3/32"}, "10.1.2.3:1", http.StatusForbidden},
		{"host bits in the prefix", []string{"10.9.9.9/8"}, nil, "10.1.2.3:1", http.StatusOK},
		// A dual-stack listener reports v4 peers as ::ffff:a.b.c.d. Without
		// unmapping, a rule written as 10.0.0.0/8 matches nothing at all.
		{"v4-mapped peer", []string{"10.0.0.0/8"}, nil, "[::ffff:10.1.2.3]:1", http.StatusOK},
		{"v6 rule and v6 peer", []string{"2001:db8::/32"}, nil, "[2001:db8::1]:1", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := proxyWith(t, ProxyConfig{}, func(r *Route) {
				r.IPRestriction = &IPRestriction{Allow: tc.allow, Deny: tc.deny}
			}, nil)

			resp := requestFrom(p, testHost, tc.remoteAddr, nil)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// IP restriction runs before the rate limit: spending a token on a client that
// is not allowed to spend one lets a blocked address exhaust everyone's budget.
func TestIPRestrictionRunsBeforeRateLimit(t *testing.T) {
	p := proxyWith(t, ProxyConfig{}, func(r *Route) {
		r.IPRestriction = &IPRestriction{Deny: []string{"203.0.113.9/32"}}
		r.RateLimit = &RateLimit{Requests: 1, Window: "1h", Per: RateLimitPerService}
	}, nil)

	for range 5 {
		resp := requestFrom(p, testHost, "203.0.113.9:1", nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	}
	// The service bucket must still be full for a permitted client.
	resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; the refused client spent the shared budget", resp.StatusCode)
	}
}

func TestRateLimitRefusesWithRetryAfter(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	p := proxyWith(t, ProxyConfig{Now: clock.Now}, func(r *Route) {
		r.RateLimit = &RateLimit{Requests: 3, Window: "1m", Per: RateLimitPerIP}
	}, nil)

	for i := range 3 {
		resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	// Without Retry-After a client can only guess, and guessing means retrying
	// immediately, which is the behaviour the limit exists to stop.
	retry := resp.Header.Get("Retry-After")
	seconds, err := strconv.Atoi(retry)
	if err != nil || seconds < 1 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", retry)
	}

	// Another address has its own budget.
	other := requestFrom(p, testHost, "10.0.0.2:1", nil)
	defer func() { _ = other.Body.Close() }()
	if other.StatusCode != http.StatusOK {
		t.Errorf("a second address got %d; buckets are not per-address", other.StatusCode)
	}

	// And the first refills.
	clock.advance(time.Minute)
	after := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = after.Body.Close() }()
	if after.StatusCode != http.StatusOK {
		t.Errorf("status = %d after a full window, want 200", after.StatusCode)
	}
}

func TestRateLimitPerService(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	p := proxyWith(t, ProxyConfig{Now: clock.Now}, func(r *Route) {
		r.RateLimit = &RateLimit{Requests: 2, Window: "1m", Per: RateLimitPerService}
	}, nil)

	// One bucket for the whole service, so distinct addresses share it.
	for _, addr := range []string{"10.0.0.1:1", "10.0.0.2:1"} {
		resp := requestFrom(p, testHost, addr, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", addr, resp.StatusCode)
		}
	}
	resp := requestFrom(p, testHost, "10.0.0.3:1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 from the shared bucket", resp.StatusCode)
	}
}

func TestRateLimitPerHeader(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	p := proxyWith(t, ProxyConfig{Now: clock.Now}, func(r *Route) {
		r.RateLimit = &RateLimit{Requests: 1, Window: "1m", Per: "header:X-API-Key"}
	}, nil)

	first := http.Header{"X-Api-Key": []string{"tenant-a"}}
	second := http.Header{"X-Api-Key": []string{"tenant-b"}}

	resp := requestFrom(p, testHost, "10.0.0.1:1", first)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// Same key, same bucket: even from a different address.
	again := requestFrom(p, testHost, "10.0.0.2:1", first)
	_ = again.Body.Close()
	if again.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 for the same key", again.StatusCode)
	}
	// Different key, different bucket.
	other := requestFrom(p, testHost, "10.0.0.1:1", second)
	defer func() { _ = other.Body.Close() }()
	if other.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 for a different key", other.StatusCode)
	}
}

// Omitting the header must not be a way around a per-key limit, so those
// requests share one bucket rather than falling back to per-address.
func TestRateLimitPerHeaderWithoutTheHeader(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	p := proxyWith(t, ProxyConfig{Now: clock.Now}, func(r *Route) {
		r.RateLimit = &RateLimit{Requests: 1, Window: "1m", Per: "header:X-API-Key"}
	}, nil)

	first := requestFrom(p, testHost, "10.0.0.1:1", nil)
	_ = first.Body.Close()
	second := requestFrom(p, testHost, "10.0.0.2:1", nil)
	defer func() { _ = second.Body.Close() }()

	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusTooManyRequests {
		t.Errorf("statuses = %d, %d; unkeyed requests should share one bucket",
			first.StatusCode, second.StatusCode)
	}
}

// A redeploy must not hand a throttled client a fresh allowance, or the limit
// is evadable by anyone who can trigger one.
func TestRateLimitSurvivesAReload(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	p := proxyWith(t, ProxyConfig{Now: clock.Now}, func(r *Route) {
		r.RateLimit = &RateLimit{Requests: 1, Window: "1h", Per: RateLimitPerIP}
	}, nil)

	resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
	_ = resp.Body.Close()

	// Same route, republished: a scale event or an unrelated change.
	route, _ := p.Table().Lookup(testHost)
	table, err := NewTable(Snapshot{Index: 99, Routes: []Route{route}})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	p.SetTable(table)

	after := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = after.Body.Close() }()
	if after.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d; the reload reset the bucket", after.StatusCode)
	}
}

func TestHeaderMiddleware(t *testing.T) {
	seen := make(chan http.Header, 1)
	p := proxyWith(t, ProxyConfig{}, func(r *Route) {
		r.Headers = &Headers{
			RequestSet:     map[string]string{"X-Kanea-Tenant": "shop"},
			RequestRemove:  []string{"X-Internal-Debug"},
			ResponseSet:    map[string]string{"X-Served-By": "kanea"},
			ResponseRemove: []string{"Server", "X-Powered-By"},
		}
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Set("Server", "nginx/1.27")
		w.Header().Set("X-Powered-By", "PHP/8.0")
		w.WriteHeader(http.StatusOK)
	}))

	resp := requestFrom(p, testHost, "10.0.0.1:1", http.Header{
		"X-Internal-Debug": []string{"leaked"},
	})
	defer func() { _ = resp.Body.Close() }()

	req := <-seen
	if got := req.Get("X-Kanea-Tenant"); got != "shop" {
		t.Errorf("request_set: X-Kanea-Tenant = %q", got)
	}
	if got := req.Get("X-Internal-Debug"); got != "" {
		t.Errorf("request_remove: X-Internal-Debug survived as %q", got)
	}
	if got := resp.Header.Get("X-Served-By"); got != "kanea" {
		t.Errorf("response_set: X-Served-By = %q", got)
	}
	for _, name := range []string{"Server", "X-Powered-By"} {
		if got := resp.Header.Get(name); got != "" {
			t.Errorf("response_remove: %s survived as %q", name, got)
		}
	}
}

// The spec's transforms run after the edge has set its own headers, so a
// service can add whatever it likes without reaching the ones above it.
func TestHeaderMiddlewareCannotForgeClientIdentity(t *testing.T) {
	// Compilation refuses it outright, which is what makes the ordering moot.
	_, err := compile(Route{
		Project: "shop", Service: "web",
		Domains: []string{"a.example.com"}, Upstream: "10.0.0.1", Port: 80,
		Headers: &Headers{RequestSet: map[string]string{"X-Forwarded-For": "1.2.3.4"}},
	})
	if err == nil {
		t.Fatal("a route forging X-Forwarded-For compiled")
	}
	if !strings.Contains(err.Error(), "set by the edge") {
		t.Errorf("error = %v", err)
	}
}

func TestSecurityHeaderDefaults(t *testing.T) {
	p := proxyWith(t, ProxyConfig{SecurityHeaders: true}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// The upstream has an opinion about one of them; it must win.
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.WriteHeader(http.StatusOK)
		}))

	resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got == "" {
		t.Error("Referrer-Policy was not set")
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q; the upstream's own value must win", got)
	}
	// HSTS on a plaintext response is meaningless and would lock users out of
	// an HTTP-only node before certificates exist.
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q on a plaintext listener", got)
	}
}

func TestSecurityHeadersOffByConfig(t *testing.T) {
	p := proxyWith(t, ProxyConfig{SecurityHeaders: false}, nil, nil)
	resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Content-Type-Options"); got != "" {
		t.Errorf("X-Content-Type-Options = %q with defaults disabled", got)
	}
}

// A malformed rule must be a rejected snapshot, not a decision made mid-request
// where allowing means the control is not enforced and denying means a typo
// takes the service down.
func TestCompileRejectsMalformedMiddleware(t *testing.T) {
	base := Route{
		Project: "shop", Service: "web",
		Domains: []string{"a.example.com"}, Upstream: "10.0.0.1", Port: 80,
	}
	tests := []struct {
		name   string
		mutate func(*Route)
		want   string
	}{
		{"bad allow CIDR", func(r *Route) {
			r.IPRestriction = &IPRestriction{Allow: []string{"10.0.0.0/33"}}
		}, "ip_restriction.allow"},
		{"bad deny CIDR", func(r *Route) {
			r.IPRestriction = &IPRestriction{Deny: []string{"nonsense"}}
		}, "ip_restriction.deny"},
		{"zero requests", func(r *Route) {
			r.RateLimit = &RateLimit{Requests: 0, Window: "1m"}
		}, "must be positive"},
		{"bad window", func(r *Route) {
			r.RateLimit = &RateLimit{Requests: 1, Window: "one minute"}
		}, "window"},
		{"zero window", func(r *Route) {
			r.RateLimit = &RateLimit{Requests: 1, Window: "0s"}
		}, "must be positive"},
		{"unknown key", func(r *Route) {
			r.RateLimit = &RateLimit{Requests: 1, Window: "1m", Per: "user"}
		}, "per"},
		{"hop-by-hop header", func(r *Route) {
			r.Headers = &Headers{RequestRemove: []string{"Connection"}}
		}, "connection-scoped"},
		{"malformed header name", func(r *Route) {
			r.Headers = &Headers{ResponseSet: map[string]string{"X-Bad: injected": "v"}}
		}, "not a valid header name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			route := base
			tc.mutate(&route)

			if _, err := compile(route); err == nil {
				t.Fatal("compiled a malformed rule")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not mention %q", err, tc.want)
			}
			// And it never reaches the edge: publishing refuses it too.
			if err := (Snapshot{Routes: []Route{route}}).Validate(); err == nil {
				t.Error("an invalid snapshot passed validation")
			}
		})
	}
}

// An omitted `per` means per-address, which is the useful default and the one
// PRD §6.1 writes out.
func TestRateLimitDefaultsToPerAddress(t *testing.T) {
	_, per, err := compileRateLimit(RateLimit{Requests: 5, Window: "1m"})
	if err != nil {
		t.Fatalf("compileRateLimit: %v", err)
	}
	if per != RateLimitPerIP {
		t.Errorf("per = %q, want %q", per, RateLimitPerIP)
	}
}

// Burst is capacity above the sustained allowance, so a client that has been
// quiet may spend more than one window at once, and no more.
func TestRateLimitBurst(t *testing.T) {
	clock := &testClock{now: time.Unix(1_700_000_000, 0)}
	p := proxyWith(t, ProxyConfig{Now: clock.Now}, func(r *Route) {
		r.RateLimit = &RateLimit{Requests: 2, Window: "1m", Burst: 3, Per: RateLimitPerIP}
	}, nil)

	var ok int
	for range 10 {
		resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			ok++
		}
	}
	if ok != 5 {
		t.Errorf("%d requests allowed, want requests+burst = 5", ok)
	}
}

func TestProxyStillServesWithoutMiddleware(t *testing.T) {
	p := proxyWith(t, ProxyConfig{}, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "plain")
	}))
	resp := requestFrom(p, testHost, "10.0.0.1:1", nil)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "plain" {
		t.Errorf("status = %d, body = %q", resp.StatusCode, body)
	}
}

// testClock is an injectable clock so rate-limit tests do not sleep.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }
