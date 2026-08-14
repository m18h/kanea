package dashboard_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/dashboard"
)

func get(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Result()
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(out)
}

// The root always answers with something: a real build if one is embedded, the
// placeholder if not. A binary built without `make dashboard` must still serve.
func TestServesTheEntryPoint(t *testing.T) {
	resp := get(t, dashboard.Handler("/", nil), "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Errorf("content-type = %q", got)
	}
	if !strings.Contains(body(t, resp), "<html") {
		t.Error("the root did not return HTML")
	}
}

// The router is client-side, so a deep link is a real URL to the user and a
// missing file to the server. It has to reach the app.
func TestClientRoutesFallBackToTheApp(t *testing.T) {
	h := dashboard.Handler("/", nil)
	for _, path := range []string{"/services", "/projects/shop", "/settings/tokens"} {
		resp := get(t, h, path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, resp.StatusCode)
		}
		if !strings.Contains(body(t, resp), "<html") {
			t.Errorf("%s did not return the app", path)
		}
	}
}

// A missing *file* must 404. Falling back for those too would answer a missing
// script with HTML, which the browser reports as a syntax error and sends you
// looking in entirely the wrong place.
func TestMissingAssetsAreNotFound(t *testing.T) {
	h := dashboard.Handler("/", nil)
	for _, path := range []string{
		"/assets/index-deadbeef.js",
		"/assets/missing.css",
		"/favicon.ico",
	} {
		resp := get(t, h, path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, resp.StatusCode)
		}
		_ = body(t, resp)
	}
}

// Path traversal must not reach outside the embedded tree. The FS is read-only
// and in-binary, so the blast radius is small, but answering ../../etc/passwd
// with anything but a 404 is still wrong.
func TestPathTraversalIsRefused(t *testing.T) {
	h := dashboard.Handler("/", nil)
	for _, path := range []string{
		"/../dashboard.go",
		"/assets/../../dashboard.go",
		"/%2e%2e/dashboard.go",
	} {
		resp := get(t, h, path)
		text := body(t, resp)
		if strings.Contains(text, "package dashboard") {
			t.Errorf("%s escaped the embedded tree", path)
		}
	}
}

// Hashed assets are immutable and the entry point is not: caching index.html
// hard would leave a browser pinned to the old asset hashes after an upgrade.
func TestCacheHeaders(t *testing.T) {
	resp := get(t, dashboard.Handler("/", nil), "/")
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("entry point Cache-Control = %q, want no-cache", got)
	}
}

func TestBuiltReportsWhetherAssetsArePresent(t *testing.T) {
	// Both answers are legitimate — this asserts it does not panic and agrees
	// with what the handler serves.
	built := dashboard.Built()
	resp := get(t, dashboard.Handler("/", nil), "/")
	text := body(t, resp)

	isPlaceholder := strings.Contains(text, "was not built into this binary")
	if built == isPlaceholder {
		t.Errorf("Built() = %v but the served page is the placeholder = %v", built, isPlaceholder)
	}
}

// The security headers protect the origin, not one page, so every answer
// carries them — the 200, the 404 and the 405 alike.
func TestSecurityHeaders(t *testing.T) {
	h := dashboard.Handler("/", nil)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodGet, "/services"},
		{http.MethodGet, "/assets/index-deadbeef.js"}, // a 404
		{http.MethodPost, "/"},                        // a 405
	}
	for _, tc := range cases {
		req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		resp := w.Result()
		_ = body(t, resp)

		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s %s: %s = %q, want %q", tc.method, tc.path, header, got, want)
			}
		}

		csp := resp.Header.Get("Content-Security-Policy")
		for _, directive := range []string{
			"default-src 'self'",
			"script-src 'self'",
			// xterm.js and shadcn set style attributes at runtime; without the
			// inline exception the terminal renders broken.
			"style-src 'self' 'unsafe-inline'",
			"frame-ancestors 'none'",
			"base-uri 'none'",
			"object-src 'none'",
		} {
			if !strings.Contains(csp, directive) {
				t.Errorf("%s %s: CSP missing %q: %q", tc.method, tc.path, directive, csp)
			}
		}
	}
}

// connect-src bounds where a compromised page can send what it has read, so
// the websocket schemes are pinned to the origin serving the page rather than
// written as the bare `ws: wss:`, which matches any host anywhere.
func TestConnectSrcIsBoundToTheRequestHost(t *testing.T) {
	h := dashboard.Handler("/", nil)

	csp := func(host string) string {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		resp := w.Result()
		_ = body(t, resp)
		return resp.Header.Get("Content-Security-Policy")
	}

	for _, host := range []string{"kanea.example.com", "192.168.1.10:8600", "[::1]:8600"} {
		got := csp(host)
		if want := "connect-src 'self' ws://" + host + " wss://" + host; !strings.Contains(got, want) {
			t.Errorf("host %q: CSP missing %q: %q", host, want, got)
		}
		if strings.Contains(got, "ws: ") || strings.HasSuffix(got, "ws:") || strings.Contains(got, "wss: ") {
			t.Errorf("host %q: CSP still carries a bare websocket scheme: %q", host, got)
		}
	}

	// A Host that is not a bare host[:port] cannot be a real page's origin, and
	// a `;` in one would be a directive separator under the client's control.
	for _, host := range []string{"evil.example.com; script-src *", "host with spaces", ""} {
		got := csp(host)
		if !strings.Contains(got, "connect-src 'self'") {
			t.Errorf("host %q: CSP missing the fallback connect-src: %q", host, got)
		}
		if strings.Contains(got, "ws://") || strings.Contains(got, "wss://") {
			t.Errorf("host %q: an unusable Host reached the header: %q", host, got)
		}
	}
}

// The websocket handshake accepts same-origin plus --dashboard-origins, so
// connect-src has to permit the same set: a policy naming only the first would
// block, in the browser, a socket the daemon was configured to allow.
func TestConnectSrcCarriesTheConfiguredOrigins(t *testing.T) {
	h := dashboard.Handler("/", []string{
		"https://kanea.example.com",
		"http://192.168.1.10:8600",
		"not a url",     // dropped: checkOrigin will refuse it too
		"https://a b/c", // dropped: not a bare host
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = "10.0.0.2:8600"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	resp := w.Result()
	_ = body(t, resp)
	csp := resp.Header.Get("Content-Security-Policy")

	// The scheme is carried over, never doubled: a page on https can only open
	// wss, so naming ws:// as well would widen the policy past anything usable.
	for _, want := range []string{"wss://kanea.example.com", "ws://192.168.1.10:8600"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %q", want, csp)
		}
	}
	for _, unwanted := range []string{"ws://kanea.example.com", "wss://192.168.1.10:8600", "a b"} {
		if strings.Contains(csp, unwanted) {
			t.Errorf("CSP unexpectedly carries %q: %q", unwanted, csp)
		}
	}
}

// HSTS is only claimed under TLS: browsers ignore it over plain HTTP, and a
// node behind its own proxy may legitimately serve HTTP.
func TestHSTSRequiresTLS(t *testing.T) {
	h := dashboard.Handler("/", nil)

	plain := get(t, h, "/")
	_ = body(t, plain)
	if got := plain.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS over plain HTTP = %q, want none", got)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{} // any TLS state: the fact of it is the point
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	resp := w.Result()
	_ = body(t, resp)
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Error("no HSTS under TLS")
	}
}
