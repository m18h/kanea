package dashboard_test

import (
	"context"
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
	resp := get(t, dashboard.Handler("/"), "/")
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
	h := dashboard.Handler("/")
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
	h := dashboard.Handler("/")
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
	h := dashboard.Handler("/")
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
	resp := get(t, dashboard.Handler("/"), "/")
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("entry point Cache-Control = %q, want no-cache", got)
	}
}

func TestBuiltReportsWhetherAssetsArePresent(t *testing.T) {
	// Both answers are legitimate — this asserts it does not panic and agrees
	// with what the handler serves.
	built := dashboard.Built()
	resp := get(t, dashboard.Handler("/"), "/")
	text := body(t, resp)

	isPlaceholder := strings.Contains(text, "was not built into this binary")
	if built == isPlaceholder {
		t.Errorf("Built() = %v but the served page is the placeholder = %v", built, isPlaceholder)
	}
}
