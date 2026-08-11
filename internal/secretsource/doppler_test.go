package secretsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func dopplerFixture(t *testing.T, handler http.Handler, maps []syncMapping) (*dopplerProvider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	token := writeFile(t, t.TempDir(), "token", "dp.st.token", 0o600)
	cfg := providerConfig{
		kind: KindDoppler, name: "ci",
		hcl:  hclProvider{TokenFile: token, Project: "backend", ConfigName: "prd", BaseURL: srv.URL},
		maps: maps,
	}
	return newDoppler(cfg, DefaultHTTPClient(), discardLogger()), srv
}

func TestDopplerFetch(t *testing.T) {
	maps := []syncMapping{
		{To: "shop/db-url", Name: "DATABASE_URL"},
		{To: "shop/missing", Name: "NOT_THERE"},
	}
	var authSeen string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSeen = r.Header.Get("Authorization")
		if r.URL.Path != "/v3/configs/config/secrets/download" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("project"); got != "backend" {
			t.Errorf("project = %q", got)
		}
		if got := r.URL.Query().Get("format"); got != "json" {
			t.Errorf("format = %q", got)
		}
		_, _ = w.Write([]byte(`{"DATABASE_URL": "postgres://db", "UNMAPPED": "ignored"}`))
	})
	p, _ := dopplerFixture(t, handler, maps)

	res := p.Fetch(context.Background())
	if authSeen != "Bearer dp.st.token" {
		t.Errorf("Authorization = %q", authSeen)
	}
	if len(res.Values) != 1 || string(res.Values[0].Data) != "postgres://db" || res.Values[0].To != "shop/db-url" {
		t.Errorf("Values = %+v", res.Values)
	}
	// A name the config does not hold is a per-mapping failure that names it,
	// never a silent skip and never a failure of its siblings.
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "NOT_THERE") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

func TestDopplerRefusesARedirect(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	})
	p, _ := dopplerFixture(t, handler, []syncMapping{{To: "shop/a", Name: "A"}})

	res := p.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "redirects are refused") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

func TestDopplerRefusesAnOversizedResponse(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"A": "`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBytes)))
		_, _ = w.Write([]byte(`"}`))
	})
	p, _ := dopplerFixture(t, handler, []syncMapping{{To: "shop/a", Name: "A"}})

	res := p.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "exceeds") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

func TestDopplerRefusesAReadableTokenFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("a request was made with a world-readable token on disk")
	}))
	t.Cleanup(srv.Close)
	token := writeFile(t, t.TempDir(), "token", "dp.st.token", 0o644)
	cfg := providerConfig{
		kind: KindDoppler, name: "ci",
		hcl:  hclProvider{TokenFile: token, Project: "backend", ConfigName: "prd", BaseURL: srv.URL},
		maps: []syncMapping{{To: "shop/a", Name: "A"}},
	}
	p := newDoppler(cfg, DefaultHTTPClient(), discardLogger())

	res := p.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "chmod 600") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

// The error surface must never echo a body that could carry a value; only the
// provider's own message shape is quoted.
func TestDopplerErrorsCarryTheMessageNotTheBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"messages": ["Invalid Auth token"], "leaked": "hunter2"}`))
	})
	p, _ := dopplerFixture(t, handler, []syncMapping{{To: "shop/a", Name: "A"}})

	res := p.Fetch(context.Background())
	if len(res.Failures) != 1 {
		t.Fatalf("Failures = %+v", res.Failures)
	}
	msg := res.Failures[0].Err.Error()
	if !strings.Contains(msg, "Invalid Auth token") {
		t.Errorf("the provider's message was dropped: %q", msg)
	}
	if strings.Contains(msg, "hunter2") {
		t.Errorf("the raw body leaked into the error: %q", msg)
	}
}
