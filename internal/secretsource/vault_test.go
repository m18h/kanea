package secretsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func vaultFixture(t *testing.T, handler http.Handler, maps []syncMapping) *vaultProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	token := writeFile(t, t.TempDir(), "token", "hvs.token", 0o600)
	cfg := providerConfig{
		kind: KindVault, name: "infra",
		hcl:  hclProvider{TokenFile: token, Address: srv.URL, Mount: "kv"},
		maps: maps,
	}
	p, err := newVault(cfg, DefaultHTTPClient(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVaultGroupsMappingsByPath(t *testing.T) {
	maps := []syncMapping{
		{To: "media/s3-key", Path: "apps/media", Field: "s3_key"},
		{To: "media/s3-secret", Path: "apps/media", Field: "s3_secret"},
		{To: "media/db", Path: "apps/db", Field: "url"},
	}
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("X-Vault-Token"); got != "hvs.token" {
			t.Errorf("X-Vault-Token = %q", got)
		}
		switch r.URL.Path {
		case "/v1/kv/data/apps/media":
			_, _ = w.Write([]byte(`{"data": {"data": {"s3_key": "AK", "s3_secret": "SK"}, "metadata": {"version": 3}}}`))
		case "/v1/kv/data/apps/db":
			_, _ = w.Write([]byte(`{"data": {"data": {"url": "postgres://db"}}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	p := vaultFixture(t, handler, maps)

	res := p.Fetch(context.Background())
	if len(res.Failures) != 0 {
		t.Fatalf("Failures = %+v", res.Failures)
	}
	if len(res.Values) != 3 {
		t.Fatalf("Values = %+v", res.Values)
	}
	// Two fields out of one path is one read: the grouping is what keeps a
	// pass from hammering Vault once per field.
	if got := requests.Load(); got != 2 {
		t.Errorf("made %d requests, want 2", got)
	}
}

func TestVaultAMissingPathFailsOnlyItsMappings(t *testing.T) {
	maps := []syncMapping{
		{To: "media/ok", Path: "exists", Field: "v"},
		{To: "media/gone", Path: "missing", Field: "v"},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/kv/data/exists" {
			_, _ = w.Write([]byte(`{"data": {"data": {"v": "value"}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors": []}`))
	})
	p := vaultFixture(t, handler, maps)

	res := p.Fetch(context.Background())
	if len(res.Values) != 1 || res.Values[0].To != "media/ok" {
		t.Errorf("Values = %+v", res.Values)
	}
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "no secret at kv/missing") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

// A JSON object silently re-encoded into a credential file is a lie; a
// non-string field is refused by name.
func TestVaultRefusesANonStringField(t *testing.T) {
	maps := []syncMapping{
		{To: "media/bad", Path: "apps/media", Field: "nested"},
		{To: "media/absent", Path: "apps/media", Field: "no_such_field"},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data": {"data": {"nested": {"a": 1}}}}`))
	})
	p := vaultFixture(t, handler, maps)

	res := p.Fetch(context.Background())
	if len(res.Values) != 0 {
		t.Errorf("Values = %+v", res.Values)
	}
	if len(res.Failures) != 2 {
		t.Fatalf("Failures = %+v", res.Failures)
	}
	for _, f := range res.Failures {
		switch f.To {
		case "media/bad":
			if !strings.Contains(f.Err.Error(), "not a string") {
				t.Errorf("non-string error = %v", f.Err)
			}
		case "media/absent":
			if !strings.Contains(f.Err.Error(), `no field "no_such_field"`) {
				t.Errorf("missing-field error = %v", f.Err)
			}
		}
	}
}

// A KV v1 mount answers without the v2 envelope; the mistake is named rather
// than stored as an empty value.
func TestVaultNamesAKVv1Mount(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data": {"v": "value"}}`))
	})
	p := vaultFixture(t, handler, []syncMapping{{To: "media/a", Path: "p", Field: "v"}})

	res := p.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "KV v2") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}
