package secretsource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// azureFixture serves both the token endpoint and the vault from one fake.
type azureFixture struct {
	provider   *azureKVProvider
	tokenCalls atomic.Int32
	// serveToken is the token the endpoint mints; getStatus lets a test force
	// the vault's answer.
	serveToken atomic.Value // string
	rejectOnce atomic.Bool
}

func newAzureFixture(t *testing.T, secrets map[string]string, maps []syncMapping) *azureFixture {
	t.Helper()
	f := &azureFixture{}
	f.serveToken.Store("token-1")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-a/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		for key, want := range map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     "client-a",
			"client_secret": "sp-secret",
			"scope":         azureScope,
		} {
			if got := r.PostForm.Get(key); got != want {
				t.Errorf("token form %s = %q, want %q", key, got, want)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": f.serveToken.Load(), "expires_in": 3600,
		})
	})
	mux.HandleFunc("GET /secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if f.rejectOnce.CompareAndSwap(true, false) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": {"message": "token expired early"}}`))
			return
		}
		want := "Bearer " + f.serveToken.Load().(string)
		if got := r.Header.Get("Authorization"); got != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if got := r.URL.Query().Get("api-version"); got != azureAPIVersion {
			t.Errorf("api-version = %q", got)
		}
		value, ok := secrets[r.PathValue("name")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": {"code": "SecretNotFound", "message": "not found"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	secretFile := writeFile(t, t.TempDir(), "azure.secret", "sp-secret", 0o600)
	cfg := providerConfig{
		kind: KindAzure, name: "corp",
		hcl: hclProvider{VaultURI: srv.URL, TenantID: "tenant-a", ClientID: "client-a",
			ClientSecretFile: secretFile, LoginURL: srv.URL},
		maps: maps,
	}
	f.provider = newAzureKV(cfg, DefaultHTTPClient(), discardLogger())
	return f
}

func TestAzureKVFetchAndTokenCache(t *testing.T) {
	f := newAzureFixture(t, map[string]string{"db-password": "hunter2"},
		[]syncMapping{{To: "shop/db-password", Name: "db-password"}})

	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 0 || len(res.Values) != 1 || string(res.Values[0].Data) != "hunter2" {
		t.Fatalf("Values = %+v, Failures = %+v", res.Values, res.Failures)
	}

	// A second pass on the same instance reuses the token: the reason
	// Providers.Current keeps instances stable across unchanged passes.
	res = f.provider.Fetch(context.Background())
	if len(res.Failures) != 0 {
		t.Fatalf("second pass: %+v", res.Failures)
	}
	if got := f.tokenCalls.Load(); got != 1 {
		t.Errorf("token endpoint was called %d times across two passes, want 1", got)
	}
}

func TestAzureKVRefreshesANearExpiryToken(t *testing.T) {
	f := newAzureFixture(t, map[string]string{"a": "v"},
		[]syncMapping{{To: "shop/a", Name: "a"}})

	now := time.Now()
	f.provider.now = func() time.Time { return now }
	f.provider.Fetch(context.Background())

	// Just inside the slack window: the cached token must not be trusted.
	now = now.Add(3600*time.Second - tokenExpirySlack + time.Second)
	f.provider.Fetch(context.Background())
	if got := f.tokenCalls.Load(); got != 2 {
		t.Errorf("token endpoint was called %d times, want 2 (refresh near expiry)", got)
	}
}

// One 401 is an early-revoked token and gets one fresh retry; the failure
// only surfaces when the fresh token is refused too.
func TestAzureKVRetriesOnceOnA401(t *testing.T) {
	f := newAzureFixture(t, map[string]string{"a": "v"},
		[]syncMapping{{To: "shop/a", Name: "a"}})

	f.provider.Fetch(context.Background()) // prime the cache
	f.rejectOnce.Store(true)
	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 0 || len(res.Values) != 1 {
		t.Fatalf("Values = %+v, Failures = %+v", res.Values, res.Failures)
	}
	if got := f.tokenCalls.Load(); got != 2 {
		t.Errorf("token endpoint was called %d times, want 2 (one refresh after the 401)", got)
	}
}

func TestAzureKVAMissingSecretFailsByName(t *testing.T) {
	f := newAzureFixture(t, map[string]string{},
		[]syncMapping{{To: "shop/gone", Name: "gone"}})

	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "not found") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

func TestAzureKVRequestsAVersionWhenMapped(t *testing.T) {
	var path atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("POST /t/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "pinned"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	secretFile := writeFile(t, t.TempDir(), "azure.secret", "s", 0o600)
	cfg := providerConfig{
		kind: KindAzure, name: "corp",
		hcl: hclProvider{VaultURI: srv.URL, TenantID: "t", ClientID: "c",
			ClientSecretFile: secretFile, LoginURL: srv.URL},
		maps: []syncMapping{{To: "shop/a", Name: "a", Version: "abc123"}},
	}
	p := newAzureKV(cfg, DefaultHTTPClient(), discardLogger())

	res := p.Fetch(context.Background())
	if len(res.Failures) != 0 {
		t.Fatalf("Failures = %+v", res.Failures)
	}
	if got := path.Load(); got != "/secrets/a/abc123" {
		t.Errorf("path = %v, want /secrets/a/abc123", got)
	}
}
