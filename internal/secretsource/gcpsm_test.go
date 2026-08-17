package secretsource

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type gcpFixture struct {
	provider   *gcpsmProvider
	tokenCalls atomic.Int32
	corrupt    atomic.Bool
}

// newGCPFixture builds a fake token endpoint that verifies the RS256
// assertion against the test key (a signature the verifier does not check is
// the MinIO lesson again) plus a Secret Manager `:access` surface.
func newGCPFixture(t *testing.T, secrets map[string]string, maps []syncMapping) *gcpFixture {
	t.Helper()
	f := &gcpFixture{}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if got := r.PostForm.Get("grant_type"); got != gcpJWTBearerGrant {
			t.Errorf("grant_type = %q", got)
		}
		assertion := r.PostForm.Get("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("assertion has %d segments", len(parts))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Errorf("signature encoding: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
			t.Errorf("the assertion's signature does not verify: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var claims struct {
			Iss   string `json:"iss"`
			Scope string `json:"scope"`
			Aud   string `json:"aud"`
		}
		claimJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if err := json.Unmarshal(claimJSON, &claims); err != nil {
			t.Errorf("claims: %v", err)
		}
		if claims.Iss != "sync@test-project.iam.gserviceaccount.com" || claims.Scope != gcpScope {
			t.Errorf("claims = %+v", claims)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gcp-token", "expires_in": 3600})
	})
	mux.HandleFunc("GET /v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		// The path is /v1/projects/{p}/secrets/{name}/versions/{version}:access;
		// ServeMux wildcards cannot carry the ":access" suffix, so parse by hand.
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/projects/"), "/")
		if len(parts) != 5 || parts[1] != "secrets" || parts[3] != "versions" ||
			!strings.HasSuffix(parts[4], ":access") {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		project, name, version := parts[0], parts[2], strings.TrimSuffix(parts[4], ":access")
		if got := r.Header.Get("Authorization"); got != "Bearer gcp-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if project != "test-project" {
			t.Errorf("project = %q", project)
		}
		value, ok := secrets[name+"@"+version]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": {"message": "secret not found"}}`))
			return
		}
		sum := crc32.Checksum([]byte(value), crc32.MakeTable(crc32.Castagnoli))
		if f.corrupt.Load() {
			sum++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"payload": map[string]any{
				"data":       base64.StdEncoding.EncodeToString([]byte(value)),
				"dataCrc32c": fmt.Sprintf("%d", sum),
			},
		})
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	saKey, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "sync@test-project.iam.gserviceaccount.com",
		"private_key":  string(keyPEM),
		"token_uri":    srv.URL + "/token",
		"project_id":   "test-project",
	})
	if err != nil {
		t.Fatal(err)
	}
	credFile := writeFile(t, t.TempDir(), "gcp-sa.json", string(saKey), 0o600)

	cfg := providerConfig{
		kind: KindGCP, name: "prod",
		hcl:  hclProvider{CredentialsFile: credFile, Endpoint: srv.URL},
		maps: maps,
	}
	f.provider = newGCPSM(cfg, DefaultHTTPClient(), discardLogger())
	return f
}

func TestGCPSMFetchAndTokenCache(t *testing.T) {
	f := newGCPFixture(t, map[string]string{"db-password@latest": "hunter2"},
		[]syncMapping{{To: "shop/db-password", Name: "db-password", Version: "latest"}})

	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 0 || len(res.Values) != 1 || string(res.Values[0].Data) != "hunter2" {
		t.Fatalf("Values = %+v, Failures = %+v", res.Values, res.Failures)
	}

	res = f.provider.Fetch(context.Background())
	if len(res.Failures) != 0 {
		t.Fatalf("second pass: %+v", res.Failures)
	}
	if got := f.tokenCalls.Load(); got != 1 {
		t.Errorf("token endpoint was called %d times across two passes, want 1", got)
	}
}

func TestGCPSMRequestsThePinnedVersion(t *testing.T) {
	f := newGCPFixture(t, map[string]string{"key@7": "old-but-pinned"},
		[]syncMapping{{To: "shop/key", Name: "key", Version: "7"}})

	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 0 || string(res.Values[0].Data) != "old-but-pinned" {
		t.Errorf("Values = %+v, Failures = %+v", res.Values, res.Failures)
	}
}

// The API sends a checksum so a client can notice corruption before acting on
// the value; a mismatch is a refusal, not a warning.
func TestGCPSMRefusesABadChecksum(t *testing.T) {
	f := newGCPFixture(t, map[string]string{"a@latest": "v"},
		[]syncMapping{{To: "shop/a", Name: "a", Version: "latest"}})
	f.corrupt.Store(true)

	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "crc32c") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}

func TestGCPSMAMissingSecretFailsByName(t *testing.T) {
	f := newGCPFixture(t, map[string]string{},
		[]syncMapping{{To: "shop/gone", Name: "gone", Version: "latest"}})

	res := f.provider.Fetch(context.Background())
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Err.Error(), "secret not found") {
		t.Errorf("Failures = %+v", res.Failures)
	}
}
