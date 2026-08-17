package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/secretsource"
)

// The secrets surface is write-only (PRD §13.3, §16.3): there is no route that
// returns a value, and its absence is the enforcement.
func TestSecretsHaveNoReadRoute(t *testing.T) {
	h := newHarness(t, withSecrets)
	ctx := context.Background()

	if err := h.client.PutSecret(ctx, "shop/token", []byte("hunter2")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	// Every plausible read shape must fail, and none may return the value.
	for _, path := range []string{
		"/v1/secrets/shop/token",
		"/v1/secrets/shop/token/value",
		"/v1/secrets?path=shop/token",
	} {
		status, body := h.raw(t, http.MethodGet, path)
		if strings.Contains(body, "hunter2") {
			t.Fatalf("GET %s leaked the secret value", path)
		}
		if status == http.StatusOK && strings.Contains(body, "<html") {
			t.Errorf("GET %s fell through to the dashboard with 200", path)
		}
	}
}

// A mistyped or removed API route must be a 404, not the SPA with 200: a
// client would otherwise see success and fail to decode it somewhere else.
func TestUnmatchedAPIRoutesAreNotTheDashboard(t *testing.T) {
	h := newHarness(t, withSecrets)

	for _, path := range []string{"/v1/nope", "/v1/secrets/shop/token", "/v1/services/extra/bits"} {
		status, body := h.raw(t, http.MethodGet, path)
		if status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, status)
		}
		if strings.Contains(body, "<html") {
			t.Errorf("GET %s returned HTML", path)
		}
	}
}

func TestSecretsListReturnsMetadataOnly(t *testing.T) {
	h := newHarness(t, withSecrets)
	ctx := context.Background()

	if err := h.client.PutSecret(ctx, "shop/token", []byte("hunter2")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	status, body := h.raw(t, http.MethodGet, "/v1/secrets")
	if status != http.StatusOK {
		t.Fatalf("list = %d", status)
	}
	if strings.Contains(body, "hunter2") {
		t.Fatal("the listing includes the value")
	}
	if !strings.Contains(body, "shop/token") {
		t.Errorf("the listing does not name the secret: %s", body)
	}
}

func TestSecretDelete(t *testing.T) {
	h := newHarness(t, withSecrets)
	ctx := context.Background()

	if err := h.client.PutSecret(ctx, "shop/token", []byte("v")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := h.client.DeleteSecret(ctx, "shop/token"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	infos, err := h.client.ListSecrets(ctx, "")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("secrets remain after delete: %+v", infos)
	}
}

// Without a configured store the routes must refuse rather than pretend.
func TestSecretsUnavailableWithoutAStore(t *testing.T) {
	h := newHarness(t)
	status, _ := h.raw(t, http.MethodGet, "/v1/secrets")
	if status != http.StatusServiceUnavailable {
		t.Errorf("list without a store = %d, want 503", status)
	}
}

// The sync status surface (PRD §5.2.13): metadata only, and absent (with a
// pointer at the flag) on a node with no providers configured.
func TestSecretProvidersStatus(t *testing.T) {
	status := []secretsource.ProviderStatus{{
		Kind: secretsource.KindDoppler, Name: "ci", Mappings: 1,
		Entries: []secretsource.MappingStatus{{To: "shop/db-url", Ref: "backend/prd/DATABASE_URL"}},
	}}
	h := newHarness(t, withSecrets, func(cfg *api.ServerConfig) {
		cfg.SecretSync = fixedSecretSync(status)
	})

	code, body := h.raw(t, http.MethodGet, "/v1/secrets/providers")
	if code != http.StatusOK {
		t.Fatalf("providers = %d", code)
	}
	for _, want := range []string{"doppler", "ci", "shop/db-url", "backend/prd/DATABASE_URL"} {
		if !strings.Contains(body, want) {
			t.Errorf("status is missing %q: %s", want, body)
		}
	}
}

func TestSecretProvidersAbsentWhenUnconfigured(t *testing.T) {
	h := newHarness(t, withSecrets)
	code, body := h.raw(t, http.MethodGet, "/v1/secrets/providers")
	if code != http.StatusNotFound {
		t.Errorf("providers without config = %d, want 404", code)
	}
	if !strings.Contains(body, "secrets-providers-config") {
		t.Errorf("the refusal does not name the flag: %s", body)
	}
}

// The listing carries provenance now (§5.2.13); still never a value.
func TestSecretsListCarriesTheSource(t *testing.T) {
	h := newHarness(t, withSecrets, func(cfg *api.ServerConfig) {
		// Reach the underlying store through the concrete type to plant a
		// managed secret the API itself has no verb to create.
		s := cfg.Secrets.(*secrets.Store)
		if err := s.PutManaged(context.Background(), "shop/db", []byte("v"), "doppler/ci"); err != nil {
			panic(err)
		}
	})

	infos, err := h.client.ListSecrets(context.Background(), "")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(infos) != 1 || infos[0].Source != "doppler/ci" {
		t.Errorf("infos = %+v, want one entry sourced doppler/ci", infos)
	}
}

// fixedSecretSync satisfies api.SecretSyncStatus with a literal.
type fixedSecretSync []secretsource.ProviderStatus

func (f fixedSecretSync) Status() []secretsource.ProviderStatus { return f }
