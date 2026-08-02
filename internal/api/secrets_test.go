package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
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

// A mistyped or removed API route must be a 404, not the SPA with 200 — a
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
