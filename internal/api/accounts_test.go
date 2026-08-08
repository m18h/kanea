package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
)

func TestAccountRoutesAreAdminOnly(t *testing.T) {
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleViewer)

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, api.PathUsers, nil},
		{http.MethodPut, api.PathUsers + "/mallory", api.UserRequest{Password: "a-long-enough-one", Role: auth.RoleAdmin}},
		{http.MethodDelete, api.PathUsers + "/" + adminUser, nil},
		{http.MethodGet, api.PathTokens, nil},
		{http.MethodPost, api.PathTokens, api.TokenRequest{Name: "ci", Role: auth.RoleAdmin}},
		{http.MethodDelete, api.PathTokens + "/deadbeef", nil},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := h.request(t, tc.method, tc.path, tc.body)
			req.Header.Set("Authorization", "Bearer "+token)
			if resp, body := h.do(t, req); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", resp.StatusCode, body)
			}
		})
	}
}

func TestUserLifecycle(t *testing.T) {
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleAdmin)

	// Create.
	req := h.request(t, http.MethodPut, api.PathUsers+"/grace",
		api.UserRequest{Password: "a-perfectly-fine-passphrase", Role: auth.RoleViewer})
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}

	// List, and never a hash.
	req = h.request(t, http.MethodGet, api.PathUsers, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d: %s", resp.StatusCode, body)
	}
	if strings.Contains(body, "$2a$") || strings.Contains(body, "password_hash\":\"$") {
		t.Fatalf("a password hash reached the API: %s", body)
	}

	var users api.UsersResponse
	if err := json.Unmarshal([]byte(body), &users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users.Users) != 3 {
		t.Fatalf("users = %d, want 3", len(users.Users))
	}

	// The new account works.
	if _, csrf := h.login(t, "grace", "a-perfectly-fine-passphrase"); csrf == "" {
		t.Fatal("the new account cannot log in")
	}

	// Delete.
	req = h.request(t, http.MethodDelete, api.PathUsers+"/grace", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", resp.StatusCode, body)
	}

	// And the password stops working the moment the account is gone.
	req = h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: "grace", Password: "a-perfectly-fine-passphrase"})
	if resp, _ := h.do(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login for a deleted account = %d, want 401", resp.StatusCode)
	}
}

func TestWeakPasswordIsRefused(t *testing.T) {
	h := newAuthHarness(t)
	req := h.request(t, http.MethodPut, api.PathUsers+"/grace",
		api.UserRequest{Password: "short", Role: auth.RoleViewer})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))

	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "12") {
		t.Errorf("the refusal does not say what would be acceptable: %s", body)
	}
}

func TestRemovingTheLastAdminIsRefused(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleAdmin)

	req := h.request(t, http.MethodDelete, api.PathUsers+"/"+adminUser, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", resp.StatusCode, body)
	}

	// The account is still there and still an admin.
	users, err := h.users.Users(ctx)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	for _, u := range users {
		if u.Name == adminUser && u.Role == auth.RoleAdmin {
			return
		}
	}
	t.Fatal("the last admin was removed anyway")
}

func TestDemotingTheLastAdminIsRefused(t *testing.T) {
	h := newAuthHarness(t)
	req := h.request(t, http.MethodPut, api.PathUsers+"/"+adminUser,
		api.UserRequest{Password: adminPass, Role: auth.RoleViewer})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))

	if resp, body := h.do(t, req); resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", resp.StatusCode, body)
	}
}

func TestASecondAdminMakesTheFirstRemovable(t *testing.T) {
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleAdmin)

	req := h.request(t, http.MethodPut, api.PathUsers+"/second-admin",
		api.UserRequest{Password: "yet-another-long-passphrase", Role: auth.RoleAdmin})
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}

	req = h.request(t, http.MethodDelete, api.PathUsers+"/"+adminUser, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 now that another admin exists: %s", resp.StatusCode, body)
	}
}

func TestTokenLifecycle(t *testing.T) {
	h := newAuthHarness(t)
	admin := h.token(t, auth.RoleAdmin)

	req := h.request(t, http.MethodPost, api.PathTokens,
		api.TokenRequest{Name: "ci", Role: auth.RoleViewer, ExpiresIn: "720h"})
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}

	var created api.TokenResponse
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Secret == "" || !strings.HasPrefix(created.Secret, auth.TokenPrefix) {
		t.Fatalf("secret = %q, want a kanea_-prefixed token", created.Secret)
	}
	if created.Token.Hash != "" {
		t.Error("the stored hash was returned; only the secret should leave")
	}
	if created.Token.Expires.IsZero() {
		t.Error("expires_in was ignored")
	}

	// The minted token works, at the role it was given.
	req = h.request(t, http.MethodGet, api.PathServices, nil)
	req.Header.Set("Authorization", "Bearer "+created.Secret)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("minted token read = %d: %s", resp.StatusCode, body)
	}
	req = h.request(t, http.MethodPut, api.PathServices, api.ApplyRequest{})
	req.Header.Set("Authorization", "Bearer "+created.Secret)
	if resp, _ := h.do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer token write = %d, want 403", resp.StatusCode)
	}

	// Revoking it takes effect immediately — that is the point of storing a
	// hash server-side rather than a self-contained credential.
	req = h.request(t, http.MethodDelete, api.PathTokens+"/"+created.Token.ID, nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d: %s", resp.StatusCode, body)
	}
	req = h.request(t, http.MethodGet, api.PathServices, nil)
	req.Header.Set("Authorization", "Bearer "+created.Secret)
	if resp, _ := h.do(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token = %d, want 401", resp.StatusCode)
	}
}

func TestTokenListingCarriesNoSecrets(t *testing.T) {
	h := newAuthHarness(t)
	admin := h.token(t, auth.RoleAdmin)

	req := h.request(t, http.MethodPost, api.PathTokens,
		api.TokenRequest{Name: "ci", Role: auth.RoleViewer})
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	var created api.TokenResponse
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	req = h.request(t, http.MethodGet, api.PathTokens, nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	_, listing := h.do(t, req)
	if strings.Contains(listing, created.Secret) {
		t.Fatal("the token secret is in the listing; it is shown exactly once, at creation")
	}
	secret := strings.SplitN(created.Secret, ".", 2)[1]
	if strings.Contains(listing, secret) {
		t.Fatal("the secret half of the token is in the listing")
	}
}

func TestBadTokenTTLIsRejected(t *testing.T) {
	h := newAuthHarness(t)
	for _, ttl := range []string{"soon", "-1h", "0s"} {
		t.Run(ttl, func(t *testing.T) {
			req := h.request(t, http.MethodPost, api.PathTokens,
				api.TokenRequest{Name: "ci", Role: auth.RoleViewer, ExpiresIn: ttl})
			req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
			if resp, body := h.do(t, req); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
			}
		})
	}
}

func TestAccountChangesAreAudited(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleAdmin)

	req := h.request(t, http.MethodPut, api.PathUsers+"/grace",
		api.UserRequest{Password: "a-perfectly-fine-passphrase", Role: auth.RoleViewer})
	req.Header.Set("Authorization", "Bearer "+token)
	h.do(t, req)

	page, err := h.audit.List(ctx, audit.Filter{Action: "user.put"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(page.Entries))
	}
	if page.Entries[0].Target != "grace" {
		t.Errorf("target = %q, want grace", page.Entries[0].Target)
	}
	raw, err := json.Marshal(page.Entries[0])
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(raw), "passphrase") {
		t.Fatalf("the new password reached the audit log: %s", raw)
	}
}

func TestAccountRoutesAreOffWithoutAnAccountStore(t *testing.T) {
	h := newAuthHarness(t, func(cfg *api.ServerConfig) { cfg.Accounts = nil })
	req := h.request(t, http.MethodGet, api.PathUsers, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))

	if resp, body := h.do(t, req); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", resp.StatusCode, body)
	}
}
