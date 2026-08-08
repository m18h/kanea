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

// stubProvider stands in for an identity provider. The protocol itself is
// tested against a real one in internal/auth; what matters here is what the
// routes do with the answer.
type stubProvider struct {
	handle string
	result auth.OIDCResult
	err    error
	// seen records what Complete was called with.
	seenHandle, seenState, seenCode string
}

func (s *stubProvider) Start(next string) (string, string, error) {
	s.result.Next = next
	return "https://idp.example/authorize?state=abc", s.handle, nil
}

func (s *stubProvider) Complete(_ context.Context, handle, state, code string) (auth.OIDCResult, error) {
	s.seenHandle, s.seenState, s.seenCode = handle, state, code
	if s.err != nil {
		return auth.OIDCResult{}, s.err
	}
	return s.result, nil
}

func (s *stubProvider) Issuer() string { return "https://idp.example" }

func withProvider(p *stubProvider) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) {
		cfg.OIDC = p
		cfg.Sessions, _ = cfg.Auth.(api.SessionIssuer)
	}
}

func newProviderHarness(t *testing.T, p *stubProvider) *authHarness {
	t.Helper()
	return newAuthHarness(t, withProvider(p))
}

func TestOIDCStartRedirectsAndSetsAHandle(t *testing.T) {
	h := newProviderHarness(t, &stubProvider{handle: "handle-1"})

	resp, _ := h.do(t, h.request(t, http.MethodGet, api.PathOIDCStart+"?next=/services", nil))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got == "" {
		t.Fatal("no Location on the redirect")
	}

	var found bool
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "kanea_oidc" {
			found = true
			if !cookie.HttpOnly {
				t.Error("the login handle is readable from script")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Error("Strict would break the provider's redirect back")
			}
		}
	}
	if !found {
		t.Fatal("no handle cookie was set")
	}
}

func TestOIDCCallbackIssuesASession(t *testing.T) {
	provider := &stubProvider{
		handle: "handle-1",
		result: auth.OIDCResult{Subject: "ada@example.com", Role: auth.RoleAdmin, Next: "/services"},
	}
	h := newProviderHarness(t, provider)

	req := h.request(t, http.MethodGet, api.PathOIDCCallback+"?state=abc&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: "kanea_oidc", Value: "handle-1"})
	resp, body := h.do(t, req)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/services" {
		t.Errorf("Location = %q, want the page the login started from", got)
	}
	if provider.seenState != "abc" || provider.seenCode != "xyz" {
		t.Errorf("callback passed state=%q code=%q", provider.seenState, provider.seenCode)
	}

	var session *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == api.SessionCookie && cookie.Value != "" {
			session = cookie
		}
		if cookie.Name == "kanea_oidc" && cookie.MaxAge >= 0 {
			t.Error("the login handle was left usable after the callback")
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}

	// The session must actually work, with the role the provider's claims gave.
	req = h.request(t, http.MethodGet, api.PathSession, nil)
	req.AddCookie(session)
	resp, body = h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session = %d: %s", resp.StatusCode, body)
	}
	var current api.SessionResponse
	if err := json.Unmarshal([]byte(body), &current); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if current.Subject != "ada@example.com" || current.Role != auth.RoleAdmin {
		t.Errorf("session = %+v, want the provider's identity", current)
	}
}

func TestOIDCCallbackWithoutAHandleIsRefused(t *testing.T) {
	h := newProviderHarness(t, &stubProvider{handle: "handle-1"})

	// A callback with a state but no cookie is someone else's login being
	// replayed into this browser.
	resp, _ := h.do(t, h.request(t, http.MethodGet, api.PathOIDCCallback+"?state=abc&code=xyz", nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestOIDCNoRoleIsForbiddenNotUnauthorized(t *testing.T) {
	ctx := context.Background()
	provider := &stubProvider{handle: "handle-1", err: auth.ErrOIDCNoRole}
	h := newProviderHarness(t, provider)

	req := h.request(t, http.MethodGet, api.PathOIDCCallback+"?state=abc&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: "kanea_oidc", Value: "handle-1"})
	resp, _ := h.do(t, req)

	// "The provider vouched for you and Kanea has no role for you" is a
	// different problem from "log in again", and the status has to say which.
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	page, err := h.audit.List(ctx, audit.Filter{Action: "auth.login"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Result != audit.ResultDenied {
		t.Fatalf("entries = %+v, want one denied login", page.Entries)
	}
	if page.Entries[0].Via != string(auth.MethodOIDC) {
		t.Errorf("via = %q, want oidc", page.Entries[0].Via)
	}
}

func TestOIDCProviderErrorIsNotEchoedBack(t *testing.T) {
	h := newProviderHarness(t, &stubProvider{handle: "handle-1"})

	// A crafted redirect must not be able to put arbitrary text on Kanea's page.
	req := h.request(t, http.MethodGet,
		api.PathOIDCCallback+"?error=access_denied&error_description=CALL+555+FOR+SUPPORT", nil)
	req.AddCookie(&http.Cookie{Name: "kanea_oidc", Value: "handle-1"})
	resp, body := h.do(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if strings.Contains(body, "555") {
		t.Fatalf("the provider's text was echoed to the caller: %s", body)
	}
}

func TestOIDCRoutesAnswer501WhenNoProviderIsConfigured(t *testing.T) {
	h := newAuthHarness(t) // no provider
	for _, path := range []string{api.PathOIDCStart, api.PathOIDCCallback} {
		resp, body := h.do(t, h.request(t, http.MethodGet, path, nil))
		// 501, not 404: "this daemon has no provider" and "no such feature" are
		// different answers, and the dashboard shows a different thing for each.
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s = %d, want 501: %s", path, resp.StatusCode, body)
		}
		if !strings.Contains(body, "identity provider") {
			t.Errorf("%s does not say why: %s", path, body)
		}
	}
}

func TestHealthAdvertisesTheProvider(t *testing.T) {
	h := newProviderHarness(t, &stubProvider{handle: "handle-1"})

	// The login screen needs this before it has any credential to ask with,
	// and health is the route it can reach unauthenticated.
	resp, body := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d: %s", resp.StatusCode, body)
	}

	var health api.Health
	if err := json.Unmarshal([]byte(body), &health); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if health.OIDC == nil || !health.OIDC.Enabled {
		t.Fatalf("health does not advertise the provider: %s", body)
	}
	if health.OIDC.Issuer != "https://idp.example" || health.OIDC.StartPath != api.PathOIDCStart {
		t.Errorf("provider status = %+v", health.OIDC)
	}
}

func TestHealthOmitsTheProviderWhenThereIsNone(t *testing.T) {
	h := newAuthHarness(t)
	_, body := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))

	var health api.Health
	if err := json.Unmarshal([]byte(body), &health); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if health.OIDC != nil {
		t.Fatalf("a daemon with no provider advertises one: %+v", health.OIDC)
	}
}
