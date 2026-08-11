package api_test

// Directory-login routes and — most importantly — the v1.47 CSRF allowlist.
// The directory protocol is internal/auth's problem; a stub verifier stands in
// (the stubProvider pattern), and what is under test is what the routes do
// with each answer.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/store"
)

const ldapServerURL = "ldaps://dc.example.test:636"

// stubVerifier answers for the directory.
type stubVerifier struct {
	subject string
	role    auth.Role
	err     error
	calls   int
}

func (s *stubVerifier) Verify(_ context.Context, name, _ string) (string, auth.Role, error) {
	s.calls++
	if s.err != nil {
		return "", "", s.err
	}
	if s.subject != "" {
		return s.subject, s.role, nil
	}
	return name, s.role, nil
}

// withLDAP rebuilds the harness's auth store over the same backing Store with
// a directory verifier wired in, and tells the server the directory's name —
// which is how a real kanead is assembled (cmd/kanea/ldap.go).
func withLDAP(t *testing.T, v auth.PasswordVerifier) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) {
		st, ok := cfg.Store.(store.Store)
		if !ok {
			t.Fatalf("harness store %T does not implement store.Store", cfg.Store)
		}
		users, err := auth.NewStore(auth.StoreConfig{Store: st, Verifier: v})
		if err != nil {
			t.Fatalf("auth store with a verifier: %v", err)
		}
		cfg.Auth = users
		cfg.LDAPServer = ldapServerURL
	}
}

// TestCookieMutationViaAnExternalLoginStillNeedsCSRF is the v1.47 regression
// test: checkCSRF skips by an allowlist (token, socket), never by "unless the
// Via is session". An "ldap" or "oidc" session is still a browser cookie a
// cross-site request can ride, and the old predicate — skip unless
// MethodSession — would have silently exempted both.
func TestCookieMutationViaAnExternalLoginStillNeedsCSRF(t *testing.T) {
	h := newAuthHarness(t)
	ctx := context.Background()

	for _, method := range []auth.Method{auth.MethodLDAP, auth.MethodOIDC} {
		t.Run(string(method), func(t *testing.T) {
			session, cookieValue, err := h.users.CreateSession(
				ctx, "dirk-"+string(method), auth.RoleAdmin, method)
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			cookie := &http.Cookie{Name: api.SessionCookie, Value: cookieValue}

			// Without the header: the request a cross-site form post would make.
			req := h.request(t, http.MethodPut, api.PathServices, api.ApplyRequest{})
			req.AddCookie(cookie)
			resp, body := h.do(t, req)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("mutation without CSRF = %d, want 403: %s", resp.StatusCode, body)
			}

			// With the right token, authentication is satisfied and the empty
			// apply reaches the handler's own 400.
			req = h.request(t, http.MethodPut, api.PathServices, api.ApplyRequest{})
			req.AddCookie(cookie)
			req.Header.Set(api.CSRFHeader, session.CSRF)
			resp, body = h.do(t, req)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("mutation with CSRF = %d, want 400 from the handler: %s",
					resp.StatusCode, body)
			}
		})
	}
}

func TestSocketMutationNeedsNoCSRFToken(t *testing.T) {
	// The other half of the allowlist (bearer tokens are covered by
	// TestBearerMutationNeedsNoCSRFToken): a socket caller is not a browser,
	// so there is no ambient credential for a third party to ride.
	h := newHarness(t)
	status, body := h.raw(t, http.MethodPut, api.PathServices)
	if status != http.StatusBadRequest {
		t.Fatalf("socket mutation = %d, want 400 from the handler, not a CSRF 403: %s",
			status, body)
	}
}

func TestSessionRouteHandsExternalLoginsTheirCSRFToken(t *testing.T) {
	// The regression the checkCSRF allowlist almost created: this route is the
	// only place a cookie client can learn its CSRF token (the OIDC callback
	// is a redirect with no body, and a page reload loses the login response).
	// If it answered only Via == "session" while checkCSRF demanded the token
	// from every cookie caller, an external login could never mutate again.
	h := newAuthHarness(t)
	ctx := context.Background()

	for _, method := range []auth.Method{auth.MethodLDAP, auth.MethodOIDC} {
		t.Run(string(method), func(t *testing.T) {
			session, cookieValue, err := h.users.CreateSession(
				ctx, "dirk-"+string(method), auth.RoleAdmin, method)
			if err != nil {
				t.Fatalf("CreateSession: %v", err)
			}

			req := h.request(t, http.MethodGet, api.PathSession, nil)
			req.AddCookie(&http.Cookie{Name: api.SessionCookie, Value: cookieValue})
			resp, body := h.do(t, req)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("session = %d: %s", resp.StatusCode, body)
			}

			var out api.SessionResponse
			if err := json.Unmarshal([]byte(body), &out); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if out.Via != string(method) {
				t.Errorf("via = %q, want %q", out.Via, method)
			}
			if out.CSRF != session.CSRF {
				t.Errorf("CSRF = %q, want the session's own token — a cookie client has nowhere else to get one", out.CSRF)
			}
		})
	}
}

func TestLoginThroughTheDirectorySaysViaLDAP(t *testing.T) {
	ctx := context.Background()
	v := &stubVerifier{subject: "dirk", role: auth.RoleAdmin}
	h := newAuthHarness(t, withLDAP(t, v))

	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: "dirk", Password: "a-directory-password"})
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("directory login = %d: %s", resp.StatusCode, body)
	}
	if v.calls != 1 {
		t.Fatalf("verifier consulted %d times, want 1", v.calls)
	}

	var session api.SessionResponse
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session.Via != string(auth.MethodLDAP) {
		t.Errorf("via = %q, want ldap", session.Via)
	}
	if session.Subject != "dirk" || session.Role != auth.RoleAdmin {
		t.Errorf("session = %+v, want the verifier's identity", session)
	}
	// A directory session is still a cookie session, so it still gets the
	// double-submit token the browser will need for mutations.
	if session.CSRF == "" {
		t.Error("no CSRF token on a directory login")
	}

	// The audit entry names the mechanism and the directory (the OIDC
	// "issuer …" rule, for LDAP).
	page, err := h.audit.List(ctx, audit.Filter{Action: "auth.login"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("audit entries = %d, want 1: %+v", len(page.Entries), page.Entries)
	}
	entry := page.Entries[0]
	if entry.Result != audit.ResultOK || entry.Actor != "dirk" {
		t.Errorf("entry = %+v, want an OK login by dirk", entry)
	}
	if entry.Via != string(auth.MethodLDAP) {
		t.Errorf("audit via = %q, want ldap", entry.Via)
	}
	if entry.Detail != "server "+ldapServerURL {
		t.Errorf("audit detail = %q, want %q", entry.Detail, "server "+ldapServerURL)
	}
}

func TestDirectoryNoRoleAnswersForbidden(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t, withLDAP(t, &stubVerifier{err: auth.ErrLDAPNoRole}))

	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: "dirk", Password: "a-directory-password"})
	resp, body := h.do(t, req)
	// "The directory vouched for you and Kanea has no role for you" is a
	// different problem from "log in again", and the status has to say which
	// (the OIDC no-role rule).
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-role login = %d, want 403: %s", resp.StatusCode, body)
	}

	page, err := h.audit.List(ctx, audit.Filter{Action: "auth.login"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(page.Entries))
	}
	entry := page.Entries[0]
	if entry.Result != audit.ResultDenied || entry.Target != "dirk" {
		t.Errorf("entry = %+v, want a denied login naming the attempted user", entry)
	}
}

func TestDirectoryRefusalAnswersUnauthorized(t *testing.T) {
	h := newAuthHarness(t, withLDAP(t,
		&stubVerifier{err: errors.New("the directory refused the password")}))

	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: "dirk", Password: "not-the-password"})
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refused directory login = %d, want 401: %s", resp.StatusCode, body)
	}
	// The same generic refusal every other bad credential gets (§14, A07):
	// the caller must not learn a directory was even involved.
	if strings.Contains(strings.ToLower(body), "directory") {
		t.Errorf("the refusal names the directory: %s", body)
	}
}
