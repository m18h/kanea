package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/audit"
	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/store"
)

// authHarness serves the API over TCP, which is the only way to exercise the
// middleware: a unix-socket caller is the local root of §13.1 and is admitted by
// the socket's file mode, so every check below would be skipped on it.
type authHarness struct {
	server *httptest.Server
	store  store.Store
	users  *auth.Store
	audit  *audit.Log
	client *http.Client
}

const (
	adminUser  = "ada"
	adminPass  = "correct-horse-battery-staple"
	viewerUser = "vic"
	viewerPass = "another-long-passphrase"
)

func newAuthHarness(t *testing.T, with ...func(*api.ServerConfig)) *authHarness {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	users, err := auth.NewStore(auth.StoreConfig{Store: st})
	if err != nil {
		t.Fatalf("auth store: %v", err)
	}
	if err := users.PutUser(ctx, adminUser, adminPass, auth.RoleAdmin); err != nil {
		t.Fatalf("put admin: %v", err)
	}
	if err := users.PutUser(ctx, viewerUser, viewerPass, auth.RoleViewer); err != nil {
		t.Fatalf("put viewer: %v", err)
	}

	trail, err := audit.Open(ctx, audit.Config{Store: st})
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}

	cfg := api.ServerConfig{
		Store: st, Version: "test", LogDir: t.TempDir(),
		Auth: users, Accounts: users, Audit: trail, InsecureCookies: true,
	}
	for _, apply := range with {
		apply(&cfg)
	}
	server, err := api.NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)

	return &authHarness{
		server: ts, store: st, users: users, audit: trail,
		// Redirects are never expected here, and following one silently would
		// turn a 401 into whatever the next page said.
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// request builds a request against the harness. Body may be nil.
func (h *authHarness) request(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.server.URL+path, reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// do sends a request and returns the response with its body already read.
func (h *authHarness) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// login performs a password login and returns the session cookie and CSRF token.
func (h *authHarness) login(t *testing.T, user, password string) (*http.Cookie, string) {
	t.Helper()
	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: user, Password: password})
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d: %s", user, resp.StatusCode, body)
	}

	var session api.SessionResponse
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == api.SessionCookie {
			return cookie, session.CSRF
		}
	}
	t.Fatalf("login set no %s cookie", api.SessionCookie)
	return nil, ""
}

// applyOne is a one-service apply body, for the cases that care what was
// applied rather than that the apply was allowed.
func applyOne(project, service string) []reconciler.Desired {
	d := testService(service, 1)
	d.Project = project
	return []reconciler.Desired{d}
}

// token mints a bearer token of the given role.
func (h *authHarness) token(t *testing.T, role auth.Role) string {
	t.Helper()
	_, presented, err := h.users.CreateToken(context.Background(), "ci-"+string(role), role, time.Time{})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return presented
}

func TestNetworkRequestWithoutCredentialsIsRefused(t *testing.T) {
	h := newAuthHarness(t)

	for _, path := range []string{api.PathServices, api.PathAllocs, api.PathSession, api.PathAudit} {
		t.Run(path, func(t *testing.T) {
			resp, body := h.do(t, h.request(t, http.MethodGet, path, nil))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("GET %s = %d, want 401: %s", path, resp.StatusCode, body)
			}
			// The refusal must not say which half was wrong (§14, A07).
			if strings.Contains(strings.ToLower(body), "user") {
				t.Errorf("refusal names the credential: %s", body)
			}
		})
	}
}

func TestHealthIsPublic(t *testing.T) {
	h := newAuthHarness(t)
	resp, body := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET healthz = %d, want 200: %s", resp.StatusCode, body)
	}
}

func TestSocketCallerIsLocalAdmin(t *testing.T) {
	// The CLI's path: no auth configured, no credential presented, and the
	// 0600 socket is what stands in for one (§13.1).
	h := newHarness(t)
	status, body := h.raw(t, http.MethodGet, api.PathSession)
	if status != http.StatusOK {
		t.Fatalf("session over the socket = %d: %s", status, body)
	}

	var session api.SessionResponse
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session.Role != auth.RoleAdmin {
		t.Errorf("role = %q, want admin", session.Role)
	}
	if session.Via != string(auth.MethodSocket) {
		t.Errorf("via = %q, want socket — an audit entry must not claim a user that did not authenticate", session.Via)
	}
}

func TestBearerTokenAuthenticates(t *testing.T) {
	h := newAuthHarness(t)
	req := h.request(t, http.MethodGet, api.PathServices, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))

	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET services with a token = %d: %s", resp.StatusCode, body)
	}
}

func TestBadTokenIsRefused(t *testing.T) {
	h := newAuthHarness(t)
	tests := []struct {
		name  string
		value string
	}{
		{"not a kanea token", "Bearer hunter2"},
		{"wrong secret", "Bearer kanea_deadbeef.notthesecret"},
		{"no scheme", h.token(t, auth.RoleAdmin)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := h.request(t, http.MethodGet, api.PathServices, nil)
			req.Header.Set("Authorization", tc.value)
			resp, body := h.do(t, req)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", resp.StatusCode, body)
			}
		})
	}
}

func TestViewerMayReadButNotWrite(t *testing.T) {
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleViewer)

	req := h.request(t, http.MethodGet, api.PathServices, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer read = %d: %s", resp.StatusCode, body)
	}

	req = h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{})
	req.Header.Set("Authorization", "Bearer "+token)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer write = %d, want 403: %s", resp.StatusCode, body)
	}
}

func TestAdminTokenMayWrite(t *testing.T) {
	h := newAuthHarness(t)
	req := h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))

	resp, body := h.do(t, req)
	// An empty service list is a bad request, not a refusal: the point is that
	// authorization let it through to the handler.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("admin write = %d, want 400 from the handler: %s", resp.StatusCode, body)
	}
}

func TestLoginIssuesASessionCookieWithTheRightFlags(t *testing.T) {
	h := newAuthHarness(t)
	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: adminUser, Password: adminPass})
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d: %s", resp.StatusCode, body)
	}

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == api.SessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if !cookie.HttpOnly {
		t.Error("cookie is readable from script (§14, A03)")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax (§13.3)", cookie.SameSite)
	}
	if cookie.Value == "" {
		t.Error("empty cookie value")
	}

	var session api.SessionResponse
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session.CSRF == "" {
		t.Error("no CSRF token: a cookie client has nowhere else to get one")
	}
	if strings.Contains(body, adminPass) {
		t.Error("the response echoed the password")
	}
}

func TestSecureCookieIsTheDefault(t *testing.T) {
	h := newAuthHarness(t, func(cfg *api.ServerConfig) { cfg.InsecureCookies = false })
	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: adminUser, Password: adminPass})
	resp, _ := h.do(t, req)
	for _, c := range resp.Cookies() {
		if c.Name == api.SessionCookie && !c.Secure {
			t.Fatal("Secure is not set by default (§13.3)")
		}
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	h := newAuthHarness(t)
	tests := []struct{ name, user, password string }{
		{"wrong password", adminUser, "not-it"},
		{"unknown user", "nobody", adminPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := h.request(t, http.MethodPost, api.PathLogin,
				api.LoginRequest{User: tc.user, Password: tc.password})
			resp, body := h.do(t, req)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", resp.StatusCode, body)
			}
			for _, c := range resp.Cookies() {
				if c.Name == api.SessionCookie && c.Value != "" {
					t.Fatal("a failed login issued a session")
				}
			}
		})
	}
}

func TestCookieMutationRequiresACSRFToken(t *testing.T) {
	h := newAuthHarness(t)
	cookie, csrf := h.login(t, adminUser, adminPass)

	// Without the header: a cross-site form post carries the cookie and nothing
	// else, and this is the request it would make.
	req := h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{})
	req.AddCookie(cookie)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without CSRF = %d, want 403: %s", resp.StatusCode, body)
	}

	// With a wrong one.
	req = h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{})
	req.AddCookie(cookie)
	req.Header.Set(api.CSRFHeader, "not-the-token")
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation with a bad CSRF = %d, want 403: %s", resp.StatusCode, body)
	}

	// With the right one it reaches the handler.
	req = h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{})
	req.AddCookie(cookie)
	req.Header.Set(api.CSRFHeader, csrf)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mutation with the CSRF token = %d, want 400 from the handler: %s",
			resp.StatusCode, body)
	}
}

func TestCookieReadsNeedNoCSRFToken(t *testing.T) {
	h := newAuthHarness(t)
	cookie, _ := h.login(t, adminUser, adminPass)

	req := h.request(t, http.MethodGet, api.PathServices, nil)
	req.AddCookie(cookie)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie read = %d: %s", resp.StatusCode, body)
	}
}

func TestBearerMutationNeedsNoCSRFToken(t *testing.T) {
	h := newAuthHarness(t)
	// A token is not attached by a browser, so there is nothing to ride and
	// nothing to prove — demanding a header would only break every CI client.
	req := h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token mutation = %d, want 400 from the handler: %s", resp.StatusCode, body)
	}
}

func TestLogoutRevokesTheSessionServerSide(t *testing.T) {
	h := newAuthHarness(t)
	cookie, csrf := h.login(t, adminUser, adminPass)

	req := h.request(t, http.MethodPost, api.PathLogout, nil)
	req.AddCookie(cookie)
	req.Header.Set(api.CSRFHeader, csrf)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d: %s", resp.StatusCode, body)
	}

	// The same cookie value must now be worthless even to a client that kept it.
	req = h.request(t, http.MethodGet, api.PathSession, nil)
	req.AddCookie(cookie)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after logout = %d, want 401: %s", resp.StatusCode, body)
	}
}

func TestViewerMayLogOut(t *testing.T) {
	h := newAuthHarness(t)
	cookie, csrf := h.login(t, viewerUser, viewerPass)

	req := h.request(t, http.MethodPost, api.PathLogout, nil)
	req.AddCookie(cookie)
	req.Header.Set(api.CSRFHeader, csrf)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("viewer logout = %d, want 204 — logging out is not an admin action: %s",
			resp.StatusCode, body)
	}
}

func TestSessionDescribesTheCaller(t *testing.T) {
	h := newAuthHarness(t)
	cookie, csrf := h.login(t, viewerUser, viewerPass)

	req := h.request(t, http.MethodGet, api.PathSession, nil)
	req.AddCookie(cookie)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session = %d: %s", resp.StatusCode, body)
	}

	var session api.SessionResponse
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if session.Subject != viewerUser || session.Role != auth.RoleViewer {
		t.Errorf("session = %+v, want %s/viewer", session, viewerUser)
	}
	if session.CSRF != csrf {
		t.Errorf("CSRF token changed between login and session: %q vs %q", session.CSRF, csrf)
	}
}

func TestAuditRecordsMutations(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)

	req := h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{Services: applyOne("shop", "web")})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("apply = %d: %s", resp.StatusCode, body)
	}

	page, err := h.audit.List(ctx, audit.Filter{Action: "service.apply"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("audit entries = %d, want 1: %+v", len(page.Entries), page.Entries)
	}
	entry := page.Entries[0]
	if entry.Target != "shop/web" {
		t.Errorf("target = %q, want shop/web", entry.Target)
	}
	if entry.Result != audit.ResultOK || entry.Status != http.StatusOK {
		t.Errorf("result = %s/%d, want ok/200", entry.Result, entry.Status)
	}
	if entry.Via != string(auth.MethodToken) || entry.TokenID == "" {
		t.Errorf("entry does not name the credential used: %+v", entry)
	}
	if entry.Role != string(auth.RoleAdmin) {
		t.Errorf("role = %q, want admin", entry.Role)
	}
}

func TestAuditRecordsRefusedMutations(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)

	req := h.request(t, http.MethodPut, api.PathServices,
		api.ApplyRequest{Services: applyOne("shop", "web")})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	if resp, _ := h.do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer apply = %d, want 403", resp.StatusCode)
	}

	page, err := h.audit.List(ctx, audit.Filter{Result: audit.ResultDenied})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("denied entries = %d, want 1: %+v", len(page.Entries), page.Entries)
	}
	if page.Entries[0].Action != "service.apply" {
		t.Errorf("action = %q, want service.apply", page.Entries[0].Action)
	}
}

func TestAuditRecordsFailedLogins(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)

	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: adminUser, Password: "wrong"})
	if resp, _ := h.do(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login = %d, want 401", resp.StatusCode)
	}

	page, err := h.audit.List(ctx, audit.Filter{Action: "auth.login"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(page.Entries))
	}
	entry := page.Entries[0]
	if entry.Result != audit.ResultDenied {
		t.Errorf("result = %q, want denied", entry.Result)
	}
	if entry.Target != adminUser {
		t.Errorf("target = %q, want the attempted user name", entry.Target)
	}
	// The whole point of A07's redaction rule: the attempt is visible, the
	// credential is not.
	if strings.Contains(entry.Detail, "wrong") {
		t.Errorf("the attempted password reached the audit log: %q", entry.Detail)
	}
}

func TestUnauthenticatedProbesAreNotAudited(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)

	// An audit log any anonymous caller can grow is a disk-exhaustion vector,
	// so a request with no credential at all is refused without a record.
	for range 5 {
		h.do(t, h.request(t, http.MethodGet, api.PathServices, nil))
	}
	page, err := h.audit.List(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 0 {
		t.Fatalf("anonymous probes wrote %d audit entries", len(page.Entries))
	}
}

func TestRejectedCredentialsAreAudited(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t)

	req := h.request(t, http.MethodGet, api.PathServices, nil)
	req.Header.Set("Authorization", "Bearer kanea_deadbeef.wrongsecret")
	h.do(t, req)

	page, err := h.audit.List(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 — a rejected credential is a security event", len(page.Entries))
	}
	if strings.Contains(page.Entries[0].Detail, "wrongsecret") {
		t.Errorf("the presented secret reached the log: %q", page.Entries[0].Detail)
	}
}

func TestAuditIsAdminOnly(t *testing.T) {
	h := newAuthHarness(t)

	req := h.request(t, http.MethodGet, api.PathAudit, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer read of the audit log = %d, want 403: %s", resp.StatusCode, body)
	}

	req = h.request(t, http.MethodGet, api.PathAudit, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin read of the audit log = %d: %s", resp.StatusCode, body)
	}
}

func TestAuditListFilters(t *testing.T) {
	h := newAuthHarness(t)
	token := h.token(t, auth.RoleAdmin)

	for _, name := range []string{"web", "api"} {
		req := h.request(t, http.MethodPut, api.PathServices,
			api.ApplyRequest{Services: applyOne("shop", name)})
		req.Header.Set("Authorization", "Bearer "+token)
		h.do(t, req)
	}

	req := h.request(t, http.MethodGet, api.PathAudit+"?action=service.&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit list = %d: %s", resp.StatusCode, body)
	}

	var page api.AuditResponse
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("entries = %d, want the requested 1", len(page.Entries))
	}
	if page.Entries[0].Target != "shop/api" {
		t.Errorf("newest entry = %q, want shop/api", page.Entries[0].Target)
	}
	if !page.More || page.NextAfter == "" {
		t.Error("a truncated listing must say how to continue")
	}
}

func TestSecretRoutesAreAdminOnly(t *testing.T) {
	h := newAuthHarness(t, withSecrets)
	token := h.token(t, auth.RoleViewer)

	cases := []struct{ method, path string }{
		{http.MethodGet, api.PathSecrets},
		{http.MethodPut, api.PathSecrets + "/shop/db"},
		{http.MethodDelete, api.PathSecrets + "/shop/db"},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			var body any
			if tc.method == http.MethodPut {
				body = api.SecretRequest{Value: "s3cret"}
			}
			req := h.request(t, tc.method, tc.path, body)
			req.Header.Set("Authorization", "Bearer "+token)
			if resp, got := h.do(t, req); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s = %d, want 403: %s", tc.method, tc.path, resp.StatusCode, got)
			}
		})
	}
}

func TestSecretValuesNeverReachTheAuditLog(t *testing.T) {
	ctx := context.Background()
	h := newAuthHarness(t, withSecrets)

	req := h.request(t, http.MethodPut, api.PathSecrets+"/shop/db-password",
		api.SecretRequest{Value: "hunter2-but-longer"})
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put secret = %d: %s", resp.StatusCode, body)
	}

	page, err := h.audit.List(ctx, audit.Filter{Action: "secret."})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(page.Entries))
	}
	entry := page.Entries[0]
	// The path is exactly what the trail should carry; the value is exactly
	// what it must not (§13.3, §14 A09).
	if entry.Target != "shop/db-password" {
		t.Errorf("target = %q, want the secret path", entry.Target)
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("encode entry: %v", err)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("the secret value is in the audit entry: %s", raw)
	}
}

func TestSecurityHeadersAreOnEveryResponse(t *testing.T) {
	h := newAuthHarness(t)

	// Including on a refusal, which is the response an unauthenticated browser
	// is most likely to receive.
	for _, path := range []string{api.PathHealth, api.PathServices} {
		resp, _ := h.do(t, h.request(t, http.MethodGet, path, nil))
		want := map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		}
		for header, value := range want {
			if got := resp.Header.Get(header); got != value {
				t.Errorf("%s: %s = %q, want %q", path, header, got, value)
			}
		}
	}
}

func TestContentSecurityPolicyIsSetWhenTheDashboardIsServed(t *testing.T) {
	h := newAuthHarness(t, func(cfg *api.ServerConfig) { cfg.ServeDashboard = true })
	resp, _ := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy with the dashboard served")
	}
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("inline script is allowed; an XSS would execute (§14, A03)")
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	h := newAuthHarness(t)

	// Enough failures to trip the per-account lockout (§13.3, §14 A07). The
	// point is that the answer changes from "wrong" to "stop asking".
	var last int
	for range auth.DefaultLoginLimit.Attempts + 1 {
		req := h.request(t, http.MethodPost, api.PathLogin,
			api.LoginRequest{User: adminUser, Password: "wrong"})
		resp, _ := h.do(t, req)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status after repeated failures = %d, want 429", last)
	}

	// And a correct password does not unlock it while the lockout stands.
	req := h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: adminUser, Password: adminPass})
	if resp, _ := h.do(t, req); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("login during lockout = %d, want 429", resp.StatusCode)
	}
}
