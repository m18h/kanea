package api

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/notify"
)

// Auth routes (PRD §16.1).
const (
	PathLogin   = "/v1/auth/login"
	PathLogout  = "/v1/auth/logout"
	PathSession = "/v1/auth/session"
	PathAudit   = "/v1/audit"
)

// SessionCookie holds the dashboard session id.
//
// The __Host- prefix is not used: it requires Secure, and a daemon reached over
// plain HTTP on a private network is a supported deployment. The properties the
// prefix would enforce are set explicitly below instead.
const SessionCookie = "kanea_session"

// CSRFHeader carries the double-submit token on cookie-authenticated mutations
// (PRD §13.3). A header is the whole point: a cross-site form post can carry a
// cookie but cannot set a custom header without a preflight the browser will
// refuse. On a WebSocket upgrade the constructor cannot set this header either,
// which is what CSRFProtocolPrefix exists for.
const CSRFHeader = "X-Kanea-CSRF" // #nosec G101: a header name, not a credential

// CSRFProtocolPrefix carries the CSRF token on a WebSocket upgrade, where the
// browser cannot set a custom header (PRD v1.64): the client offers a
// Sec-WebSocket-Protocol entry "kanea-csrf.<token>" beside the route's
// negotiable subprotocol. Honored only on an Upgrade request: Upgrade and
// Sec-* are browser-forbidden headers, so no cross-site fetch or form can
// produce that shape, and the server never echoes the token entry back.
const CSRFProtocolPrefix = "kanea-csrf." // #nosec G101: a prefix, not a credential

// Authenticator is the slice of the auth store the API needs.
//
// Defined here rather than imported as a struct so the API depends on the four
// questions it actually asks, and so a test can answer them without a Store.
type Authenticator interface {
	Login(ctx context.Context, name, password, source string) (auth.Session, string, error)
	Session(ctx context.Context, cookie string) (auth.Session, error)
	DeleteSession(ctx context.Context, cookie string) error
	AuthenticateToken(ctx context.Context, presented string) (auth.Identity, error)
}

// AuditLog is the slice of the audit log the API needs.
type AuditLog interface {
	Record(ctx context.Context, e audit.Entry) (audit.Entry, error)
	List(ctx context.Context, f audit.Filter) (audit.Page, error)
}

// LoginRequest is a password login.
type LoginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// SessionResponse describes the caller to itself. It is what the dashboard asks
// for on load, and what tells it whether to render the app or the login form.
//
// It carries the CSRF token because a cookie-authenticated client cannot read
// the session cookie (HttpOnly) and has nowhere else to get one.
type SessionResponse struct {
	Subject string    `json:"subject"`
	Role    auth.Role `json:"role"`
	Via     string    `json:"via"`
	// CSRF is set for session logins only; a bearer-token caller has no ambient
	// credential for a third party to ride, and therefore needs no token.
	CSRF    string    `json:"csrf,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
}

// AuditResponse is a page of the audit log.
type AuditResponse struct {
	Entries   []audit.Entry `json:"entries"`
	NextAfter string        `json:"next_after,omitempty"`
	More      bool          `json:"more"`
}

// policy is what a route requires. Every route declares one at registration:
// the alternative (a middleware that infers requirements from the path) makes
// "which routes are protected" a question about string matching rather than
// something readable next to the handler (PRD §14, A01).
type policy struct {
	// action names this route in the audit log. Required.
	action string
	// mutates marks a state change: admin role, CSRF on cookie authentication,
	// and an audit entry whether it succeeds or fails.
	mutates bool
	// selfService lifts the admin requirement from a mutation a caller performs
	// on themselves: logging out. It is an explicit opt-out rather than a
	// per-route role field, so a new mutating route that says nothing about
	// roles is admin-only by default rather than open by omission.
	selfService bool
	// adminOnly marks a read that is still privileged: the audit log itself.
	adminOnly bool
	// public exempts the route from authentication. Exactly two routes may set
	// it (§5.2.1): health, and login. Everything else is deny-by-default.
	public bool
}

// localConnKey marks a request that arrived on the unix socket.
type localConnKey struct{}

// withLocalConn is the ConnContext hook for the socket listener.
//
// Marking the connection rather than inspecting RemoteAddr is deliberate: the
// address on a unix connection is empty or "@", which is indistinguishable from
// a value a proxy could put there. The listener knows the truth; the request
// handler should not have to guess it.
func withLocalConn(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*net.UnixConn); ok {
		return context.WithValue(ctx, localConnKey{}, true)
	}
	return ctx
}

func isLocalConn(ctx context.Context) bool {
	local, _ := ctx.Value(localConnKey{}).(bool)
	return local
}

// route wraps a handler with the checks its policy calls for.
//
// The order matters and is the order an attacker meets it: authenticate, then
// authorize, then verify the request was intended, then act, then record.
func (s *Server) route(p policy, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First, before any work this request could make the daemon do.
		if !s.checkRateLimit(w, r, p) {
			return
		}
		if p.public {
			h(w, r)
			return
		}

		id, err := s.identify(r)
		if err != nil {
			s.refuse(w, r, p, id, err)
			return
		}
		if (p.mutates && !p.selfService || p.adminOnly) && !id.Role.CanWrite() {
			s.refuse(w, r, p, id, fmt.Errorf("%w: %s may not %s", auth.ErrForbidden, id.Role, p.action))
			return
		}
		if p.mutates {
			if err := s.checkCSRF(r, id); err != nil {
				s.refuse(w, r, p, id, err)
				return
			}
		}

		r = r.WithContext(auth.WithIdentity(r.Context(), id))
		fields := &auditFields{}
		r = r.WithContext(context.WithValue(r.Context(), auditFieldsKey{}, fields))

		rec := &recordingWriter{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)

		if p.mutates {
			// Recorded after the fact, because the outcome is half of what makes
			// the entry worth having. The window that leaves (the action landed,
			// the record did not) is real but narrow: it needs the Store to fail
			// between two writes, and a Store that is failing has already failed
			// the mutation. It is logged loudly and counted rather than hidden,
			// and it is the reason an audit entry is never the only evidence.
			s.record(r, audit.Entry{
				Action: p.action, Target: fields.target, Detail: fields.detail,
				Result: resultFor(rec.status), Status: rec.status,
			}, id)
		}
	})
}

// identify resolves the caller, or fails.
//
// There is no fall-through: a request that presents nothing usable on a network
// connection is refused, whether or not auth is configured. That is the "no
// unauthenticated API" line of §14 A05, enforced in the one place every route
// passes through.
func (s *Server) identify(r *http.Request) (auth.Identity, error) {
	if presented := bearerToken(r); presented != "" {
		if s.auth == nil {
			return auth.Identity{}, fmt.Errorf("%w: no authentication is configured", auth.ErrUnauthenticated)
		}
		id, err := s.auth.AuthenticateToken(r.Context(), presented)
		if err != nil {
			return auth.Identity{}, err
		}
		return id, nil
	}

	if cookie, err := r.Cookie(SessionCookie); err == nil && s.auth != nil {
		session, err := s.auth.Session(r.Context(), cookie.Value)
		if err != nil {
			return auth.Identity{}, err
		}
		// Via carries how the session was established (v1.47): "session",
		// "oidc" or "ldap". Whatever it says, this is a browser cookie:
		// checkCSRF's allowlist is what enforces that reading.
		return auth.Identity{
			Subject: session.Subject, Role: session.Role, Via: session.Via(),
		}, nil
	}

	// The unix socket is the credential. It is created 0600 and owned by the
	// user running kanead, so reaching it means being that user: who can
	// already replace the binary, read the master key and mint any token they
	// like. Demanding a second credential from them would be theatre, and
	// §13.1 names this as the local path. It is recorded as MethodSocket so an
	// audit entry never claims a user that did not authenticate.
	if isLocalConn(r.Context()) {
		return auth.Identity{Subject: "local", Role: auth.RoleAdmin, Via: auth.MethodSocket}, nil
	}

	return auth.Identity{}, auth.ErrUnauthenticated
}

// bearerToken extracts a presented token from the Authorization header.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

// checkCSRF enforces the double-submit token on cookie-authenticated mutations.
//
// Only cookie authentication needs it. A bearer token is not attached by the
// browser to a cross-site request, so there is nothing to ride; a socket caller
// is not a browser at all. SameSite=Lax on the cookie is defence in depth, not
// a substitute: it does not cover every navigation, and it is a property of the
// browser rather than of this server (PRD §13.3).
//
// An allowlist skip, not "skip unless via session": since v1.47 a cookie
// identity's Via can read "ldap" or "oidc", and every one of those is still a
// browser cookie a cross-site request can ride. The old predicate would have
// silently exempted them: a hole opened by bookkeeping.
func (s *Server) checkCSRF(r *http.Request, id auth.Identity) error {
	if id.Via == auth.MethodToken || id.Via == auth.MethodSocket {
		return nil
	}
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return fmt.Errorf("%w: no session cookie", auth.ErrForbidden)
	}
	session, err := s.auth.Session(r.Context(), cookie.Value)
	if err != nil {
		return err
	}
	presented := presentedCSRF(r)
	if presented == "" {
		return fmt.Errorf("%w: missing %s header", auth.ErrForbidden, CSRFHeader)
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(session.CSRF)) != 1 {
		return fmt.Errorf("%w: bad CSRF token", auth.ErrForbidden)
	}
	return nil
}

// presentedCSRF finds the token the request carries: the header, or (on a
// WebSocket upgrade only) a Sec-WebSocket-Protocol entry with the
// CSRFProtocolPrefix. The Upgrade gate is the security property: off a
// websocket handshake the subprotocol header is attacker-settable by any
// same-machine client, and honoring it there would widen every cookie-auth
// mutation. On the handshake it is exactly as unforgeable cross-site as the
// custom header is.
func presentedCSRF(r *http.Request) string {
	if t := r.Header.Get(CSRFHeader); t != "" {
		return t
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return ""
	}
	for _, value := range r.Header.Values("Sec-Websocket-Protocol") {
		for _, entry := range strings.Split(value, ",") {
			if token, ok := strings.CutPrefix(strings.TrimSpace(entry), CSRFProtocolPrefix); ok {
				return token
			}
		}
	}
	return ""
}

// refuse answers a rejected request and records it.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, p policy, id auth.Identity, err error) {
	status := http.StatusUnauthorized
	if errors.Is(err, auth.ErrForbidden) {
		status = http.StatusForbidden
	}
	if errors.Is(err, auth.ErrRateLimited) {
		status = http.StatusTooManyRequests
	}

	// A refusal is audited when the caller presented *something*: a rejected
	// token or an expired session is a security event worth keeping. A request
	// with no credential at all is not recorded, because that is what every
	// internet-wide scanner sends, and an audit log an anonymous caller can
	// grow without limit is a disk-exhaustion vector wearing a compliance hat.
	if id.Subject != "" || presentedSomething(r) {
		s.record(r, audit.Entry{
			Action: p.action, Result: audit.ResultDenied, Status: status,
			Detail: err.Error(),
		}, id)
	}
	s.log.Warn("request refused",
		"action", p.action, "actor", id.Subject, "source", sourceOf(r), "error", err)

	// The reason is deliberately not spelled out to the caller: "no such user"
	// and "wrong password" must read alike (§14, A07).
	writeError(w, status, errRefused)
}

var (
	errRefused     = errors.New("api: not authorised")
	errRateLimited = errors.New("api: too many requests")
)

// presentedSomething reports whether the caller offered a credential at all.
func presentedSomething(r *http.Request) bool {
	if bearerToken(r) != "" {
		return true
	}
	_, err := r.Cookie(SessionCookie)
	return err == nil
}

// record appends an audit entry, or says loudly that it could not.
func (s *Server) record(r *http.Request, e audit.Entry, id auth.Identity) {
	if s.audit == nil {
		return
	}
	e.Actor, e.Role, e.Via, e.TokenID = id.Subject, string(id.Role), string(id.Via), id.TokenID
	e.Source = sourceOf(r)

	// A cancelled request must still be recorded: the action it triggered
	// already happened, and "the client hung up" is not a reason to lose the
	// only record of it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditWriteTimeout)
	defer cancel()
	if _, err := s.audit.Record(ctx, e); err != nil {
		auditFailures.Add(1)
		s.log.Error("cannot record an audit entry",
			"action", e.Action, "actor", e.Actor, "target", e.Target, "error", err)
	}
}

// auditWriteTimeout bounds the audit write on a request path. The Store is
// single-writer; a wedged one must fail the entry rather than pin the handler.
const auditWriteTimeout = 5 * time.Second

// auditFailures counts entries that could not be written, so the condition is
// observable rather than silent.
var auditFailures atomic.Int64

// AuditFailures reports how many audit entries could not be recorded.
func AuditFailures() int64 { return auditFailures.Load() }

func resultFor(status int) audit.Result {
	switch {
	case status < 400:
		return audit.ResultOK
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return audit.ResultDenied
	default:
		return audit.ResultError
	}
}

// sourceOf is the caller's address, without the ephemeral port.
func sourceOf(r *http.Request) string {
	if isLocalConn(r.Context()) {
		return "unix"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- per-request audit detail ----

type auditFieldsKey struct{}

// auditFields is what only the handler knows: which service was applied, which
// secret was written. The wrapper cannot infer it from the path for routes that
// carry it in the body.
type auditFields struct {
	target string
	detail string
}

// auditTarget names what the request acted on, for the audit entry.
func auditTarget(r *http.Request, target string) {
	if f, ok := r.Context().Value(auditFieldsKey{}).(*auditFields); ok {
		f.target = target
	}
}

// ---- handlers ----

// handleLogin verifies a password and issues a session.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusNotImplemented, errNoAuthConfigured)
		return
	}
	var req LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}

	source := sourceOf(r)
	session, cookie, err := s.auth.Login(r.Context(), req.User, req.Password, source)
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, auth.ErrRateLimited):
			status = http.StatusTooManyRequests
		case errors.Is(err, auth.ErrLDAPNoRole):
			// The directory vouched for them; Kanea has no role for them;
			// the difference between "log in again" and "ask an
			// administrator" (v1.47, the OIDC no-role rule).
			status = http.StatusForbidden
		}
		// Recorded with the attempted user name but never the password: the
		// name is what makes a brute-force visible, and Redact would strip the
		// password anyway (§14, A07/A09).
		s.record(r, audit.Entry{
			Action: "auth.login", Target: req.User, Result: audit.ResultDenied, Status: status,
		}, auth.Identity{})
		// Node-level, with no project: a failed login belongs to nobody's
		// project. The attempted name is included for the same reason the audit
		// entry carries it (a brute force is only visible as a pattern of
		// names) and one failure is a typo, which is why §11 files this as a
		// warning and the dispatcher coalesces it into a count.
		s.emit(notify.EventAuthLoginFailed, "", "",
			fmt.Sprintf("failed login for %q from %s", req.User, sourceOf(r)))
		writeError(w, status, errRefused)
		return
	}

	http.SetCookie(w, s.sessionCookie(cookie, session.Expires))
	// Via comes from the session itself (v1.47): "session" for a local
	// password, "ldap" for a directory one. The audit Detail names the
	// directory for LDAP logins, mirroring OIDC's "issuer …".
	entry := audit.Entry{Action: "auth.login", Result: audit.ResultOK, Status: http.StatusOK}
	if session.Via() == auth.MethodLDAP && s.ldapServer != "" {
		entry.Detail = "server " + s.ldapServer
	}
	s.record(r, entry,
		auth.Identity{Subject: session.Subject, Role: session.Role, Via: session.Via()})
	writeJSON(w, http.StatusOK, SessionResponse{
		Subject: session.Subject, Role: session.Role, Via: string(session.Via()),
		CSRF: session.CSRF, Expires: session.Expires,
	})
}

// maxLoginBytes bounds a login body. Credentials are small; anything larger is
// not a login attempt.
const maxLoginBytes = 4 << 10

// handleLogout revokes the session server-side.
//
// Clearing the cookie alone would leave a session that still works for anyone
// holding a copy of it, which is exactly what §13.3's revocation list exists to
// prevent.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookie)
	if err == nil && s.auth != nil {
		if err := s.auth.DeleteSession(r.Context(), cookie.Value); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	// Expired in the past and emptied: a browser that ignores one usually
	// honours the other.
	// #nosec G124: the flags come from sessionCookie, which sets HttpOnly and
	// SameSite unconditionally; Secure is the documented InsecureCookies opt-out.
	cleared := s.sessionCookie("", time.Unix(0, 0))
	cleared.MaxAge = -1
	http.SetCookie(w, cleared)
	w.WriteHeader(http.StatusNoContent)
}

// handleSession describes the caller to itself.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errRefused)
		return
	}
	out := SessionResponse{Subject: id.Subject, Role: id.Role, Via: string(id.Via)}
	// checkCSRF's allowlist, mirrored (v1.47): an "ldap" or "oidc" Via is still
	// a browser cookie, and this route is the only place a cookie client can
	// learn its CSRF token (the OIDC callback is a redirect with no body, and a
	// reload loses the login response). Gating on Via == "session" here while
	// checkCSRF demands the token for every cookie caller would leave external
	// logins unable to mutate at all.
	if id.Via != auth.MethodToken && id.Via != auth.MethodSocket {
		if cookie, err := r.Cookie(SessionCookie); err == nil {
			if session, err := s.auth.Session(r.Context(), cookie.Value); err == nil {
				out.CSRF, out.Expires = session.CSRF, session.Expires
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAudit serves the audit log, newest first.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("api: the audit log is not configured"))
		return
	}
	q := r.URL.Query()
	filter := audit.Filter{
		Actor:  q.Get("actor"),
		Action: q.Get("action"),
		Result: audit.Result(q.Get("result")),
		After:  q.Get("after"),
		Oldest: q.Get("order") == "oldest",
	}
	if raw := q.Get("since"); raw != "" {
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("since: %w", err))
			return
		}
		filter.Since = at
	}
	if raw := q.Get("until"); raw != "" {
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("until: %w", err))
			return
		}
		filter.Until = at
	}
	if raw := q.Get("limit"); raw != "" {
		var limit int
		if _, err := fmt.Sscanf(raw, "%d", &limit); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit: %w", err))
			return
		}
		filter.Limit = limit
	}

	page, err := s.audit.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, AuditResponse{
		Entries: page.Entries, NextAfter: page.NextAfter, More: page.More,
	})
}

var errNoAuthConfigured = errors.New("api: no authentication is configured on this daemon")

// sessionCookie builds the session cookie with the flags §13.3 requires.
func (s *Server) sessionCookie(value string, expires time.Time) *http.Cookie {
	// #nosec G124: HttpOnly and SameSite are set unconditionally below. Secure
	// is conditional on purpose: a daemon reached over plain HTTP on a private
	// network is a supported deployment, and a cookie a browser refuses to send
	// is not a security win, it is a login screen nobody can get past. The
	// default is Secure; dropping it takes an explicit operator decision.
	return &http.Cookie{
		Name:  SessionCookie,
		Value: value,
		Path:  "/",
		// HttpOnly: script cannot read it, so an XSS that gets as far as running
		// still cannot exfiltrate the session (§14, A03).
		HttpOnly: true,
		// Secure unless an operator has explicitly said this daemon is reached
		// over plain HTTP. The default is the safe one; the exception is a
		// decision someone has to make out loud.
		Secure: !s.insecureCookies,
		// Lax rather than Strict: a link into the dashboard from a chat client
		// should not land on a login screen. Mutations are covered by the CSRF
		// token above, which is the actual defence.
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

// ---- security headers ----

// secureHeaders sets the response headers every route shares (PRD §14).
//
// Applied to the whole mux rather than per route, so a handler that is added
// later cannot forget them: including the ones that answer errors and the
// dashboard's static files. The Content-Security-Policy is deliberately NOT
// set here: it belongs to the dashboard package, which is the only thing
// serving HTML. Two CSP headers on one response are not defence in depth:
// browsers intersect them, so a duplicate silently tightens the policy the
// app was written against.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// No camera, microphone or geolocation: nothing here uses them, and the
		// header costs nothing to state.
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		// Cross-origin isolation of the API surface: a page on another origin
		// must not be able to read these responses even by embedding them.
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// ---- response recording ----

// recordingWriter remembers the status so the audit entry can carry the outcome.
//
// It forwards the interfaces the handlers underneath actually use: Flush for the
// log stream, Hijack for the websocket upgrade. Unwrap covers everything reached
// through http.ResponseController. A wrapper that silently dropped these would
// turn `kanea logs -f` into a stream that never arrives.
type recordingWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *recordingWriter) WriteHeader(status int) {
	if !w.written {
		w.status, w.written = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

func (w *recordingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("api: %T cannot be hijacked", w.ResponseWriter)
	}
	return h.Hijack()
}

func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// auditDetail records extra context on the audit entry: for exec, the command
// that was asked for, which is the whole point of auditing an exec at all.
func auditDetail(r *http.Request, detail string) {
	if f, ok := r.Context().Value(auditFieldsKey{}).(*auditFields); ok {
		f.detail = detail
	}
}
