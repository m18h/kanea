package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kanea-dev/kanea/internal/audit"
	"github.com/kanea-dev/kanea/internal/auth"
)

// OIDC routes (PRD §16.1, §13.2).
const (
	PathOIDCStart    = "/v1/auth/oidc/start"
	PathOIDCCallback = "/v1/auth/oidc/callback"
)

// oidcCookie carries the handle for one in-flight login. It is not the session
// cookie and never becomes one: it is worthless after the callback, and it is
// deleted there whether the login succeeded or not.
const oidcCookie = "kanea_oidc"

// Provider is the slice of the OIDC provider the API needs.
type Provider interface {
	Start(next string) (authURL, handle string, err error)
	Complete(ctx context.Context, handle, state, code string) (auth.OIDCResult, error)
	Issuer() string
}

// SessionIssuer mints a session for an identity the daemon has already
// authenticated by some other means — today, an identity provider.
//
// Separate from Authenticator because it is a different question: that
// interface asks "who is this caller", this one says "this one is vouched for".
type SessionIssuer interface {
	CreateSession(ctx context.Context, subject string, role auth.Role) (auth.Session, string, error)
}

// handleOIDCStart sends the browser to the identity provider.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotImplemented, auth.ErrOIDCDisabled)
		return
	}

	// `next` is where to land afterwards. The provider bounds it to a path on
	// this origin; an absolute URL here would make the login page a phishing
	// hop with this daemon's name on it.
	authURL, handle, err := s.oidc.Start(r.URL.Query().Get("next"))
	if err != nil {
		s.log.Warn("cannot start an OIDC login", "error", err)
		writeError(w, http.StatusServiceUnavailable, errRefused)
		return
	}

	// #nosec G124 — sessionCookie sets HttpOnly and SameSite unconditionally;
	// Secure is the documented InsecureCookies opt-out for a plain-HTTP daemon.
	cookie := s.sessionCookie(handle, time.Now().Add(auth.PendingLoginTTL))
	cookie.Name = oidcCookie
	// Lax, like the session cookie: the provider returns the browser here by a
	// top-level GET, which Lax allows and Strict would silently break.
	http.SetCookie(w, cookie)
	// #nosec G710 — authURL is built by the provider from the configured issuer
	// and this daemon's own state, nonce and PKCE challenge. The only
	// caller-supplied value that reached Start is `next`, which never appears
	// here: it is stored server-side, bounded to a path on this origin by
	// auth.safeNext, and used at the end of the callback.
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback completes a login and issues a session.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || s.sessions == nil {
		writeError(w, http.StatusNotImplemented, auth.ErrOIDCDisabled)
		return
	}

	// The handle cookie is cleared first, on every path out of here: a login
	// that failed must not leave a reusable handle in the browser.
	// #nosec G124 — same cookie builder, same flags; this one only clears it.
	cleared := s.sessionCookie("", time.Unix(0, 0))
	cleared.Name, cleared.MaxAge = oidcCookie, -1
	http.SetCookie(w, cleared)

	handle, err := r.Cookie(oidcCookie)
	if err != nil {
		s.refuseOIDC(w, r, auth.ErrOIDCState)
		return
	}
	query := r.URL.Query()
	if desc := query.Get("error"); desc != "" {
		// The provider refused, and it is the one with the reason. Recorded
		// with its message, shown to the user without it — the message is the
		// provider's to explain, and repeating it here would let a crafted
		// redirect put arbitrary text on Kanea's page.
		s.log.Warn("the identity provider refused a login",
			"error", desc, "description", query.Get("error_description"))
		s.refuseOIDC(w, r, errors.New("the identity provider refused the login"))
		return
	}

	result, err := s.oidc.Complete(r.Context(), handle.Value, query.Get("state"), query.Get("code"))
	if err != nil {
		s.refuseOIDC(w, r, err)
		return
	}

	session, cookie, err := s.sessions.CreateSession(r.Context(), result.Subject, result.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(cookie, session.Expires))

	s.record(r, audit.Entry{
		Action: "auth.login", Result: audit.ResultOK, Status: http.StatusFound,
		Detail: "issuer " + s.oidc.Issuer(),
	}, auth.Identity{Subject: result.Subject, Role: result.Role, Via: auth.MethodOIDC})
	s.log.Info("oidc login", "user", result.Subject, "role", result.Role, "source", sourceOf(r))

	// A redirect rather than JSON: the browser arrived here by navigation, and
	// what it wants is the page it was going to.
	http.Redirect(w, r, result.Next, http.StatusFound)
}

// refuseOIDC records a failed provider login and answers it.
func (s *Server) refuseOIDC(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusUnauthorized
	if errors.Is(err, auth.ErrOIDCNoRole) {
		// The provider vouched for them; Kanea has no role for them. That is a
		// permission answer, not an identity one, and telling them apart is the
		// difference between "log in again" and "ask an administrator".
		status = http.StatusForbidden
	}

	s.record(r, audit.Entry{
		Action: "auth.login", Result: audit.ResultDenied, Status: status,
		Detail: err.Error(),
	}, auth.Identity{Via: auth.MethodOIDC})
	s.log.Warn("oidc login refused", "source", sourceOf(r), "error", err)
	writeError(w, status, errRefused)
}

// OIDCStatus tells the dashboard whether to offer a provider button.
type OIDCStatus struct {
	Enabled bool   `json:"enabled"`
	Issuer  string `json:"issuer,omitempty"`
	// StartPath is where the button points, so the dashboard does not have to
	// know how the route is spelled.
	StartPath string `json:"start_path,omitempty"`
}
