package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// MethodOIDC is a caller who authenticated through an identity provider.
const MethodOIDC Method = "oidc"

// Errors an OIDC login can fail with.
var (
	// ErrOIDCDisabled means no provider is configured.
	ErrOIDCDisabled = errors.New("auth: no identity provider is configured")
	// ErrOIDCState marks a callback that does not match a login this daemon
	// started — a replay, a stale tab, or a forged request.
	ErrOIDCState = errors.New("auth: the login state does not match")
	// ErrOIDCNoRole means the provider authenticated someone Kanea has no role
	// for. It is the deny-by-default case, not an error in the provider.
	ErrOIDCNoRole = errors.New("auth: no role maps to this account's claims")
)

// OIDCConfig configures the identity provider (PRD §13.2).
type OIDCConfig struct {
	// Issuer is the provider's base URL; its discovery document is fetched from
	// it at startup, which is also how a typo is caught before anyone tries to
	// log in.
	Issuer   string
	ClientID string
	// ClientSecret may be empty: with PKCE, a public client is a supported and
	// well-defined configuration rather than a downgrade.
	ClientSecret string
	// RedirectURL is the exact URI registered with the provider. Kanea never
	// takes a redirect target from a request, so this is the only one that can
	// ever be used (§13.2 — restricted redirect URIs).
	RedirectURL string
	// Scopes beyond openid. "profile" and "email" are usual; a provider that
	// carries roles in a custom scope needs it named here.
	Scopes []string

	// RoleClaim is the claim consulted for authorization, "groups" by default.
	RoleClaim string
	// AdminValues and ViewerValues map claim values to roles. A caller whose
	// claim matches nothing is refused: deny-by-default is the requirement, and
	// "authenticated" is not "authorized" (§13.2).
	AdminValues  []string
	ViewerValues []string

	Logger *slog.Logger
	Now    func() time.Time
}

// OIDC is a configured identity provider.
type OIDC struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	cfg      OIDCConfig
	log      *slog.Logger
	now      func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingLogin
}

// pendingLogin is one in-flight authorization request.
//
// Held in memory rather than in the Store: it lives for a minute, it is
// worthless after use, and a login interrupted by a restart is a login someone
// retries. Writing it to state would replicate a secret with no lifetime.
type pendingLogin struct {
	state    string
	nonce    string
	verifier string
	// next is where to send the browser afterwards. Always a path on this
	// origin — see safeNext.
	next    string
	expires time.Time
}

// PendingLoginTTL bounds how long a started login may be completed within.
const PendingLoginTTL = 10 * time.Minute

// maxPendingLogins bounds the in-flight set. Starting a login is unauthenticated
// by necessity, so without a cap it is a memory exhaustion vector — the same
// problem the rate limiter solves for requests, and the rate limiter in front of
// this route is the other half of the answer.
const maxPendingLogins = 1024

// NewOIDC builds a provider, fetching its discovery document.
//
// Discovery happens here so a misconfigured issuer fails at startup, in front of
// the operator, rather than at the first login attempt in front of a user.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	if cfg.Issuer == "" {
		return nil, ErrOIDCDisabled
	}
	if cfg.ClientID == "" {
		return nil, errors.New("auth: an OIDC client id is required")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("auth: an OIDC redirect URL is required")
	}
	if len(cfg.AdminValues) == 0 && len(cfg.ViewerValues) == 0 {
		// Without a mapping every login would be refused, which is safe but
		// looks like a bug to whoever configured it. Say so now.
		return nil, errors.New("auth: OIDC needs at least one admin or viewer claim value; " +
			"without one, every login is refused")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = DefaultRoleClaim
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC discovery for %s: %w", cfg.Issuer, err)
	}

	scopes := append([]string{oidc.ScopeOpenID}, cfg.Scopes...)
	return &OIDC{
		provider: provider,
		// The verifier checks signature, issuer, audience and expiry — all four,
		// because a token that is merely well-formed is not a login.
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		cfg:     cfg,
		log:     cfg.Logger,
		now:     cfg.Now,
		pending: map[string]*pendingLogin{},
	}, nil
}

// DefaultRoleClaim is the claim consulted when none is configured.
const DefaultRoleClaim = "groups"

// Start begins a login and returns the provider URL to send the browser to,
// along with the opaque handle that identifies this attempt.
//
// The handle goes in a short-lived cookie. The state parameter goes to the
// provider. Both must come back, and they are different values: a callback that
// carries a state without the matching cookie is someone else's login being
// replayed into this browser.
func (o *OIDC) Start(next string) (authURL, handle string, err error) {
	state, err := randomSecret()
	if err != nil {
		return "", "", err
	}
	nonce, err := randomSecret()
	if err != nil {
		return "", "", err
	}
	handle, err = randomSecret()
	if err != nil {
		return "", "", err
	}
	// PKCE: the verifier never leaves this process until the code exchange, so
	// an authorization code intercepted in the browser's redirect chain cannot
	// be redeemed by whoever intercepted it.
	verifier := oauth2.GenerateVerifier()

	o.mu.Lock()
	o.evictExpired()
	if len(o.pending) >= maxPendingLogins {
		o.mu.Unlock()
		return "", "", errors.New("auth: too many logins in flight")
	}
	o.pending[handle] = &pendingLogin{
		state: state, nonce: nonce, verifier: verifier,
		next: safeNext(next), expires: o.now().Add(PendingLoginTTL),
	}
	o.mu.Unlock()

	authURL = o.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return authURL, handle, nil
}

// OIDCResult is a completed login.
type OIDCResult struct {
	Subject string
	Role    Role
	// Next is where the browser asked to go before it was sent to the provider.
	Next string
}

// Complete finishes a login: it verifies the callback, exchanges the code, and
// maps the resulting claims to a role.
func (o *OIDC) Complete(ctx context.Context, handle, state, code string) (OIDCResult, error) {
	o.mu.Lock()
	o.evictExpired()
	login, ok := o.pending[handle]
	// Removed on first use whatever happens next: an authorization code is
	// single-use, and so is the state that authorises redeeming it.
	delete(o.pending, handle)
	o.mu.Unlock()

	if !ok || login.expires.Before(o.now()) {
		return OIDCResult{}, ErrOIDCState
	}
	if !constantTimeEqual(state, login.state) {
		return OIDCResult{}, ErrOIDCState
	}

	token, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(login.verifier))
	if err != nil {
		return OIDCResult{}, fmt.Errorf("auth: OIDC code exchange: %w", err)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		// No ID token means this is an OAuth2 provider, not an OIDC one. Kanea
		// does not fall back to a userinfo call here: the whole reason to
		// require OIDC is that the identity arrives signed.
		return OIDCResult{}, errors.New("auth: the provider returned no id_token")
	}

	idToken, err := o.verifier.Verify(ctx, rawID)
	if err != nil {
		return OIDCResult{}, fmt.Errorf("auth: ID token verification: %w", err)
	}
	if !constantTimeEqual(idToken.Nonce, login.nonce) {
		// A replayed ID token from another login would pass signature, issuer,
		// audience and expiry. The nonce is what ties it to *this* attempt.
		return OIDCResult{}, ErrOIDCState
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return OIDCResult{}, fmt.Errorf("auth: read claims: %w", err)
	}

	role, ok := o.cfg.roleFor(claims)
	if !ok {
		o.log.Warn("OIDC login refused: no role maps to this account",
			"subject", subjectFrom(claims, idToken.Subject), "claim", o.cfg.RoleClaim)
		return OIDCResult{}, ErrOIDCNoRole
	}
	return OIDCResult{
		Subject: subjectFrom(claims, idToken.Subject),
		Role:    role,
		Next:    login.next,
	}, nil
}

// Issuer reports the configured provider, for the dashboard's sign-in button.
func (o *OIDC) Issuer() string { return o.cfg.Issuer }

// evictExpired drops timed-out logins. The caller holds the lock.
func (o *OIDC) evictExpired() {
	now := o.now()
	for handle, login := range o.pending {
		if login.expires.Before(now) {
			delete(o.pending, handle)
		}
	}
}

// roleFor maps claims to a role, or reports that none applies.
//
// Admin is checked first: someone in both lists gets the role they were
// deliberately granted rather than whichever list happened to be examined first.
func (c OIDCConfig) roleFor(claims map[string]any) (Role, bool) {
	values := claimValues(claims[c.RoleClaim])
	if matchesAny(values, c.AdminValues) {
		return RoleAdmin, true
	}
	if matchesAny(values, c.ViewerValues) {
		return RoleViewer, true
	}
	return "", false
}

// claimValues normalises a claim that may be a string, a list, or absent.
//
// Providers disagree: `groups` is usually a list, `email` and `hd` are strings,
// and some send a space-separated string. All three are accepted because the
// alternative is an operator discovering the difference at login time.
func claimValues(raw any) []string {
	switch v := raw.(type) {
	case string:
		return strings.Fields(v)
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func matchesAny(values, allowed []string) bool {
	for _, value := range values {
		for _, want := range allowed {
			if value == want {
				return true
			}
		}
	}
	return false
}

// subjectFrom picks the most human name available, falling back to the opaque
// subject. An audit trail naming `108423...` is technically correct and
// operationally useless.
func subjectFrom(claims map[string]any, sub string) string {
	for _, key := range []string{"preferred_username", "email", "name"} {
		if value, ok := claims[key].(string); ok && value != "" {
			return value
		}
	}
	return sub
}

// safeNext bounds where a login may return the browser to.
//
// Only a path on this origin. Anything else — an absolute URL, a
// protocol-relative "//evil.example" — is an open redirect, which turns the
// login page into a credible phishing hop.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") {
		return "/"
	}
	// "//host" is protocol-relative and leaves this origin. So does "/\host":
	// browsers normalise a backslash to a slash in the authority position, so
	// checking for "//" alone is a defence that Chrome walks straight past.
	if strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		return "/"
	}
	if parsed, err := url.Parse(next); err != nil || parsed.Host != "" || parsed.Scheme != "" {
		return "/"
	}
	return next
}

// constantTimeEqual compares two secrets without leaking their contents through
// timing. The values here are fixed-length random strings, so the length
// difference this reveals is not information anyone can use.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
