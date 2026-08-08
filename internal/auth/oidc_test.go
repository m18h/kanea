package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/m18h/kanea/internal/auth"
)

// fakeProvider is a minimal but honest OIDC provider: real discovery, a real
// JWKS, and real RS256 signatures. A stub that skipped the signature would test
// everything except the part that matters.
type fakeProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	// claims is what the next ID token will carry beyond the standard set.
	claims map[string]any
	// nonce is echoed into the ID token; a test overrides it to replay one.
	nonceOverride string
	// lastForm records what the token endpoint received, so PKCE can be checked.
	lastForm url.Values
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &fakeProvider{key: key, keyID: "test-key", claims: map[string]any{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"issuer":                                p.issuer(),
			"authorization_endpoint":                p.issuer() + "/authorize",
			"token_endpoint":                        p.issuer() + "/token",
			"jwks_uri":                              p.issuer() + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"kid": p.keyID,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	// The token endpoint echoes the authorization code into the ID token's
	// nonce. That is the seam these tests use: a real provider carries the
	// nonce from the authorization request, which no test here performs (a
	// browser would), so the test passes the nonce as the code and gets a token
	// bound to its own login. p.nonceOverride is how a test breaks that bond on
	// purpose.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
		}
		p.lastForm = r.Form
		writeJSON(t, w, map[string]any{
			"access_token": "access",
			"token_type":   "Bearer",
			"id_token":     p.idToken(t, r.Form.Get("code")),
		})
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) issuer() string {
	if p.server == nil {
		return ""
	}
	return p.server.URL
}

// idToken signs an ID token for a login. The nonce comes from the
// authorization request the test captured, unless it was overridden.
func (p *fakeProvider) idToken(t *testing.T, nonce string) string {
	t.Helper()
	if p.nonceOverride != "" {
		nonce = p.nonceOverride
	}

	claims := map[string]any{
		"iss":   p.issuer(),
		"aud":   "kanea",
		"sub":   "user-1",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	}
	for k, v := range p.claims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode: %v", err)
	}
}

func newOIDC(t *testing.T, p *fakeProvider, adjust ...func(*auth.OIDCConfig)) *auth.OIDC {
	t.Helper()
	cfg := auth.OIDCConfig{
		Issuer:       p.issuer(),
		ClientID:     "kanea",
		ClientSecret: "client-secret",
		RedirectURL:  "https://kanea.example.com/v1/auth/oidc/callback",
		RoleClaim:    "groups",
		AdminValues:  []string{"platform-admins"},
		ViewerValues: []string{"developers"},
	}
	for _, apply := range adjust {
		apply(&cfg)
	}
	provider, err := auth.NewOIDC(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	return provider
}

// start begins a login and returns the handle, the state and the nonce.
//
// Callers pass the nonce back as the authorization code — see the token
// endpoint above for why.
func start(t *testing.T, o *auth.OIDC, next string) (handle, state, nonce string) {
	t.Helper()
	authURL, handle, err := o.Start(next)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := parsed.Query()
	return handle, q.Get("state"), q.Get("nonce")
}

func TestOIDCLoginMapsClaimsToARole(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.claims = map[string]any{
		"groups":             []any{"developers"},
		"preferred_username": "ada",
	}
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "/services")
	result, err := o.Complete(ctx, handle, state, nonce)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result.Role != auth.RoleViewer {
		t.Errorf("role = %q, want viewer", result.Role)
	}
	// The audit trail needs a name a person recognises, not an opaque subject.
	if result.Subject != "ada" {
		t.Errorf("subject = %q, want ada", result.Subject)
	}
	if result.Next != "/services" {
		t.Errorf("next = %q, want /services", result.Next)
	}
}

func TestOIDCAdminWinsOverViewer(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	// Someone in both lists gets the role they were deliberately granted, not
	// whichever list happened to be checked first.
	p.claims = map[string]any{"groups": []any{"developers", "platform-admins"}}
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "")
	result, err := o.Complete(ctx, handle, state, nonce)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result.Role != auth.RoleAdmin {
		t.Errorf("role = %q, want admin", result.Role)
	}
}

func TestOIDCRefusesAnAccountWithNoMatchingClaim(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	// Authenticated by the provider, unknown to Kanea. Deny-by-default: this is
	// the whole point of the claim mapping (§13.2).
	p.claims = map[string]any{"groups": []any{"contractors"}}
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "")
	if _, err := o.Complete(ctx, handle, state, nonce); err == nil {
		t.Fatal("an unmapped account was let in")
	} else if !strings.Contains(err.Error(), "no role") {
		t.Fatalf("err = %v, want the no-role refusal", err)
	}
}

func TestOIDCAcceptsAStringClaim(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	// Providers disagree about the shape of a claim; a string is as common as
	// a list, and an operator should not have to discover which at login time.
	p.claims = map[string]any{"groups": "platform-admins"}
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "")
	result, err := o.Complete(ctx, handle, state, nonce)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result.Role != auth.RoleAdmin {
		t.Errorf("role = %q, want admin", result.Role)
	}
}

func TestOIDCSendsAPKCEChallenge(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.claims = map[string]any{"groups": []any{"developers"}}
	o := newOIDC(t, p)

	authURL, handle, err := o.Start("")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	query := mustParseQuery(t, authURL)
	if query.Get("code_challenge") == "" {
		t.Fatal("no PKCE challenge in the authorization request")
	}
	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("challenge method = %q, want S256 — plain is no protection at all", got)
	}

	if _, err := o.Complete(ctx, handle, query.Get("state"), query.Get("nonce")); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// The verifier is what proves the exchange comes from whoever started the
	// login, so an intercepted code is worthless without it.
	if p.lastForm.Get("code_verifier") == "" {
		t.Error("no PKCE verifier in the code exchange")
	}
}

func TestOIDCRejectsAMismatchedState(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	o := newOIDC(t, p)

	handle, _, nonce := start(t, o, "")
	if _, err := o.Complete(ctx, handle, "not-the-state", nonce); err == nil {
		t.Fatal("a callback with the wrong state was accepted")
	}
}

func TestOIDCRejectsAnUnknownHandle(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	o := newOIDC(t, p)

	_, state, nonce := start(t, o, "")
	// A state without the cookie that goes with it is someone else's login
	// being replayed into this browser.
	if _, err := o.Complete(ctx, "not-a-handle", state, nonce); err == nil {
		t.Fatal("a callback with no matching handle was accepted")
	}
}

func TestOIDCLoginIsSingleUse(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.claims = map[string]any{"groups": []any{"developers"}}
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "")
	if _, err := o.Complete(ctx, handle, state, nonce); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// An authorization code is single-use, and so is the state that authorises
	// redeeming it.
	if _, err := o.Complete(ctx, handle, state, nonce); err == nil {
		t.Fatal("a login was completed twice")
	}
}

func TestOIDCRejectsAReplayedNonce(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.claims = map[string]any{"groups": []any{"developers"}}
	// An ID token from another login: correctly signed, right issuer, right
	// audience, unexpired. The nonce is the only thing that ties a token to
	// *this* attempt, which is exactly why it is checked.
	p.nonceOverride = "a-nonce-from-another-login"
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "")
	if _, err := o.Complete(ctx, handle, state, nonce); err == nil {
		t.Fatal("a token minted for a different login was accepted")
	}
}

func TestOIDCRejectsATokenSignedByAnotherKey(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.claims = map[string]any{"groups": []any{"developers"}}
	o := newOIDC(t, p)

	handle, state, nonce := start(t, o, "")
	// Swap the signing key after discovery: the JWKS the verifier fetches no
	// longer matches what signs the token.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p.key = other

	if _, err := o.Complete(ctx, handle, state, nonce); err == nil {
		t.Fatal("a token signed by an unknown key was accepted")
	}
}

func TestOIDCExpiredLoginIsRefused(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	clock := &clock{now: time.Unix(1_700_000_000, 0)}
	o := newOIDC(t, p, func(cfg *auth.OIDCConfig) { cfg.Now = clock.Now })

	handle, state, nonce := start(t, o, "")
	clock.advance(auth.PendingLoginTTL + time.Minute)

	if _, err := o.Complete(ctx, handle, state, nonce); err == nil {
		t.Fatal("a login left open past its lifetime was completed")
	}
}

func TestOIDCBoundsTheReturnPath(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)
	p.claims = map[string]any{"groups": []any{"developers"}}
	o := newOIDC(t, p)

	// Anything that leaves this origin turns the login into a phishing hop.
	for _, next := range []string{
		"https://evil.example/",
		"//evil.example/",
		`/\evil.example/`,
		"http://evil.example",
		"",
	} {
		t.Run(next, func(t *testing.T) {
			handle, state, nonce := start(t, o, next)
			result, err := o.Complete(ctx, handle, state, nonce)
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if result.Next != "/" {
				t.Fatalf("next = %q, want / — that is an open redirect", result.Next)
			}
		})
	}
}

func TestNewOIDCRefusesAConfigurationNobodyCouldUse(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider(t)

	tests := []struct {
		name   string
		adjust func(*auth.OIDCConfig)
	}{
		{"no client id", func(c *auth.OIDCConfig) { c.ClientID = "" }},
		{"no redirect URL", func(c *auth.OIDCConfig) { c.RedirectURL = "" }},
		{"no role mapping", func(c *auth.OIDCConfig) {
			c.AdminValues, c.ViewerValues = nil, nil
		}},
		{"unreachable issuer", func(c *auth.OIDCConfig) { c.Issuer = "http://127.0.0.1:1/nope" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auth.OIDCConfig{
				Issuer: p.issuer(), ClientID: "kanea",
				RedirectURL: "https://kanea.example.com/cb",
				AdminValues: []string{"admins"},
			}
			tc.adjust(&cfg)
			if _, err := auth.NewOIDC(ctx, cfg); err == nil {
				t.Fatal("a configuration nobody could log in with was accepted")
			}
		})
	}
}

func mustParseQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return parsed.Query()
}
