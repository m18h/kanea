package edge

// R27 (v1.40): the auth middleware; modes, fail-closed behaviour, and the
// JWT verifier's refusals.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// authProxy builds a proxy whose route requires auth, serving a fake
// upstream, with the given entries loaded.
func authProxy(t *testing.T, entries []AuthEntry) (*Proxy, compiled) {
	t.Helper()
	p := NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)})
	p.SetAuth(entries)
	route, err := compile(Route{
		Project: "shop", Service: "fn",
		Upstream: "10.201.0.7", Port: 8080,
		AuthRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, route
}

// try runs authorize against a request and reports the written status when it
// refused, or 0 when it passed.
func try(t *testing.T, p *Proxy, route compiled, mutate func(*http.Request)) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://fn.shop.test/", nil)
	mutate(r)
	w := httptest.NewRecorder()
	if p.authorize(w, r, route) {
		return 0
	}
	return w.Code
}

func TestAuthFailsClosedWithoutMaterial(t *testing.T) {
	// Marked route, no entry at all: 503, never open. The bundle may simply
	// not have arrived yet, and "open until the file lands" is not a state
	// an authenticated route may pass through.
	p, route := authProxy(t, nil)
	if code := try(t, p, route, func(*http.Request) {}); code != http.StatusServiceUnavailable {
		t.Fatalf("no material = %d, want 503", code)
	}

	// Invalid entry: same answer, with the reason logged rather than served.
	p2, route2 := authProxy(t, []AuthEntry{{
		Project: "shop", Service: "fn", Mode: AuthBasic,
		Users: []string{"ama:plaintext-password"}, // not a bcrypt hash
	}})
	if code := try(t, p2, route2, func(*http.Request) {}); code != http.StatusServiceUnavailable {
		t.Fatalf("invalid material = %d, want 503", code)
	}
}

func TestBasicAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	p, route := authProxy(t, []AuthEntry{{
		Project: "shop", Service: "fn", Mode: AuthBasic,
		Users: []string{"ama:" + string(hash)},
	}})

	if code := try(t, p, route, func(r *http.Request) { r.SetBasicAuth("ama", "hunter2") }); code != 0 {
		t.Fatalf("valid credentials refused with %d", code)
	}
	// The success cache must serve the repeat without weakening failures.
	if code := try(t, p, route, func(r *http.Request) { r.SetBasicAuth("ama", "hunter2") }); code != 0 {
		t.Fatalf("cached credentials refused with %d", code)
	}
	for name, mutate := range map[string]func(*http.Request){
		"wrong password": func(r *http.Request) { r.SetBasicAuth("ama", "wrong") },
		"unknown user":   func(r *http.Request) { r.SetBasicAuth("nobody", "hunter2") },
		"no header":      func(*http.Request) {},
	} {
		if code := try(t, p, route, mutate); code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, code)
		}
	}
}

func TestBearerAuth(t *testing.T) {
	token := "kanea-test-token-of-adequate-entropy"
	sum := sha256.Sum256([]byte(token))
	p, route := authProxy(t, []AuthEntry{{
		Project: "shop", Service: "fn", Mode: AuthBearer,
		TokenHashes: []string{hex.EncodeToString(sum[:])},
	}})

	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	}); code != 0 {
		t.Fatalf("valid token refused with %d", code)
	}
	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer not-the-token")
	}); code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", code)
	}
	// The challenge names the scheme.
	r := httptest.NewRequest(http.MethodGet, "http://fn.shop.test/", nil)
	w := httptest.NewRecorder()
	p.authorize(w, r, route)
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

// signJWT builds a token; alg/claims are the test's to bend.
func signJWT(t *testing.T, alg string, key any, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch k := key.(type) {
	case []byte:
		mac := hmac.New(sha256.New, k)
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	default:
		t.Fatalf("unsupported key %T", key)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestJWTHS256(t *testing.T) {
	key := []byte("a-32-byte-minimum-hs256-test-key")
	p, route := authProxy(t, []AuthEntry{{
		Project: "shop", Service: "fn", Mode: AuthJWT,
		JWT: &JWTConfig{
			Algorithm: AlgHS256,
			SecretB64: base64.StdEncoding.EncodeToString(key),
			Issuer:    "https://issuer.test",
			Audience:  "kanea",
		},
	}})

	exp := float64(time.Now().Add(time.Hour).Unix())
	good := map[string]any{"exp": exp, "iss": "https://issuer.test", "aud": "kanea"}
	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+signJWT(t, "HS256", key, good))
	}); code != 0 {
		t.Fatalf("valid token refused with %d", code)
	}
	// aud as an array is the other legal shape.
	arrAud := map[string]any{"exp": exp, "iss": "https://issuer.test", "aud": []string{"x", "kanea"}}
	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+signJWT(t, "HS256", key, arrAud))
	}); code != 0 {
		t.Fatalf("array audience refused with %d", code)
	}

	refusals := map[string]string{
		"expired":        signJWT(t, "HS256", key, map[string]any{"exp": float64(time.Now().Add(-time.Hour).Unix()), "iss": "https://issuer.test", "aud": "kanea"}),
		"no exp":         signJWT(t, "HS256", key, map[string]any{"iss": "https://issuer.test", "aud": "kanea"}),
		"wrong issuer":   signJWT(t, "HS256", key, map[string]any{"exp": exp, "iss": "https://evil.test", "aud": "kanea"}),
		"wrong audience": signJWT(t, "HS256", key, map[string]any{"exp": exp, "iss": "https://issuer.test", "aud": "other"}),
		"not yet valid":  signJWT(t, "HS256", key, map[string]any{"exp": exp, "nbf": float64(time.Now().Add(time.Hour).Unix()), "iss": "https://issuer.test", "aud": "kanea"}),
		"wrong key":      signJWT(t, "HS256", []byte("a-different-32-byte-hs256-key!!!"), good),
		"garbage":        "not.a.jwt",
	}
	for name, token := range refusals {
		if code := try(t, p, route, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
		}); code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, code)
		}
	}
}

// The algorithm is configuration, never the token's claim: an HS256 token
// against an ES256 config is refused even when its MAC would verify under
// the "key" a public key would make. This is the alg-confusion class.
func TestJWTAlgorithmIsConfiguredNotRead(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	p, route := authProxy(t, []AuthEntry{{
		Project: "shop", Service: "fn", Mode: AuthJWT,
		JWT: &JWTConfig{Algorithm: AlgES256, PublicKeyPEM: pubPEM},
	}})

	exp := float64(time.Now().Add(time.Hour).Unix())
	// A genuine ES256 token passes.
	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+signJWT(t, "ES256", priv, map[string]any{"exp": exp}))
	}); code != 0 {
		t.Fatalf("valid ES256 token refused with %d", code)
	}
	// An HS256 token MACed with the public key's PEM (the classic downgrade)
	// is refused on the alg mismatch alone.
	forged := signJWT(t, "HS256", []byte(pubPEM), map[string]any{"exp": exp})
	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+forged)
	}); code != http.StatusUnauthorized {
		t.Fatalf("alg-confused token = %d, want 401", code)
	}
	// And "none" does not exist here at all.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + "9999999999" + `}`))
	if code := try(t, p, route, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+header+"."+body+".")
	}); code != http.StatusUnauthorized {
		t.Fatalf("alg=none = %d, want 401", code)
	}
}

// End to end through serveRoute: the marked route refuses before the
// upstream, and passes with credentials; auth sits inside the chain, not
// beside it.
func TestServeRouteEnforcesAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "served")
	}))
	t.Cleanup(upstream.Close)
	up := splitUpstream(t, strings.TrimPrefix(upstream.URL, "http://"))

	token := "end-to-end-token"
	sum := sha256.Sum256([]byte(token))
	p := NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)})
	p.SetAuth([]AuthEntry{{
		Project: "shop", Service: "fn", Mode: AuthBearer,
		TokenHashes: []string{hex.EncodeToString(sum[:])},
	}})
	route, err := compile(Route{
		Project: "shop", Service: "fn",
		Upstream: up.host, Port: up.port, AuthRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://fn.shop.test/", nil)
	w := httptest.NewRecorder()
	p.serveRoute(w, r, route, "test", EntrypointWeb)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", w.Code)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://fn.shop.test/", nil)
	r2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	p.serveRoute(w2, r2, route, "test", EntrypointWeb)
	if w2.Code != http.StatusOK || w2.Body.String() != "served" {
		t.Fatalf("authenticated = %d %q, want 200 served", w2.Code, w2.Body.String())
	}
}
