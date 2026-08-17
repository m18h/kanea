package edge

// Request authentication (PRD v1.40, §6.2 R27): basic, bearer and JWT
// verification at the edge.
//
// The §5.2.6 boundary decides the whole shape. The edge resolves no secrets
// and the route table is world-readable, so routes.json carries only a
// fail-closed `auth` marker per route, and the *verifier material* arrives in
// the restricted bundle beside the certificates: bcrypt lines (verifier
// material by construction), SHA-256 hashes of bearer tokens (the file cannot
// authenticate anyone), and JWT keys; public for RS256/ES256, and only HS256
// crosses as a secret, because MAC verification cannot be done with less.
//
// A route marked auth whose entry is missing or invalid answers 503, never
// open: middleware that fails open is R16's original sin. And a JWT's
// algorithm is configured, never read from the token: the alg-confusion
// class is retired by construction, not by a denylist.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ReasonAuth labels an auth refusal in the §9.1.1 metrics.
const ReasonAuth = "auth"

// Auth modes (R27).
const (
	AuthBasic  = "basic"
	AuthBearer = "bearer"
	AuthJWT    = "jwt"
)

// JWT algorithms (R27). A closed set: the algorithm is configuration, and an
// unknown one is an invalid entry, not a fallback.
const (
	AlgHS256 = "HS256"
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// jwtLeeway absorbs clock skew between the token's issuer and this node.
const jwtLeeway = 30 * time.Second

// AuthEntry is one service's verifier material, as the restricted bundle
// carries it (R27). kanead resolves the spec's references and publishes this;
// the edge only ever verifies.
type AuthEntry struct {
	Project string `json:"project"`
	Service string `json:"service"`
	// Mode is AuthBasic, AuthBearer or AuthJWT.
	Mode string `json:"mode"`
	// Users are htpasswd-format lines, bcrypt only ("user:$2y$…").
	Users []string `json:"users,omitempty"`
	// TokenHashes are lowercase hex SHA-256 of accepted bearer tokens. Never
	// the tokens: this file must not be able to authenticate anyone.
	TokenHashes []string `json:"token_hashes,omitempty"`
	// JWT is the verification config for AuthJWT.
	JWT *JWTConfig `json:"jwt,omitempty"`
}

// JWTConfig verifies tokens against a static key (R27: no JWKS, no fetch).
type JWTConfig struct {
	// Algorithm is AlgHS256, AlgRS256 or AlgES256: configured, never read
	// from the token.
	Algorithm string `json:"algorithm"`
	// SecretB64 is the HS256 key, base64. The one genuinely secret field in
	// an AuthEntry, and the reason the bundle is restricted rather than this
	// being part of routes.json.
	SecretB64 string `json:"secret_b64,omitempty"`
	// PublicKeyPEM is the RS256/ES256 verification key.
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	// Issuer and Audience are required claim values when non-empty.
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
}

// Name keys the entry the way routes are keyed.
func (e AuthEntry) Name() string { return e.Project + "/" + e.Service }

// authTable is the compiled form the request path consults. Immutable;
// swapped whole on bundle reload, like the route table.
type authTable struct {
	entries map[string]*compiledAuth
}

// compiledAuth is one entry, parsed and ready to verify.
type compiledAuth struct {
	mode string
	// invalid records an entry that failed to compile. Kept rather than
	// dropped: the route stays marked, and marked-without-material is 503;
	// the difference between "misconfigured, fix me" and "open".
	invalid string

	users  map[string][]byte // user → bcrypt hash
	tokens map[[32]byte]bool // sha256(token)

	alg      string
	hmacKey  []byte
	rsaKey   *rsa.PublicKey
	ecdsaKey *ecdsa.PublicKey
	issuer   string
	audience string

	// okCache bounds bcrypt's per-request cost: a hash of credentials that
	// verified once verifies by lookup until the table is swapped. Success
	// only: a failure must always pay full price, or the cache becomes a
	// fast oracle for guessing.
	mu      sync.Mutex
	okCache map[[32]byte]bool
}

// okCacheCap bounds the success cache. Small on purpose: it exists for the
// one hot credential a dashboard or a poller repeats, not as a session store.
const okCacheCap = 256

// newAuthTable compiles the bundle's entries. Compilation failures are kept
// as invalid entries, never dropped: see compiledAuth.invalid.
func newAuthTable(entries []AuthEntry) *authTable {
	t := &authTable{entries: make(map[string]*compiledAuth, len(entries))}
	for _, e := range entries {
		t.entries[e.Name()] = compileAuth(e)
	}
	return t
}

func compileAuth(e AuthEntry) *compiledAuth {
	c := &compiledAuth{mode: e.Mode, okCache: map[[32]byte]bool{}}
	switch e.Mode {
	case AuthBasic:
		c.users = make(map[string][]byte, len(e.Users))
		for _, line := range e.Users {
			user, hash, ok := strings.Cut(line, ":")
			// bcrypt only (R27): a line that is not a bcrypt hash is a
			// credential pretending to be verifier material.
			if !ok || user == "" || !strings.HasPrefix(hash, "$2") {
				c.invalid = fmt.Sprintf("user line for %q is not user:<bcrypt-hash>", user)
				return c
			}
			// The projection enforces the same ceiling; this is the
			// belt-and-braces half for a bundle that never passed through it.
			if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost > MaxBcryptCost {
				c.invalid = fmt.Sprintf("user line for %q has a bcrypt cost above %d", user, MaxBcryptCost)
				return c
			}
			c.users[user] = []byte(hash)
		}
		if len(c.users) == 0 {
			c.invalid = "basic auth with no users"
		}
	case AuthBearer:
		c.tokens = make(map[[32]byte]bool, len(e.TokenHashes))
		for _, h := range e.TokenHashes {
			raw, err := hex.DecodeString(h)
			if err != nil || len(raw) != 32 {
				c.invalid = "token hash is not a hex sha-256"
				return c
			}
			var key [32]byte
			copy(key[:], raw)
			c.tokens[key] = true
		}
		if len(c.tokens) == 0 {
			c.invalid = "bearer auth with no tokens"
		}
	case AuthJWT:
		if e.JWT == nil {
			c.invalid = "jwt auth with no config"
			return c
		}
		c.alg, c.issuer, c.audience = e.JWT.Algorithm, e.JWT.Issuer, e.JWT.Audience
		switch e.JWT.Algorithm {
		case AlgHS256:
			key, err := base64.StdEncoding.DecodeString(e.JWT.SecretB64)
			if err != nil || len(key) == 0 {
				c.invalid = "HS256 secret is not base64"
				return c
			}
			c.hmacKey = key
		case AlgRS256, AlgES256:
			pub, err := parsePublicKey(e.JWT.PublicKeyPEM)
			if err != nil {
				c.invalid = err.Error()
				return c
			}
			switch key := pub.(type) {
			case *rsa.PublicKey:
				if e.JWT.Algorithm != AlgRS256 {
					c.invalid = "ES256 configured with an RSA key"
					return c
				}
				c.rsaKey = key
			case *ecdsa.PublicKey:
				if e.JWT.Algorithm != AlgES256 {
					c.invalid = "RS256 configured with an ECDSA key"
					return c
				}
				c.ecdsaKey = key
			default:
				c.invalid = "public key is neither RSA nor ECDSA"
				return c
			}
		default:
			c.invalid = fmt.Sprintf("unknown jwt algorithm %q", e.JWT.Algorithm)
		}
	default:
		c.invalid = fmt.Sprintf("unknown auth mode %q", e.Mode)
	}
	return c
}

func parsePublicKey(pemText string) (any, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}

// challenge is the WWW-Authenticate value a refusal carries.
func (c *compiledAuth) challenge() string {
	if c.mode == AuthBasic {
		return `Basic realm="kanea"`
	}
	return "Bearer"
}

// verify checks one request. It never writes to w; the caller renders the
// refusal so the metrics and the response stay in one place.
func (c *compiledAuth) verify(r *http.Request, now time.Time) bool {
	switch c.mode {
	case AuthBasic:
		user, pass, ok := r.BasicAuth()
		if !ok {
			return false
		}
		hash, known := c.users[user]
		if !known {
			// Burn the cost anyway: a fast miss for an unknown user and a
			// slow miss for a wrong password is a username oracle.
			_ = bcrypt.CompareHashAndPassword(bcryptDummy, []byte(pass)) //nolint:errcheck // burning the cost; the mismatch is the point
			return false
		}
		key := sha256.Sum256([]byte(user + "\x00" + pass))
		c.mu.Lock()
		hit := c.okCache[key]
		c.mu.Unlock()
		if hit {
			return true
		}
		if bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil {
			return false
		}
		c.mu.Lock()
		if len(c.okCache) >= okCacheCap {
			c.okCache = map[[32]byte]bool{}
		}
		c.okCache[key] = true
		c.mu.Unlock()
		return true

	case AuthBearer:
		token, ok := bearerToken(r)
		if !ok {
			return false
		}
		sum := sha256.Sum256([]byte(token))
		// Map lookup on a fixed-size digest: length is not attacker-chosen
		// and the digest hides the token, so this is not a timing side
		// channel on the credential itself.
		return c.tokens[sum]

	case AuthJWT:
		token, ok := bearerToken(r)
		if !ok {
			return false
		}
		return c.verifyJWT(token, now)
	}
	return false
}

// MaxBcryptCost bounds the work a basic_auth line may demand per request
// (K-23). The twin lives in reconciler (the projection enforces it at
// resolve); the two are deliberately duplicated, like CapabilityNone: the
// import direction between the packages points the other way.
const MaxBcryptCost = 14

// bcryptDummy equalises the unknown-user path's cost. Generated once, at the
// cost ceiling (K-23): a line may cost up to MaxBcryptCost, so the dummy must
// not burn *less* than any real line, or the unknown-user timing becomes a
// username oracle.
var bcryptDummy = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("kanea-timing-equalizer"), MaxBcryptCost)
	if err != nil {
		panic(err)
	}
	return h
}()

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	return auth[len(prefix):], true
}

// verifyJWT is a deliberately small verifier: three segments, the configured
// algorithm, exp mandatory, nbf/iss/aud honoured. Hand-written on the S3/MCP
// precedent; the surface Kanea needs is bounded, stdlib crypto does the
// actual verification, and "alg: none" cannot exist here because the
// algorithm never comes from the token.
func (c *compiledAuth) verifyJWT(token string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	headerRaw, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	claimsRaw, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || header.Alg != c.alg {
		return false
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)
	switch c.alg {
	case AlgHS256:
		mac := hmac.New(sha256.New, c.hmacKey)
		mac.Write(signingInput)
		if subtle.ConstantTimeCompare(mac.Sum(nil), sig) != 1 {
			return false
		}
	case AlgRS256:
		if rsa.VerifyPKCS1v15(c.rsaKey, crypto.SHA256, digest[:], sig) != nil {
			return false
		}
	case AlgES256:
		if len(sig) != 64 {
			return false
		}
		rr := new(big.Int).SetBytes(sig[:32])
		ss := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(c.ecdsaKey, digest[:], rr, ss) {
			return false
		}
	default:
		return false
	}

	var claims struct {
		Exp *float64        `json:"exp"`
		Nbf *float64        `json:"nbf"`
		Iss string          `json:"iss"`
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(claimsRaw, &claims) != nil {
		return false
	}
	// exp is mandatory: a token that never expires is a credential with no
	// revocation story, and accepting one silently is not a default.
	if claims.Exp == nil || now.After(time.Unix(int64(*claims.Exp), 0).Add(jwtLeeway)) {
		return false
	}
	if claims.Nbf != nil && now.Add(jwtLeeway).Before(time.Unix(int64(*claims.Nbf), 0)) {
		return false
	}
	if c.issuer != "" && claims.Iss != c.issuer {
		return false
	}
	if c.audience != "" && !audienceContains(claims.Aud, c.audience) {
		return false
	}
	return true
}

// audienceContains handles aud's two legal JSON shapes: a string or an array.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
