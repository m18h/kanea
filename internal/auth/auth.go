// Package auth authenticates API, dashboard and MCP callers (PRD §13).
//
// Everything here is deny-by-default. There is no anonymous identity, no
// "unauthenticated but allowed" state, and no route that opts out except the
// three §5.2.1 names: login, the ACME challenge path, and health. That is the
// A01 requirement stated as code rather than as a convention to remember.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role is what a caller may do. Per-project ACLs are v1.1 (§13.3).
type Role string

const (
	// RoleAdmin may change anything.
	RoleAdmin Role = "admin"
	// RoleViewer may read, and nothing else.
	RoleViewer Role = "viewer"
)

// Valid reports whether a role is one Kanea knows.
//
// An unknown role is never treated as a lesser one: a config typo must fail
// loudly rather than silently grant or silently deny.
func (r Role) Valid() bool { return r == RoleAdmin || r == RoleViewer }

// CanWrite reports whether this role may mutate.
func (r Role) CanWrite() bool { return r == RoleAdmin }

// Identity is an authenticated caller.
type Identity struct {
	// Subject is the user name, or the token's name for a bearer token.
	Subject string
	Role    Role
	// Via records how the caller proved who they are, for the audit log.
	Via Method
	// TokenID is set when Via is MethodToken, so a specific token can be
	// revoked after it appears in an audit trail.
	TokenID string
}

// Method is how a caller authenticated.
type Method string

// Authentication methods.
const (
	MethodSession Method = "session"
	MethodToken   Method = "token"
	// MethodSocket is a caller on the unix socket of a daemon with no auth
	// configured. It is the local-root path §13.1 permits, and it is recorded
	// so an audit entry never claims a user that did not exist.
	MethodSocket Method = "socket"
)

// Errors callers distinguish.
var (
	// ErrUnauthenticated means no usable credential was presented.
	ErrUnauthenticated = errors.New("auth: not authenticated")
	// ErrForbidden means the caller is known but not permitted.
	ErrForbidden = errors.New("auth: forbidden")
	// ErrRateLimited means too many failures from this source.
	ErrRateLimited = errors.New("auth: too many attempts")
	// ErrNotFound marks a missing user or token.
	ErrNotFound = errors.New("auth: not found")
	// ErrLastAdmin refuses a change that would leave no admin account.
	ErrLastAdmin = errors.New("auth: refusing to remove the last admin")
)

// User is a configured account.
type User struct {
	Name string `json:"name"`
	// PasswordHash is a bcrypt hash. The plaintext never exists in the Store,
	// in a log, or in any API response.
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	Created      time.Time `json:"created"`
	Updated      time.Time `json:"updated"`
}

// Token is a bearer credential for the CLI, MCP or CI.
//
// The secret itself is never stored: only a SHA-256 of it. A Store that leaks
// (through a backup, a snapshot, a bug) must not hand over working credentials,
// and a hash means the only copy of the token is the one shown at creation.
type Token struct {
	// ID is the public half, used to name and revoke a token.
	ID   string `json:"id"`
	Name string `json:"name"`
	Role Role   `json:"role"`
	// Hash is the SHA-256 of the secret, hex-encoded.
	Hash    string    `json:"hash"`
	Created time.Time `json:"created"`
	// Expires bounds the token. Zero means no expiry, which is discouraged and
	// visible in listings for exactly that reason.
	Expires  time.Time `json:"expires,omitempty"`
	LastUsed time.Time `json:"last_used,omitempty"`
}

// Expired reports whether the token may no longer be used.
func (t Token) Expired(now time.Time) bool {
	return !t.Expires.IsZero() && now.After(t.Expires)
}

// Session is a dashboard login.
type Session struct {
	// ID is the value held in the cookie. It is a random secret, so it is
	// stored hashed for the same reason a token is.
	Hash    string    `json:"hash"`
	Subject string    `json:"subject"`
	Role    Role      `json:"role"`
	Created time.Time `json:"created"`
	// Expires is absolute, not sliding: §13.3 wants a 12-hour ceiling on a
	// session, and a sliding window means a stolen cookie never expires while
	// it is being used.
	Expires time.Time `json:"expires"`
	// CSRF is the double-submit token for cookie-authenticated mutations.
	CSRF string `json:"csrf"`
	// Method records how the session was established (v1.47): "session" for
	// a local password, "oidc", "ldap". omitempty keeps pre-v1.47 records
	// byte-identical; an absent value reads as the local path. It is what
	// lets an audit entry on a later request say via: ldap rather than
	// claiming every cookie is a local login.
	Method string `json:"method,omitempty"`
}

// SessionLifetime is the absolute ceiling on a dashboard session (§13.3).
const SessionLifetime = 12 * time.Hour

// Expired reports whether a session is past its absolute expiry.
func (s Session) Expired(now time.Time) bool { return now.After(s.Expires) }

// TokenPrefix marks a Kanea bearer token, so one found in a log or a repository
// is recognisable as a credential to revoke rather than an opaque string.
const TokenPrefix = "kanea_"

// Sizes of the random values this package mints.
//
// A token's id is public and only has to be unique, so it is short; everything
// else carries the entropy and is one size, because "how many bytes was this
// one again" is not a question worth having per credential. 32 bytes is past
// the point where a birthday bound or a guess is worth anyone's time.
const (
	tokenIDBytes = 8
	secretBytes  = 32
)

// NewToken mints a token and returns it with its one-time secret.
//
// The secret is returned exactly once, here. Nothing stores it, so a lost token
// is replaced rather than recovered, which is the property that makes a
// leaked Store harmless.
func NewToken(name string, role Role, expires time.Time, now time.Time) (Token, string, error) {
	if name == "" {
		return Token{}, "", errors.New("auth: a token needs a name")
	}
	if !role.Valid() {
		return Token{}, "", fmt.Errorf("auth: unknown role %q", role)
	}

	id, err := randomHex(tokenIDBytes)
	if err != nil {
		return Token{}, "", err
	}
	secret, err := randomSecret()
	if err != nil {
		return Token{}, "", err
	}

	// The presented form carries the id so a lookup is a single Get rather than
	// a scan comparing hashes, which would be linear in the number of tokens
	// and a timing signal.
	presented := TokenPrefix + id + "." + secret
	return Token{
		ID:      id,
		Name:    name,
		Role:    role,
		Hash:    hashSecret(secret),
		Created: now,
		Expires: expires,
	}, presented, nil
}

// SplitToken separates a presented token into its id and secret.
func SplitToken(presented string) (id, secret string, ok bool) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(presented), TokenPrefix)
	if trimmed == presented && !strings.HasPrefix(presented, TokenPrefix) {
		return "", "", false
	}
	id, secret, found := strings.Cut(trimmed, ".")
	if !found || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// VerifySecret compares a presented secret against a stored hash.
//
// Constant-time: a byte-by-byte comparison that returns early leaks how much of
// a guess was correct, which turns a search over the whole space into a search
// one byte at a time.
func VerifySecret(presented, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashSecret(presented)), []byte(storedHash)) == 1
}

// hashSecret is SHA-256, hex-encoded.
//
// Not bcrypt: a token secret is 256 bits of machine-generated randomness, so
// there is no dictionary to slow down, and a per-request bcrypt would make
// every API call cost ~100 ms. Passwords are a different problem and use bcrypt
// (see password.go).
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NewSession mints a session and returns it with the cookie value.
func NewSession(subject string, role Role, method Method, now time.Time) (Session, string, error) {
	id, err := randomSecret()
	if err != nil {
		return Session{}, "", err
	}
	csrf, err := randomSecret()
	if err != nil {
		return Session{}, "", err
	}
	return Session{
		Hash:    hashSecret(id),
		Subject: subject,
		Role:    role,
		Created: now,
		Expires: now.Add(SessionLifetime),
		CSRF:    csrf,
		Method:  string(method),
	}, id, nil
}

// Via reports how the session was established, defaulting the pre-v1.47
// records (and any zero value) to the local path.
func (s Session) Via() Method {
	if s.Method == "" {
		return MethodSession
	}
	return Method(s.Method)
}

// SessionKey is the Store key for a session cookie value.
func SessionKey(cookieValue string) string { return hashSecret(cookieValue) }

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: random: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// randomSecret returns a URL-safe random string of secretBytes bytes.
func randomSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// contextKey carries the identity through a request.
type contextKey struct{}

// WithIdentity attaches an authenticated identity to a context.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext returns the authenticated identity, if there is one.
//
// A handler that forgets to check gets `ok == false` rather than a zero
// Identity that might read as a valid subject with an empty role.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}
