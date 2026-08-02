package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/store"
)

const goodPassword = "correct-horse-battery-staple"

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newAuth(t *testing.T) (*auth.Store, *clock) {
	t.Helper()

	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	c := &clock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	a, err := auth.NewStore(auth.StoreConfig{Store: st, Now: c.Now})
	if err != nil {
		t.Fatalf("new auth store: %v", err)
	}
	return a, c
}

func TestLoginIssuesASession(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	session, cookie, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.Role != auth.RoleAdmin || session.Subject != "admin" {
		t.Errorf("session = %+v", session)
	}
	if cookie == "" || session.CSRF == "" {
		t.Error("login returned an empty cookie or CSRF token")
	}

	// The cookie value is a secret, so what is stored must not be the cookie.
	if strings.Contains(session.Hash, cookie) {
		t.Error("the session record holds the raw cookie value")
	}

	resolved, err := a.Session(ctx, cookie)
	if err != nil || resolved.Subject != "admin" {
		t.Errorf("Session = %+v, %v", resolved, err)
	}
}

// An unknown user and a wrong password must be indistinguishable, or the login
// endpoint enumerates accounts (§14, A07).
func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	_, _, wrongPassword := a.Login(ctx, "admin", "not-the-password", "10.0.0.1")
	_, _, noSuchUser := a.Login(ctx, "ghost", "not-the-password", "10.0.0.2")

	if !errors.Is(wrongPassword, auth.ErrUnauthenticated) {
		t.Errorf("wrong password = %v", wrongPassword)
	}
	if !errors.Is(noSuchUser, auth.ErrUnauthenticated) {
		t.Errorf("unknown user = %v", noSuchUser)
	}
	if wrongPassword.Error() != noSuchUser.Error() {
		t.Errorf("the two failures differ: %q vs %q", wrongPassword, noSuchUser)
	}
}

func TestLoginRateLimit(t *testing.T) {
	a, c := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	for range 5 {
		if _, _, err := a.Login(ctx, "admin", "wrong", "10.0.0.1"); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("expected an auth failure, got %v", err)
		}
	}

	// Locked out — and the correct password does not get through either, which
	// is the point: an attacker must not be able to tell they found it.
	if _, _, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("after 5 failures = %v, want ErrRateLimited", err)
	}

	c.advance(2 * time.Minute)
	if _, _, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1"); err != nil {
		t.Errorf("after the lockout expired = %v", err)
	}
}

// Per-account as well as per-source: a botnet spreading across addresses would
// otherwise never trip a per-source limit.
func TestLoginRateLimitAppliesPerAccount(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	// Five failures, each from a different address.
	for i := range 5 {
		source := "10.0.0." + string(rune('1'+i))
		if _, _, err := a.Login(ctx, "admin", "wrong", source); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("attempt %d = %v", i, err)
		}
	}
	if _, _, err := a.Login(ctx, "admin", goodPassword, "10.0.0.99"); !errors.Is(err, auth.ErrRateLimited) {
		t.Errorf("a sixth address = %v, want the account to be locked", err)
	}
}

// A successful login clears the counters, so a person who mistypes twice and
// then succeeds is not locked out on their next attempt.
func TestSuccessClearsTheRateLimit(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	for range 3 {
		_, _, _ = a.Login(ctx, "admin", "wrong", "10.0.0.1")
	}
	if _, _, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	for range 4 {
		_, _, _ = a.Login(ctx, "admin", "wrong", "10.0.0.1")
	}
	// Four failures after a reset is still under the limit.
	if _, _, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1"); err != nil {
		t.Errorf("Login after a reset = %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	a, c := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	_, cookie, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Absolute, not sliding: using it does not extend it.
	c.advance(11 * time.Hour)
	if _, err := a.Session(ctx, cookie); err != nil {
		t.Fatalf("session at 11h = %v", err)
	}
	c.advance(2 * time.Hour)
	if _, err := a.Session(ctx, cookie); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("session at 13h = %v, want expired", err)
	}
}

// Logout must actually revoke, which is why sessions are server-side.
func TestLogoutRevokes(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	_, cookie, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := a.DeleteSession(ctx, cookie); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := a.Session(ctx, cookie); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("Session after logout = %v", err)
	}
}

func TestTokenLifecycle(t *testing.T) {
	a, c := newAuth(t)
	ctx := context.Background()

	token, presented, err := a.CreateToken(ctx, "ci", auth.RoleViewer, c.now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if !strings.HasPrefix(presented, auth.TokenPrefix) {
		t.Errorf("token %q is not recognisable as a kanea credential", presented)
	}

	id, err := a.AuthenticateToken(ctx, presented)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if id.Role != auth.RoleViewer || id.Via != auth.MethodToken || id.TokenID != token.ID {
		t.Errorf("identity = %+v", id)
	}

	// The secret is never stored, so a listing cannot hand one back.
	tokens, err := a.Tokens(ctx)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("Tokens = %v, %v", tokens, err)
	}
	if tokens[0].Hash != "" {
		t.Error("the listing includes the token hash")
	}

	c.advance(2 * time.Hour)
	if _, err := a.AuthenticateToken(ctx, presented); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("expired token = %v", err)
	}

	c.advance(-2 * time.Hour)
	if err := a.RevokeToken(ctx, token.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := a.AuthenticateToken(ctx, presented); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("revoked token = %v", err)
	}
}

func TestAuthenticateTokenRejectsRubbish(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	for _, presented := range []string{
		"", "not-a-token", "kanea_", "kanea_abc", "kanea_abc.", "kanea_.secret",
		"bearer kanea_abc.def",
	} {
		if _, err := a.AuthenticateToken(ctx, presented); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("AuthenticateToken(%q) = %v, want unauthenticated", presented, err)
		}
	}
}

// A token whose id exists but whose secret is wrong must fail — otherwise the
// public half alone would be a credential.
func TestTokenIDAloneIsNotACredential(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	token, _, err := a.CreateToken(ctx, "ci", auth.RoleAdmin, time.Time{})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	forged := auth.TokenPrefix + token.ID + ".guessed-secret"
	if _, err := a.AuthenticateToken(ctx, forged); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("forged token = %v", err)
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := auth.HashPassword(goodPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if strings.Contains(hash, goodPassword) {
		t.Fatal("the hash contains the plaintext")
	}
	if !auth.VerifyPassword(goodPassword, hash) {
		t.Error("the password does not verify against its own hash")
	}
	if auth.VerifyPassword("wrong", hash) {
		t.Error("a wrong password verified")
	}

	// Same password, different salt: two hashes must differ, or a leaked file
	// shows which accounts share a password.
	other, err := auth.HashPassword(goodPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == other {
		t.Error("two hashes of the same password are identical")
	}
}

func TestHashPasswordRefusesWeakInput(t *testing.T) {
	if _, err := auth.HashPassword("short"); !errors.Is(err, auth.ErrWeakPassword) {
		t.Errorf("short password = %v", err)
	}
	// bcrypt silently truncates past 72 bytes, so a longer passphrase would get
	// less security than the user believes.
	long := strings.Repeat("a", 100)
	if _, err := auth.HashPassword(long); !errors.Is(err, auth.ErrWeakPassword) {
		t.Errorf("over-long password = %v, want a refusal rather than truncation", err)
	}
}

func TestUsersDoNotExposeHashes(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	users, err := a.Users(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("Users = %v, %v", users, err)
	}
	if users[0].PasswordHash != "" {
		t.Error("the listing includes a password hash")
	}
}

func TestRoles(t *testing.T) {
	if !auth.RoleAdmin.CanWrite() {
		t.Error("admin cannot write")
	}
	if auth.RoleViewer.CanWrite() {
		t.Error("viewer can write")
	}
	// An unknown role is never quietly treated as a lesser one.
	if auth.Role("superuser").Valid() || auth.Role("").Valid() {
		t.Error("an unknown role validated")
	}
	if auth.Role("superuser").CanWrite() {
		t.Error("an unknown role can write")
	}
}

func TestPutUserRejectsBadNames(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	// A slash would make one user's record look like another's namespace.
	for _, name := range []string{"", "a/b", "with space", strings.Repeat("x", 100)} {
		if err := a.PutUser(ctx, name, goodPassword, auth.RoleAdmin); err == nil {
			t.Errorf("PutUser(%q) was accepted", name)
		}
	}
	if err := a.PutUser(ctx, "admin", goodPassword, auth.Role("root")); err == nil {
		t.Error("an unknown role was accepted")
	}
}

func TestHasUsers(t *testing.T) {
	a, _ := newAuth(t)
	ctx := context.Background()

	has, err := a.HasUsers(ctx)
	if err != nil || has {
		t.Fatalf("HasUsers on a fresh store = %v, %v", has, err)
	}
	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	has, err = a.HasUsers(ctx)
	if err != nil || !has {
		t.Errorf("HasUsers after adding one = %v, %v", has, err)
	}
}

func TestSweepSessions(t *testing.T) {
	a, c := newAuth(t)
	ctx := context.Background()

	if err := a.PutUser(ctx, "admin", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	if _, _, err := a.Login(ctx, "admin", goodPassword, "10.0.0.1"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if n, err := a.SweepSessions(ctx); err != nil || n != 0 {
		t.Errorf("sweep of a live session = %d, %v", n, err)
	}
	c.advance(13 * time.Hour)
	if n, err := a.SweepSessions(ctx); err != nil || n != 1 {
		t.Errorf("sweep after expiry = %d, %v", n, err)
	}
}

func TestIdentityContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := auth.FromContext(ctx); ok {
		t.Error("a bare context carries an identity")
	}

	want := auth.Identity{Subject: "admin", Role: auth.RoleAdmin, Via: auth.MethodSession}
	got, ok := auth.FromContext(auth.WithIdentity(ctx, want))
	if !ok || got != want {
		t.Errorf("FromContext = %+v, %v", got, ok)
	}
}
