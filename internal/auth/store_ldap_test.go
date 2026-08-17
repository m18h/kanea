package auth_test

// Login dispatch with a directory verifier configured (PRD v1.47). The
// verifier here is a fake: what the directory protocol does is ldap_test.go's
// problem; these tests are about what the Store does with each answer.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/store"
)

// fakeVerifier is a PasswordVerifier a test steers. The call counter is the
// load-bearing part: half the dispatch rules are "the verifier is never
// consulted here", which only a count can prove.
type fakeVerifier struct {
	calls   int
	subject string // empty echoes the name back, the real verifier's shape
	role    auth.Role
	err     error
}

func (f *fakeVerifier) Verify(_ context.Context, name, _ string) (string, auth.Role, error) {
	f.calls++
	if f.err != nil {
		return "", "", f.err
	}
	if f.subject != "" {
		return f.subject, f.role, nil
	}
	return name, f.role, nil
}

// newAuthWithVerifier is newAuthWithStore with a directory verifier wired in.
func newAuthWithVerifier(t *testing.T, v auth.PasswordVerifier) (*auth.Store, store.Store, *clock) {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	c := &clock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	a, err := auth.NewStore(auth.StoreConfig{Store: st, Now: c.Now, Verifier: v})
	if err != nil {
		t.Fatalf("new auth store: %v", err)
	}
	return a, st, c
}

func TestALocalRecordIsAnsweredByBcryptAlone(t *testing.T) {
	// A local account can never be shadowed by a directory one, and a wrong
	// local password never costs a bind: the verifier only exists for names
	// with no local record.
	f := &fakeVerifier{role: auth.RoleAdmin}
	a, _, _ := newAuthWithVerifier(t, f)
	ctx := context.Background()

	if err := a.PutUser(ctx, "ada", goodPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("PutUser: %v", err)
	}

	if _, _, err := a.Login(ctx, "ada", "not-the-password", "10.0.0.1"); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("wrong local password = %v, want ErrUnauthenticated", err)
	}
	if f.calls != 0 {
		t.Fatalf("a wrong local password consulted the directory %d times", f.calls)
	}

	session, _, err := a.Login(ctx, "ada", goodPassword, "10.0.0.1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.Via() != auth.MethodSession || session.Method != string(auth.MethodSession) {
		t.Errorf("local login method = %q (Via %q), want %q",
			session.Method, session.Via(), auth.MethodSession)
	}
	if f.calls != 0 {
		t.Errorf("a good local password consulted the directory %d times", f.calls)
	}
}

func TestAnUnknownNameFallsThroughToTheDirectory(t *testing.T) {
	f := &fakeVerifier{subject: "dirk", role: auth.RoleViewer}
	a, _, _ := newAuthWithVerifier(t, f)
	ctx := context.Background()

	session, cookie, err := a.Login(ctx, "dirk", "a-directory-password", "10.0.0.1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if f.calls != 1 {
		t.Fatalf("verifier consulted %d times, want 1", f.calls)
	}
	// Subject and role come from the verifier, and the session says how it
	// was established; that is what lets a later audit entry read via: ldap
	// rather than claiming a local login that never happened.
	if session.Subject != "dirk" || session.Role != auth.RoleViewer {
		t.Errorf("session = %+v, want the verifier's identity", session)
	}
	if session.Method != string(auth.MethodLDAP) || session.Via() != auth.MethodLDAP {
		t.Errorf("session method = %q (Via %q), want ldap", session.Method, session.Via())
	}

	// The cookie resolves like any other session's.
	resolved, err := a.Session(ctx, cookie)
	if err != nil || resolved.Via() != auth.MethodLDAP {
		t.Errorf("Session = %+v, %v: the method must survive the round trip", resolved, err)
	}
}

func TestANoRoleRefusalPropagatesAndPersistsNothing(t *testing.T) {
	f := &fakeVerifier{err: auth.ErrLDAPNoRole}
	a, st, _ := newAuthWithVerifier(t, f)
	ctx := context.Background()

	// Each refusal propagates typed, so the API can answer 403 rather than
	// 401: "ask an administrator", not "log in again".
	for i := range auth.DefaultLoginLimit.Attempts {
		if _, _, err := a.Login(ctx, "dirk", "a-password", "10.0.0.1"); !errors.Is(err, auth.ErrLDAPNoRole) {
			t.Fatalf("attempt %d = %v, want ErrLDAPNoRole", i, err)
		}
	}

	// It still spends a limiter slot: a group-mapping refusal is a guess too,
	// from the limiter's point of view.
	if _, _, err := a.Login(ctx, "dirk", "a-password", "10.0.0.1"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("attempt %d = %v, want ErrRateLimited", auth.DefaultLoginLimit.Attempts+1, err)
	}
	if f.calls != auth.DefaultLoginLimit.Attempts {
		t.Errorf("verifier consulted %d times, want %d: the limiter runs first",
			f.calls, auth.DefaultLoginLimit.Attempts)
	}

	// Memory-only, never a Store record: directory names are attacker-chosen
	// (the v1.37 rule), and each persisted one would ship to the replication
	// sink.
	if _, err := st.Get(ctx, store.KindKV, "auth/lockout/dirk"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a directory name earned a persisted lockout record: %v", err)
	}
}

func TestAnUnavailableDirectoryCountsAgainstNobody(t *testing.T) {
	// Counting an outage as failures would let a directory outage lock every
	// account out: the user did nothing wrong.
	f := &fakeVerifier{err: auth.ErrLDAPUnavailable}
	a, _, _ := newAuthWithVerifier(t, f)
	ctx := context.Background()

	for i := range 10 {
		_, _, err := a.Login(ctx, "dirk", "a-password", "10.0.0.1")
		if !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("attempt %d = %v, want ErrUnauthenticated", i, err)
		}
		// Refused uniformly: the caller must not learn the directory is down
		// from the login error.
		if errors.Is(err, auth.ErrLDAPUnavailable) {
			t.Fatalf("attempt %d leaks the outage: %v", i, err)
		}
	}

	// Ten failures did not touch the limiter: the directory comes back and the
	// eleventh attempt goes straight through.
	f.err, f.role = nil, auth.RoleViewer
	session, _, err := a.Login(ctx, "dirk", "a-password", "10.0.0.1")
	if err != nil {
		t.Fatalf("login after the outage = %v: outage attempts were counted", err)
	}
	if session.Subject != "dirk" || f.calls != 11 {
		t.Errorf("session = %+v after %d calls, want dirk after 11", session, f.calls)
	}
}

func TestANilVerifierKeepsLocalOnlyBehaviour(t *testing.T) {
	// Today's behaviour, bit for bit: an unknown name with no verifier is the
	// same generic refusal it always was, and nothing panics.
	a, _ := newAuth(t)
	ctx := context.Background()

	if _, _, err := a.Login(ctx, "dirk", "a-password", "10.0.0.1"); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("unknown name without a verifier = %v, want ErrUnauthenticated", err)
	}
}

func TestTheLimiterRunsBeforeTheVerifier(t *testing.T) {
	// A locked-out name must not cost a directory bind per guess: the limiter
	// answers first, so a brute force cannot be amplified into directory
	// traffic.
	f := &fakeVerifier{err: errors.New("the directory refused the password")}
	a, st, _ := newAuthWithVerifier(t, f)
	ctx := context.Background()

	for i := range auth.DefaultLoginLimit.Attempts {
		if _, _, err := a.Login(ctx, "dirk", "wrong", "10.0.0.1"); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("attempt %d = %v, want ErrUnauthenticated", i, err)
		}
	}
	// A generic directory refusal is memory-only too, like the no-role one.
	if _, err := st.Get(ctx, store.KindKV, "auth/lockout/dirk"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a directory refusal was persisted: %v", err)
	}

	// The directory would say yes now, and must not be asked.
	f.err, f.role = nil, auth.RoleAdmin
	if _, _, err := a.Login(ctx, "dirk", "right-this-time", "10.0.0.1"); !errors.Is(err, auth.ErrRateLimited) {
		t.Fatalf("locked-out login = %v, want ErrRateLimited", err)
	}
	if f.calls != auth.DefaultLoginLimit.Attempts {
		t.Errorf("verifier consulted %d times, want %d: the lockout did not shield it",
			f.calls, auth.DefaultLoginLimit.Attempts)
	}
}
