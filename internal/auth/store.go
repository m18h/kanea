package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/store"
)

// Key prefixes for auth records.
//
// They live in the KV bucket rather than a new one: the bucket set is fixed by
// PRD §5.2.3, and `audit` is for the audit trail — putting credentials there
// would mean a log reader was also reading password hashes.
const (
	userPrefix    = "auth/user/"
	tokenPrefix   = "auth/token/" // #nosec G101 — a key prefix, not a credential
	sessionPrefix = "auth/session/"
	lockoutPrefix = "auth/lockout/"
)

// authKind is the bucket auth records live in.
const authKind = store.KindKV

// Store persists users, tokens and sessions.
type Store struct {
	store store.Store
	log   *slog.Logger
	now   func() time.Time

	limiter *loginLimiter
}

// StoreConfig configures the auth store.
type StoreConfig struct {
	Store  store.Store
	Logger *slog.Logger
	Limit  LoginLimit
	Now    func() time.Time
}

// NewStore builds the auth store.
func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.Store == nil {
		return nil, errors.New("auth: a store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Limit.Attempts <= 0 {
		cfg.Limit = DefaultLoginLimit
	}
	return &Store{
		store:   cfg.Store,
		log:     cfg.Logger,
		now:     cfg.Now,
		limiter: newLoginLimiter(cfg.Limit, cfg.Now),
	}, nil
}

// ---- users ----

// PutUser creates or replaces a user from a plaintext password.
func (s *Store) PutUser(ctx context.Context, name, password string, role Role) error {
	if err := checkName(name); err != nil {
		return err
	}
	if !role.Valid() {
		return fmt.Errorf("auth: unknown role %q for %s", role, name)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	now := s.now()
	user := User{Name: name, PasswordHash: hash, Role: role, Created: now, Updated: now}
	if existing, err := s.User(ctx, name); err == nil {
		user.Created = existing.Created
		// Demoting the last admin is refused for the same reason deleting one
		// is: it is a one-way door, and the person walking through it is
		// usually not intending to.
		if existing.Role == RoleAdmin && role != RoleAdmin {
			if err := s.checkNotLastAdmin(ctx, name); err != nil {
				return err
			}
		}
	}

	mut, err := store.PutMutation(authKind, userPrefix+name, user)
	if err != nil {
		return err
	}
	if _, err := s.store.Apply(ctx, mut); err != nil {
		return fmt.Errorf("auth: write user %s: %w", name, err)
	}
	s.log.Info("user written", "user", name, "role", role)
	return nil
}

// User returns one account.
func (s *Store) User(ctx context.Context, name string) (User, error) {
	rec, err := s.store.Get(ctx, authKind, userPrefix+name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return User{}, fmt.Errorf("%w: user %s", ErrNotFound, name)
		}
		return User{}, err
	}
	return decode[User](rec.Value)
}

// Users lists every account, without password hashes.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	users, err := listPrefix[User](ctx, s.store, userPrefix)
	if err != nil {
		return nil, err
	}
	for i := range users {
		// Redacted even though this is an internal call: a hash that never
		// leaves the store cannot be leaked by a handler that forgets.
		users[i].PasswordHash = ""
	}
	return users, nil
}

// DeleteUser removes an account.
func (s *Store) DeleteUser(ctx context.Context, name string) error {
	user, err := s.User(ctx, name)
	if err != nil {
		return err
	}
	if user.Role == RoleAdmin {
		if err := s.checkNotLastAdmin(ctx, name); err != nil {
			return err
		}
	}
	_, err = s.store.Apply(ctx, store.DeleteMutation(authKind, userPrefix+name))
	return err
}

// checkNotLastAdmin refuses a change that would leave no admin account.
//
// Not a hard lock-out — the local unix socket is always admin (§13.1), so a
// node is recoverable — but a dashboard operator who removes their own account
// should be told, not silently locked out of the only interface they use.
func (s *Store) checkNotLastAdmin(ctx context.Context, name string) error {
	users, err := s.Users(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Role == RoleAdmin && u.Name != name {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is the only admin account", ErrLastAdmin, name)
}

// HasUsers reports whether any account exists.
//
// §13.1: a daemon with no auth configured binds locally and warns. This is how
// it knows which case it is in.
func (s *Store) HasUsers(ctx context.Context) (bool, error) {
	users, err := listPrefix[User](ctx, s.store, userPrefix)
	if err != nil {
		return false, err
	}
	return len(users) > 0, nil
}

// ---- tokens ----

// CreateToken mints a bearer token and returns its one-time secret.
func (s *Store) CreateToken(ctx context.Context, name string, role Role, expires time.Time) (Token, string, error) {
	token, presented, err := NewToken(name, role, expires, s.now())
	if err != nil {
		return Token{}, "", err
	}
	mut, err := store.PutMutation(authKind, tokenPrefix+token.ID, token)
	if err != nil {
		return Token{}, "", err
	}
	if _, err := s.store.Apply(ctx, mut); err != nil {
		return Token{}, "", fmt.Errorf("auth: write token: %w", err)
	}
	s.log.Info("token created", "token_id", token.ID, "name", name, "role", role)
	return token, presented, nil
}

// Tokens lists tokens, without hashes.
func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	tokens, err := listPrefix[Token](ctx, s.store, tokenPrefix)
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		tokens[i].Hash = ""
	}
	return tokens, nil
}

// RevokeToken deletes a token by id.
func (s *Store) RevokeToken(ctx context.Context, id string) error {
	if _, err := s.store.Get(ctx, authKind, tokenPrefix+id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: token %s", ErrNotFound, id)
		}
		return err
	}
	if _, err := s.store.Apply(ctx, store.DeleteMutation(authKind, tokenPrefix+id)); err != nil {
		return err
	}
	s.log.Info("token revoked", "token_id", id)
	return nil
}

// ---- sessions ----

// CreateSession issues a dashboard session.
func (s *Store) CreateSession(ctx context.Context, subject string, role Role) (Session, string, error) {
	session, cookie, err := NewSession(subject, role, s.now())
	if err != nil {
		return Session{}, "", err
	}
	mut, err := store.PutMutation(authKind, sessionPrefix+session.Hash, session)
	if err != nil {
		return Session{}, "", err
	}
	if _, err := s.store.Apply(ctx, mut); err != nil {
		return Session{}, "", fmt.Errorf("auth: write session: %w", err)
	}
	return session, cookie, nil
}

// Session resolves a cookie value.
func (s *Store) Session(ctx context.Context, cookieValue string) (Session, error) {
	rec, err := s.store.Get(ctx, authKind, sessionPrefix+SessionKey(cookieValue))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Session{}, ErrUnauthenticated
		}
		return Session{}, err
	}
	session, err := decode[Session](rec.Value)
	if err != nil {
		return Session{}, err
	}
	if session.Expired(s.now()) {
		// Removed on read rather than swept: an expired session is discovered
		// exactly when someone tries to use it, which is when it matters. A
		// failure to delete is not a failure to reject — the caller is refused
		// either way, and the sweep will pick it up.
		if err := s.DeleteSession(ctx, cookieValue); err != nil {
			s.log.Debug("cannot remove an expired session", "error", err)
		}
		return Session{}, ErrUnauthenticated
	}
	return session, nil
}

// DeleteSession revokes one session. This is what logout does, and it is why
// §13.3 calls for a server-side revocation list rather than a self-contained
// cookie that cannot be withdrawn.
func (s *Store) DeleteSession(ctx context.Context, cookieValue string) error {
	_, err := s.store.Apply(ctx,
		store.DeleteMutation(authKind, sessionPrefix+SessionKey(cookieValue)))
	return err
}

// SweepSessions removes expired sessions.
func (s *Store) SweepSessions(ctx context.Context) (int, error) {
	sessions, err := listPrefix[Session](ctx, s.store, sessionPrefix)
	if err != nil {
		return 0, err
	}
	now := s.now()
	var muts []store.Mutation
	for _, session := range sessions {
		if session.Expired(now) {
			muts = append(muts, store.DeleteMutation(authKind, sessionPrefix+session.Hash))
		}
	}
	if len(muts) == 0 {
		return 0, nil
	}
	if _, err := s.store.Apply(ctx, muts...); err != nil {
		return 0, err
	}
	return len(muts), nil
}

// ---- login ----

// Login verifies a password and issues a session.
//
// Failures are deliberately indistinguishable: an unknown user and a wrong
// password return the same error after the same amount of work, so neither the
// message nor the timing enumerates accounts (§14, A07).
func (s *Store) Login(ctx context.Context, name, password, source string) (Session, string, error) {
	if err := s.limiter.check(source, name); err != nil {
		return Session{}, "", err
	}

	user, err := s.User(ctx, name)
	if err != nil {
		EqualiseTiming(password)
		// The failure counts, but is never persisted for a name that is not an
		// account (v1.37): unknown names are attacker-chosen, and each would
		// become a Store record shipped to the replication sink. The in-memory
		// limiter still locks the name out; only the durability differs.
		s.limiter.fail(source, name)
		s.log.Warn("login failed", "user", name, "source", source, "reason", "no such user")
		return Session{}, "", ErrUnauthenticated
	}
	if !VerifyPassword(password, user.PasswordHash) {
		s.recordFailure(ctx, name, source)
		s.log.Warn("login failed", "user", name, "source", source, "reason", "bad password")
		return Session{}, "", ErrUnauthenticated
	}

	if s.limiter.succeed(source, name) {
		// The account had failure state, so a lockout record may be persisted
		// — a good login is the transition that retires it.
		if _, err := s.store.Apply(ctx, store.DeleteMutation(authKind, lockoutPrefix+name)); err != nil {
			s.log.Warn("cannot clear a persisted lockout", "user", name, "error", err)
		}
	}
	session, cookie, err := s.CreateSession(ctx, user.Name, user.Role)
	if err != nil {
		return Session{}, "", err
	}
	s.log.Info("login", "user", user.Name, "role", user.Role, "source", source)
	return session, cookie, nil
}

// lockoutRecord is a persisted account lockout (v1.37, §13.3).
//
// Only the locking transition is written — at most one write per account per
// lockout period, never one per failed attempt — and only for names that are
// real accounts, whose key space the operator bounded. Per-source lockouts
// stay memory-only deliberately: the source key space is attacker-chosen, and
// persisting it would convert a brute-force attempt into replication traffic.
type lockoutRecord struct {
	LockedTil time.Time `json:"locked_til"`
	Failures  int       `json:"failures"`
}

// recordFailure counts a failed login against an existing account and
// persists the lockout when this failure is the one that locked it.
func (s *Store) recordFailure(ctx context.Context, name, source string) {
	lockedTil, locked := s.limiter.fail(source, name)
	if !locked {
		return
	}
	rec := lockoutRecord{LockedTil: lockedTil, Failures: s.limiter.limit.Attempts}
	if _, err := store.PutValue(ctx, s.store, authKind, lockoutPrefix+name, rec); err != nil {
		// Best-effort: the in-memory lockout is authoritative for this
		// process; only its survival across a restart is at stake.
		s.log.Warn("cannot persist an account lockout", "user", name, "error", err)
	}
}

// LoadLockouts restores account lockouts persisted before a restart (v1.37).
//
// Before this, restarting the daemon cleared every active lockout — an
// attacker who could wait out (or provoke) a restart reset the §13.3
// brute-force defence. Records whose lockout has expired are reaped here,
// which bounds the prefix to the accounts currently locked.
func (s *Store) LoadLockouts(ctx context.Context) error {
	now := s.now()
	var stale []store.Mutation
	opts := store.ListOptions{Prefix: lockoutPrefix}
	for {
		page, err := s.store.List(ctx, authKind, opts)
		if err != nil {
			return fmt.Errorf("auth: list lockouts: %w", err)
		}
		for _, rec := range page.Records {
			account := strings.TrimPrefix(rec.Key, lockoutPrefix)
			var lock lockoutRecord
			if err := json.Unmarshal(rec.Value, &lock); err != nil || !now.Before(lock.LockedTil) {
				stale = append(stale, store.DeleteMutation(authKind, rec.Key))
				continue
			}
			s.limiter.seed(account, lock.LockedTil, lock.Failures)
			s.log.Warn("account lockout restored from before the restart",
				"user", account, "until", lock.LockedTil)
		}
		if !page.More {
			break
		}
		opts.After = page.NextAfter
	}
	if len(stale) > 0 {
		if _, err := s.store.Apply(ctx, stale...); err != nil {
			s.log.Warn("cannot reap expired lockout records", "count", len(stale), "error", err)
		}
	}
	return nil
}

// AuthenticateToken resolves a presented bearer token.
func (s *Store) AuthenticateToken(ctx context.Context, presented string) (Identity, error) {
	id, secret, ok := SplitToken(presented)
	if !ok {
		return Identity{}, ErrUnauthenticated
	}
	rec, err := s.store.Get(ctx, authKind, tokenPrefix+id)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	token, err := decode[Token](rec.Value)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	if !VerifySecret(secret, token.Hash) {
		s.log.Warn("token rejected", "token_id", id, "reason", "bad secret")
		return Identity{}, ErrUnauthenticated
	}
	if token.Expired(s.now()) {
		s.log.Warn("token rejected", "token_id", id, "reason", "expired")
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Subject: token.Name, Role: token.Role, Via: MethodToken, TokenID: token.ID}, nil
}

// ---- helpers ----

func checkName(name string) error {
	switch {
	case name == "":
		return errors.New("auth: a user needs a name")
	case len(name) > 64:
		return errors.New("auth: user name is too long")
	case strings.ContainsAny(name, "/ \t\r\n"):
		// The name is part of a Store key; a slash would make one user's record
		// look like another's namespace.
		return fmt.Errorf("auth: user name %q may not contain a slash or whitespace", name)
	}
	return nil
}

func decode[T any](body []byte) (T, error) {
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("auth: decode: %w", err)
	}
	return out, nil
}

func listPrefix[T any](ctx context.Context, s store.Store, prefix string) ([]T, error) {
	var out []T
	opts := store.ListOptions{Prefix: prefix}
	for {
		values, page, err := store.ListValues[T](ctx, s, authKind, opts)
		if err != nil {
			return nil, fmt.Errorf("auth: list %s: %w", prefix, err)
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// loginLimiter bounds failed logins per source and per account.
type loginLimiter struct {
	mu     sync.Mutex
	limit  LoginLimit
	now    func() time.Time
	counts map[string]*attemptState
}

type attemptState struct {
	failures  int
	first     time.Time
	lockedTil time.Time
}

func newLoginLimiter(limit LoginLimit, now func() time.Time) *loginLimiter {
	return &loginLimiter{limit: limit, now: now, counts: map[string]*attemptState{}}
}

// check refuses a login that is currently locked out.
func (l *loginLimiter) check(source, account string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	for _, key := range keysFor(source, account) {
		state, ok := l.counts[key]
		if ok && now.Before(state.lockedTil) {
			return ErrRateLimited
		}
	}
	return nil
}

// fail records a failure against both the source and the account.
//
// It reports whether this failure is the one that locked the *account* — the
// transition, which is the only thing the caller persists (v1.37).
func (l *loginLimiter) fail(source, account string) (lockedTil time.Time, lockedAccount bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	accountKey := "acct:" + account
	for _, key := range keysFor(source, account) {
		state, ok := l.counts[key]
		if !ok || now.Sub(state.first) > l.limit.Window {
			l.counts[key] = &attemptState{failures: 1, first: now}
			continue
		}
		state.failures++
		if state.failures >= l.limit.Attempts {
			wasLocked := now.Before(state.lockedTil)
			state.lockedTil = now.Add(l.limit.Lockout)
			if key == accountKey && !wasLocked {
				lockedTil, lockedAccount = state.lockedTil, true
			}
		}
	}
	l.prune(now)
	return lockedTil, lockedAccount
}

// succeed clears the counters after a good login, reporting whether the
// account had any failure state to clear.
func (l *loginLimiter) succeed(source, account string) (hadAccountState bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	accountKey := "acct:" + account
	for _, key := range keysFor(source, account) {
		if _, ok := l.counts[key]; ok && key == accountKey {
			hadAccountState = true
		}
		delete(l.counts, key)
	}
	return hadAccountState
}

// seed restores a persisted account lockout into the limiter (v1.37).
//
// first is stamped now rather than reconstructed: the original window closed
// with the process that watched it, and what matters — until when the account
// is refused — travels in lockedTil.
func (l *loginLimiter) seed(account string, til time.Time, failures int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts["acct:"+account] = &attemptState{failures: failures, first: l.now(), lockedTil: til}
}

// prune drops entries that can no longer matter. The caller holds the lock.
//
// Without it the map grows with every distinct source address, which is a set
// chosen by whoever is attacking — the same bound the edge's rate limiter needs.
func (l *loginLimiter) prune(now time.Time) {
	for key, state := range l.counts {
		stale := now.Sub(state.first) > l.limit.Window
		unlocked := state.lockedTil.IsZero() || now.After(state.lockedTil)
		if stale && unlocked {
			delete(l.counts, key)
		}
	}
}

func keysFor(source, account string) [2]string {
	return [2]string{"src:" + source, "acct:" + account}
}
