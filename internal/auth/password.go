package auth

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the work factor for password hashes.
//
// Deliberately above bcrypt's default of 10. A password hash is checked once
// per login, not once per request, so ~250 ms is invisible to a person and
// expensive for someone working through a leaked hash file.
const BcryptCost = 12

// MinPasswordLength is the shortest password accepted.
//
// Length is the only property enforced. Composition rules ("one digit, one
// symbol") push people toward predictable substitutions and are not what makes
// a password hard to guess; a longer minimum is.
const MinPasswordLength = 12

// ErrWeakPassword marks a password that is refused at creation.
var ErrWeakPassword = errors.New("auth: password is too weak")

// HashPassword produces a bcrypt hash for storage.
func HashPassword(plaintext string) (string, error) {
	if len([]rune(plaintext)) < MinPasswordLength {
		return "", fmt.Errorf("%w: use at least %d characters", ErrWeakPassword, MinPasswordLength)
	}
	// bcrypt silently truncates at 72 bytes, so a longer password would have
	// its tail ignored — someone using a passphrase would get less security
	// than they think, without being told.
	if len(plaintext) > 72 {
		return "", fmt.Errorf("%w: bcrypt ignores anything past 72 bytes; "+
			"this password is %d bytes", ErrWeakPassword, len(plaintext))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks a password against a stored hash.
//
// bcrypt's own comparison is constant-time with respect to the hash, which is
// what matters here.
func VerifyPassword(plaintext, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// dummyHash is compared against when a user does not exist.
//
// Without it, a login for an unknown user returns immediately while one for a
// known user spends ~250 ms in bcrypt — a timing difference that enumerates
// valid account names. Comparing against a real hash makes both paths cost the
// same (§14, A07).
var dummyHash = mustHash("kanea-timing-equaliser-not-a-real-password")

func mustHash(s string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(s), BcryptCost)
	if err != nil {
		panic("auth: cannot hash the timing equaliser: " + err.Error())
	}
	return string(h)
}

// EqualiseTiming performs the same work a real check would, for a user that
// does not exist.
func EqualiseTiming(plaintext string) {
	_ = VerifyPassword(plaintext, dummyHash)
}

// LoginLimit bounds failed logins (§14, A07).
//
// Per source *and* per account: per-source alone lets a botnet spread an attack
// across addresses, and per-account alone lets one address work through every
// account. Both, and the stricter wins.
type LoginLimit struct {
	// Attempts is how many failures are tolerated within Window.
	Attempts int
	Window   time.Duration
	// Lockout is how long a source or account is refused after exceeding it.
	Lockout time.Duration
}

// DefaultLoginLimit is §14 A07's "5/min/IP + exponential account backoff",
// expressed as a fixed lockout — simpler to reason about than an escalating
// one, and a minute of lockout already makes online guessing hopeless.
var DefaultLoginLimit = LoginLimit{Attempts: 5, Window: time.Minute, Lockout: time.Minute}
