package auth

// Internal tests for the login limiter's bounds (K-14): capacity eviction and
// key hashing are limiter internals, so they are tested where they live.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTheLoginLimiterIsBounded(t *testing.T) {
	now := time.Now()
	l := newLoginLimiter(LoginLimit{Attempts: 5, Window: time.Minute, Lockout: 5 * time.Minute}, func() time.Time { return now })
	l.capacity = 4

	// Lock one account for real, then fill the table with throwaway sources.
	for i := 0; i < 5; i++ {
		l.fail("10.0.0.1", "root")
	}
	for i := 0; i < 20; i++ {
		l.fail(strings.Repeat("a", 8)+string(rune('A'+i)), "nobody")
	}

	if got := len(l.counts); got > 4 {
		t.Fatalf("entries = %d, want capped at 4", got)
	}
	// The locked account survived the flood: eviction takes unlocked entries
	// first, because a capacity attack must not be the way to clear a lockout.
	if _, ok := l.peek(accountKeyFor("root")); !ok {
		t.Error("the locked account's entry was evicted by the flood")
	}
	if err := l.check("10.9.9.9", "root"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("check after the flood = %v, want the lockout still in force", err)
	}
}

// The account half of a key is hashed: an attacker-chosen 4 KiB name enters
// the map as a fixed-length digest, so a login flood is not memory growth.
func TestTheAccountKeyIsHashed(t *testing.T) {
	key := accountKeyFor(strings.Repeat("x", 4096))
	if len(key) > 80 {
		t.Errorf("key length = %d, want a digest, not the input", len(key))
	}
	if key == accountKeyFor("root") {
		t.Error("distinct names collided")
	}
}
