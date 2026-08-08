package api

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/m18h/kanea/internal/ratelimit"
)

// Default request limits, per source address (PRD §5.2.1, §14 A07).
//
// Two tiers, because the two kinds of request cost different things and are
// reached by different people. An unauthenticated request is one anybody on the
// network can make, and the expensive one among them — login — spends ~250 ms
// in bcrypt by design; that is a denial-of-service lever if it is not bounded
// well below what an authenticated operator needs. A request that already
// carries a valid credential is bounded generously: the limit there exists to
// catch a runaway client, not to ration normal use.
var (
	// DefaultPublicLimit applies to health and login — the two routes reachable
	// without a credential. The per-account and per-source lockout on failed
	// logins (§13.3) sits behind this and is much stricter; this is the coarse
	// guard in front of it.
	DefaultPublicLimit = ratelimit.Spec{Requests: 30, Window: time.Minute, Burst: 10}
	// DefaultAuthenticatedLimit applies to everything else.
	DefaultAuthenticatedLimit = ratelimit.Spec{Requests: 600, Window: time.Minute, Burst: 100}
)

// limiterSweepInterval is how often idle buckets are dropped. Unhurried: the
// capacity bound is the safety property, and the sweep is only housekeeping so
// a node that saw a spike does not hold the high-water mark forever.
const limiterSweepInterval = time.Minute

// checkRateLimit spends one token for this request, or refuses it.
//
// It runs before authentication, which is the only order that helps: deciding
// whether to admit a request after paying for the bcrypt it asked for is not a
// rate limit, it is an accounting exercise.
//
// Unix-socket callers are exempt. They are the local root of §13.1 — already
// able to stop the daemon outright — and they share one meaningless source
// address, so a limit there would only make `kanea ps` in a loop throttle the
// reconciler's own CLI.
func (s *Server) checkRateLimit(w http.ResponseWriter, r *http.Request, p policy) bool {
	if s.limiter == nil || isLocalConn(r.Context()) {
		return true
	}

	// The tier is part of the key: a flood of anonymous requests must not spend
	// the allowance of an authenticated caller from the same address, and an
	// authenticated caller must not be able to lift the public limit by making
	// authenticated requests first.
	spec, tier := s.authLimit, "api:"
	if p.public {
		spec, tier = s.publicLimit, "pub:"
	}
	if !spec.Valid() {
		return true
	}

	ok, retry := s.limiter.Allow(tier+sourceOf(r), spec)
	if ok {
		return true
	}

	rateLimited.Add(1)
	// Debug, not warn: a refusal happens once per excess request, and a flood
	// logged at warn is a second denial-of-service against the log pipeline.
	// The counter is what makes the condition observable.
	s.log.Debug("request rate limited",
		"source", sourceOf(r), "action", p.action, "retry_after", retry)

	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Round(time.Second).Seconds())))
	writeError(w, http.StatusTooManyRequests, errRateLimited)
	return false
}

// sweepLimiter drops idle buckets until the context ends.
func (s *Server) sweepLimiter(done <-chan struct{}) {
	if s.limiter == nil {
		return
	}
	ticker := time.NewTicker(limiterSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if dropped := s.limiter.Sweep(); dropped > 0 {
				s.log.Debug("swept idle rate-limit buckets", "buckets", dropped)
			}
		}
	}
}

// rateLimited counts refused requests, so the condition is observable without
// reading a log that deliberately does not shout about it.
var rateLimited atomic.Int64

// RateLimited reports how many requests have been refused by the rate limiter.
func RateLimited() int64 { return rateLimited.Load() }
