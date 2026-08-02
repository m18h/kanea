// Package ratelimit is the bounded token-bucket limiter both public surfaces
// use: the edge's per-route `rate_limit` middleware (PRD §7.2.1) and the
// control API's global limits (§14, A07).
//
// It lives on its own because the hard part is not the token bucket — it is the
// bound on how many buckets exist, and getting that wrong the same way twice is
// how one of the two surfaces ends up with an OOM nobody tested for.
package ratelimit

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// DefaultCapacity bounds how many buckets a limiter holds.
//
// This is the whole design problem. A limit keyed by client address needs one
// bucket per address, and the set of addresses is chosen by whoever is sending
// traffic — so an unbounded map is a memory exhaustion vector reachable by
// anyone who can open connections. 64k buckets is well past any real audience
// on a single node and costs a few megabytes.
const DefaultCapacity = 1 << 16

// idleFactor decides when a bucket is stale: it is evictable once it has been
// untouched for this many windows. Two is enough for the bucket to have
// refilled completely, so dropping it loses nothing.
const idleFactor = 2

// Spec is a validated limit: Requests per Window, with an optional Burst on top.
//
// It carries no notion of what is being limited. The caller decides the key —
// an address, a route, a header value — and two callers with different ideas
// about that produce different keys rather than needing different limiters.
type Spec struct {
	Requests int
	Window   time.Duration
	// Burst is extra allowance above Requests, spendable at once.
	Burst int
}

// Valid reports whether a spec describes a usable limit.
func (s Spec) Valid() bool {
	return s.Requests > 0 && s.Window > 0 && s.Burst >= 0
}

// Rate returns tokens per second.
func (s Spec) Rate() float64 {
	return float64(s.Requests) / s.Window.Seconds()
}

// Capacity is the bucket size: the burst on top of the allowance if one was
// asked for, otherwise the full allowance, so a client may spend a whole
// window's budget at once.
func (s Spec) Capacity() float64 {
	if s.Burst > 0 {
		return float64(s.Requests + s.Burst)
	}
	return float64(s.Requests)
}

// Equal reports whether two specs describe the same limit. Used on reload to
// decide whether a bucket's accumulated state is still meaningful.
func (s Spec) Equal(other Spec) bool {
	return s.Requests == other.Requests && s.Window == other.Window && s.Burst == other.Burst
}

// Limiter is a bounded set of token buckets.
//
// Eviction is least-recently-used. That has a consequence worth being explicit
// about: a client that sprays enough distinct keys can push others out, and an
// evicted bucket starts full. It cannot be used to deny anyone — losing your
// bucket gives you *more* allowance, not less — and it cannot be driven by a
// forged address, because completing a TCP handshake requires the address to be
// real. The alternative, an unbounded map, trades that for an OOM.
type Limiter struct {
	mu       sync.Mutex
	capacity int
	now      func() time.Time

	buckets map[string]*list.Element
	// order is most-recently-used at the front.
	order *list.List
}

// bucket is one subject's allowance.
type bucket struct {
	key string
	// spec is the limit this bucket was filled under. A route whose rate limit
	// changed gets a fresh bucket rather than a stale count measured against a
	// different rule.
	spec   Spec
	tokens float64
	last   time.Time
}

// New builds a limiter. A capacity of zero means DefaultCapacity, and a nil
// clock means time.Now.
func New(capacity int, now func() time.Time) *Limiter {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		capacity: capacity,
		now:      now,
		buckets:  make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Allow spends one token for key under spec, and reports whether the request
// may proceed. When it may not, the second return is how long until it could.
func (l *Limiter) Allow(key string, spec Spec) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.bucketFor(key, spec, now)

	// Refill for the time that passed, capped at the bucket size: an idle
	// client accumulates a burst, not an unbounded credit.
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens = math.Min(spec.Capacity(), b.tokens+elapsed.Seconds()*spec.Rate())
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	// Round up: a Retry-After that is a fraction of a second short sends a
	// well-behaved client straight back into a refusal.
	wait := time.Duration(math.Ceil((1-b.tokens)/spec.Rate()*float64(time.Second)/float64(time.Millisecond))) *
		time.Millisecond
	return false, wait
}

// bucketFor returns the bucket for key, creating or resetting it as needed.
// The caller holds the lock.
func (l *Limiter) bucketFor(key string, spec Spec, now time.Time) *bucket {
	if elem, ok := l.buckets[key]; ok {
		l.order.MoveToFront(elem)
		b, _ := elem.Value.(*bucket)
		if b.spec.Equal(spec) {
			return b
		}
		// The limit was changed by a reload. Counting against the old rule
		// would be arbitrary, so start again under the new one.
		b.spec = spec
		b.tokens = spec.Capacity()
		b.last = now
		return b
	}

	l.evictIfFull()

	b := &bucket{key: key, spec: spec, tokens: spec.Capacity(), last: now}
	l.buckets[key] = l.order.PushFront(b)
	return b
}

// evictIfFull makes room for one more bucket. The caller holds the lock.
func (l *Limiter) evictIfFull() {
	if len(l.buckets) < l.capacity {
		return
	}
	// Drop the least recently used. Anything idle for two windows has refilled
	// completely, so this is usually free; past that it is a real eviction, and
	// the cap is the point.
	for len(l.buckets) >= l.capacity {
		oldest := l.order.Back()
		if oldest == nil {
			return
		}
		b, _ := oldest.Value.(*bucket)
		l.order.Remove(oldest)
		delete(l.buckets, b.key)
	}
}

// Sweep drops buckets that have been idle long enough to have refilled. It is
// what keeps a quiet node's memory flat instead of at the high-water mark.
func (l *Limiter) Sweep() int {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	var dropped int
	for elem := l.order.Back(); elem != nil; {
		prev := elem.Prev()
		b, _ := elem.Value.(*bucket)
		if now.Sub(b.last) < time.Duration(idleFactor)*b.spec.Window {
			// The list is in use order, so the first live entry from the back
			// means everything ahead of it is live too.
			break
		}
		l.order.Remove(elem)
		delete(l.buckets, b.key)
		dropped++
		elem = prev
	}
	return dropped
}

// Len reports the number of tracked buckets.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
