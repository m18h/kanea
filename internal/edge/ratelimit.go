package edge

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// DefaultLimiterCapacity bounds how many rate-limit buckets the edge holds.
//
// This is the whole design problem. A limit keyed by client address needs one
// bucket per address, and the set of addresses is chosen by whoever is sending
// traffic — so an unbounded map is a memory exhaustion vector reachable by
// anyone who can open connections. 64k buckets is well past any real audience
// on a single node and costs a few megabytes.
const DefaultLimiterCapacity = 1 << 16

// idleFactor decides when a bucket is stale: it is evictable once it has been
// untouched for this many windows. Two is enough for the bucket to have
// refilled completely, so dropping it loses nothing.
const idleFactor = 2

// limiter is a bounded set of token buckets.
//
// Eviction is least-recently-used. That has a consequence worth being explicit
// about: a client that sprays enough distinct keys can push others out, and an
// evicted bucket starts full. It cannot be used to deny anyone — losing your
// bucket gives you *more* allowance, not less — and it cannot be driven by a
// forged address, because completing a TCP handshake requires the address to be
// real. The alternative, an unbounded map, trades that for an OOM.
type limiter struct {
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
	spec   rateSpec
	tokens float64
	last   time.Time
}

func newLimiter(capacity int, now func() time.Time) *limiter {
	if capacity <= 0 {
		capacity = DefaultLimiterCapacity
	}
	if now == nil {
		now = time.Now
	}
	return &limiter{
		capacity: capacity,
		now:      now,
		buckets:  make(map[string]*list.Element),
		order:    list.New(),
	}
}

// allow spends one token for key under spec, and reports whether the request
// may proceed. When it may not, the second return is how long until it could.
func (l *limiter) allow(key string, spec rateSpec) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.bucketFor(key, spec, now)

	// Refill for the time that passed, capped at the bucket size: an idle
	// client accumulates a burst, not an unbounded credit.
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens = math.Min(spec.capacity(), b.tokens+elapsed.Seconds()*spec.rate())
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	// Round up: a Retry-After that is a fraction of a second short sends a
	// well-behaved client straight back into a refusal.
	wait := time.Duration(math.Ceil((1-b.tokens)/spec.rate()*float64(time.Second)/float64(time.Millisecond))) *
		time.Millisecond
	return false, wait
}

// bucketFor returns the bucket for key, creating or resetting it as needed.
// The caller holds the lock.
func (l *limiter) bucketFor(key string, spec rateSpec, now time.Time) *bucket {
	if elem, ok := l.buckets[key]; ok {
		l.order.MoveToFront(elem)
		b, _ := elem.Value.(*bucket)
		if b.spec.equal(spec) {
			return b
		}
		// The limit was changed by a reload. Counting against the old rule
		// would be arbitrary, so start again under the new one.
		b.spec = spec
		b.tokens = spec.capacity()
		b.last = now
		return b
	}

	l.evictIfFull(now)

	b := &bucket{key: key, spec: spec, tokens: spec.capacity(), last: now}
	l.buckets[key] = l.order.PushFront(b)
	return b
}

// evictIfFull makes room for one more bucket. The caller holds the lock.
func (l *limiter) evictIfFull(now time.Time) {
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
	_ = now
}

// sweep drops buckets that have been idle long enough to have refilled. It is
// what keeps a quiet node's memory flat instead of at the high-water mark.
func (l *limiter) sweep() int {
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

// len reports the number of tracked buckets.
func (l *limiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
