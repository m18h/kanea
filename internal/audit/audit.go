// Package audit is the append-only record of who did what (PRD §14, A09).
//
// Three properties define it, and each is a deliberate contrast with the
// workload log pipeline of §17:
//
//   - It is **state, not telemetry**. Entries go through the Store, in the
//     `audit` bucket, and a write that fails is reported rather than dropped.
//     §17's drains drop under pressure because a stalled log must never stall a
//     workload; an audit entry that vanishes under load is exactly the entry an
//     attacker wants to vanish, so this path blocks instead.
//   - It is **append-only**. Nothing here updates an entry. The only removal is
//     retention pruning from the oldest end, which is a policy an operator sets
//     rather than something a caller can aim at a specific record.
//   - It is **chained**. Every entry carries the hash of the one before it, so
//     removing or editing one breaks every entry after it. That is what makes
//     the signed periodic export of §14 A09 worth anything: signing the head of
//     a chain attests to the whole history, not just to one row.
//
// Credentials never reach here. Redact runs over every free-text field on the
// way in, and the struct has no field that would carry a password or a token
// secret in the first place (§14, A07).
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/store"
)

// auditKind is the bucket audit entries live in (PRD §5.2.3).
const auditKind = store.KindAudit

// Result is the outcome of an audited action.
type Result string

// Outcomes. Denied is separated from Error because they answer different
// questions: one is "someone tried something they may not do", the other is
// "the platform failed". Collapsing them hides the first inside the noise of
// the second.
const (
	ResultOK      Result = "ok"
	ResultDenied  Result = "denied"
	ResultError   Result = "error"
	ResultAttempt Result = "attempt"
)

// Entry is one audited action.
//
// Everything is a plain scalar: an audit trail is read under pressure, often by
// someone who did not write the code, and a nested payload is one more thing to
// misread. Fields that could carry a credential do not exist.
type Entry struct {
	// ID is the entry's key: time-ordered, so key order is chronological order.
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	// Actor is the authenticated subject, or "" for an action nobody was
	// authenticated for — which is itself worth recording.
	Actor string `json:"actor,omitempty"`
	Role  string `json:"role,omitempty"`
	// Via is how the actor authenticated (session, token, socket).
	Via string `json:"via,omitempty"`
	// TokenID names the specific credential, so a token found in an audit trail
	// can be revoked without guessing which one it was.
	TokenID string `json:"token_id,omitempty"`
	// Action is what was attempted, in dotted form: service.apply, auth.login,
	// secret.put. Stable strings, because someone will grep for them.
	Action string `json:"action"`
	// Target is what it was attempted on: a service key, a secret path, a user.
	Target string `json:"target,omitempty"`
	Result Result `json:"result"`
	// Status is the HTTP status the caller saw, when the action came in over the
	// API. Zero for actions that did not.
	Status int `json:"status,omitempty"`
	// Source is where the request came from.
	Source string `json:"source,omitempty"`
	// Detail is free text for what the other fields cannot say. Redacted.
	Detail string `json:"detail,omitempty"`
	// Prev is the chain hash of the preceding entry, and Hash is this entry's.
	// Together they make the log tamper-evident: see Verify.
	Prev string `json:"prev,omitempty"`
	Hash string `json:"hash"`
}

// Filter selects entries for a listing.
type Filter struct {
	// Since and Until bound the window. Zero means unbounded on that side.
	Since time.Time
	Until time.Time
	// Actor, Action and Result narrow the result set. Empty means any.
	//
	// They are applied after the key range because none of them is part of the
	// key: an audit bucket is written far more often than it is queried, and a
	// key that encoded the actor would page badly for every other question.
	Actor  string
	Action string
	Result Result
	// After resumes a previous page. Use Page.NextAfter.
	After string
	// Limit caps the page. Zero means store.DefaultListLimit.
	Limit int
	// Oldest walks forward in time. The default is newest-first, because that is
	// the question a dashboard and an incident both start with.
	Oldest bool
}

// Page is one bounded slice of the log.
type Page struct {
	Entries []Entry `json:"entries"`
	// NextAfter feeds the next call's Filter.After; empty at the end.
	NextAfter string `json:"next_after,omitempty"`
	More      bool   `json:"more"`
}

// Config configures a Log.
type Config struct {
	Store  store.Store
	Logger *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
}

// Log is the audit trail.
type Log struct {
	store store.Store
	log   *slog.Logger
	now   func() time.Time

	// mu serializes appends so the chain has one well-defined order. The Store
	// is single-writer anyway; this makes the hash chain agree with it.
	mu   sync.Mutex
	head string
	last string
}

// Open loads the chain head and returns a usable log.
func Open(ctx context.Context, cfg Config) (*Log, error) {
	if cfg.Store == nil {
		return nil, errors.New("audit: a store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	l := &Log{store: cfg.Store, log: cfg.Logger, now: cfg.Now}

	// The chain continues across restarts, so the head is read back rather than
	// restarted at zero — otherwise every restart would look like a break.
	page, err := l.List(ctx, Filter{Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(page.Entries) == 1 {
		l.head = page.Entries[0].Hash
		l.last = page.Entries[0].ID
	}
	return l, nil
}

// Record appends one entry.
//
// It returns an error rather than swallowing one, so a caller can decide what an
// unrecordable action means. The api package records after the handler has run,
// because the outcome is half of what makes an entry worth keeping; a failure
// there is logged at error level and counted (api.AuditFailures) rather than
// hidden. Closing that window properly means writing the entry in the same
// Store batch as the mutation it describes, which is what a Store-level audited
// apply would give and is the shape to grow into.
func (l *Log) Record(ctx context.Context, e Entry) (Entry, error) {
	if e.Action == "" {
		return Entry{}, errors.New("audit: an entry needs an action")
	}
	if e.Result == "" {
		e.Result = ResultOK
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = l.now()
	}
	id, err := l.nextID(e.Time)
	if err != nil {
		return Entry{}, err
	}
	e.ID = id
	e.Actor = Redact(e.Actor)
	e.Target = Redact(e.Target)
	e.Detail = Redact(e.Detail)
	e.Prev = l.head
	e.Hash = chainHash(e)

	mut, err := store.PutMutation(auditKind, e.ID, e)
	if err != nil {
		return Entry{}, err
	}
	if _, err := l.store.Apply(ctx, mut); err != nil {
		return Entry{}, fmt.Errorf("audit: append %s: %w", e.Action, err)
	}
	l.head, l.last = e.Hash, e.ID
	return e, nil
}

// List returns a bounded page, newest first unless Filter.Oldest is set.
func (l *Log) List(ctx context.Context, f Filter) (Page, error) {
	limit := f.limitOr()
	opts := store.ListOptions{
		Limit:   limit,
		After:   f.After,
		Reverse: !f.Oldest,
	}
	// The key is the timestamp, so a time window is a key range and costs
	// nothing to apply — unlike the field filters below, which have to decode.
	if opts.After == "" {
		switch {
		case f.Oldest && !f.Since.IsZero():
			opts.After = boundKey(f.Since, below)
		case !f.Oldest && !f.Until.IsZero():
			opts.After = boundKey(f.Until, above)
		}
	}

	page := Page{Entries: []Entry{}}
	for {
		entries, sp, err := store.ListValues[Entry](ctx, l.store, auditKind, opts)
		if err != nil {
			return Page{}, fmt.Errorf("audit: list: %w", err)
		}
		stop := false
		for i, e := range entries {
			// Past the far edge of the window there is nothing left to find:
			// keys are time-ordered, so this ends the scan rather than skipping.
			if !f.Oldest && !f.Since.IsZero() && e.Time.Before(f.Since) {
				stop = true
				break
			}
			if f.Oldest && !f.Until.IsZero() && e.Time.After(f.Until) {
				stop = true
				break
			}
			if !f.matches(e) {
				continue
			}
			page.Entries = append(page.Entries, e)
			page.NextAfter = e.ID
			if len(page.Entries) == limit {
				// "More" is the Store's meaning: another page *may* exist. A
				// filter that rejects everything left would make it a false
				// positive, and one wasted request is cheaper than a scan that
				// decodes the rest of the log to find out.
				page.More = i < len(entries)-1 || sp.More
				return page, nil
			}
		}
		// A page of records that all failed the field filters is not the end of
		// the log; keep paging so a narrow filter does not return an empty page
		// while matching entries sit one page further in.
		if stop || !sp.More {
			page.NextAfter, page.More = "", false
			return page, nil
		}
		opts.After = sp.NextAfter
	}
}

// Prune drops entries older than a cut-off, oldest first, and reports how many
// it removed.
//
// This is the one deletion the log allows, and it is deliberately shaped so it
// cannot be aimed: a caller names a time, never an entry. Pruning does break the
// chain at the cut — that is unavoidable, and it is why an export is signed
// before its window is pruned rather than after.
func (l *Log) Prune(ctx context.Context, before time.Time) (int, error) {
	pruned := 0
	for {
		page, err := l.store.List(ctx, auditKind, store.ListOptions{
			Limit: pruneBatch, KeysOnly: true,
		})
		if err != nil {
			return pruned, fmt.Errorf("audit: prune: %w", err)
		}

		var muts []store.Mutation
		for _, rec := range page.Records {
			// Keys are time-ordered, so the first key at or after the cut-off
			// ends the sweep.
			at, err := timeFromID(rec.Key)
			if err != nil || !at.Before(before) {
				break
			}
			muts = append(muts, store.DeleteMutation(auditKind, rec.Key))
		}
		if len(muts) == 0 {
			return pruned, nil
		}
		if _, err := l.store.Apply(ctx, muts...); err != nil {
			return pruned, fmt.Errorf("audit: prune: %w", err)
		}
		pruned += len(muts)
		if len(muts) < len(page.Records) {
			return pruned, nil
		}
	}
}

// pruneBatch bounds one prune transaction. Retention on a busy node can cover
// millions of entries, and one Apply of that size would hold the single writer
// for the duration (AGENTS.md #2).
const pruneBatch = 500

// Verify walks the chain from the oldest retained entry and reports the first
// entry whose hash does not follow from its predecessor.
//
// A break means one of three things: an entry was edited, an entry was removed,
// or a prune cut the chain at that point. The first two are what this exists to
// catch; the third is why the boundary entry is named rather than the whole log
// being called invalid.
func (l *Log) Verify(ctx context.Context) (broken *Entry, checked int, err error) {
	opts := store.ListOptions{}
	prev := ""
	first := true
	for {
		entries, page, err := store.ListValues[Entry](ctx, l.store, auditKind, opts)
		if err != nil {
			return nil, checked, fmt.Errorf("audit: verify: %w", err)
		}
		for _, e := range entries {
			checked++
			// The oldest retained entry is allowed to point at a predecessor
			// that pruning removed; every later one must match what we just saw.
			if !first && e.Prev != prev {
				return &e, checked, nil
			}
			if e.Hash != chainHash(e) {
				return &e, checked, nil
			}
			prev, first = e.Hash, false
		}
		if !page.More {
			return nil, checked, nil
		}
		opts.After = page.NextAfter
	}
}

// ---- helpers ----

func (f Filter) matches(e Entry) bool {
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	// Prefix rather than equality so "service." selects every service action,
	// which is how someone actually asks this question.
	if f.Action != "" && !strings.HasPrefix(e.Action, f.Action) {
		return false
	}
	if f.Result != "" && e.Result != f.Result {
		return false
	}
	return true
}

func (f Filter) limitOr() int {
	if f.Limit <= 0 {
		return store.DefaultListLimit
	}
	if f.Limit > store.MaxListLimit {
		return store.MaxListLimit
	}
	return f.Limit
}

// nextID allocates the key for an entry. The caller holds the lock.
//
// Keys are the timestamp in fixed-width nanoseconds plus a random suffix, so
// key order is time order and two entries in the same nanosecond still get
// distinct keys. A clock that steps backwards would otherwise write an entry
// that sorts before its own predecessor and reads as a gap; nudging past the
// last key keeps the ordering intact and leaves the real timestamp in Time,
// where the discrepancy is visible rather than papered over.
func (l *Log) nextID(at time.Time) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("audit: random: %w", err)
	}
	id := fmt.Sprintf("%020d-%s", at.UTC().UnixNano(), hex.EncodeToString(suffix))
	if l.last != "" && id <= l.last {
		bumped, err := idAfter(l.last)
		if err != nil {
			return "", err
		}
		id = bumped + "-" + hex.EncodeToString(suffix)
	}
	return id, nil
}

// idAfter returns the fixed-width nanosecond field one tick past a key's.
func idAfter(id string) (string, error) {
	at, err := timeFromID(id)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%020d", at.UnixNano()+1), nil
}

// bound is where a boundary key sits relative to the instant it bounds.
type bound int

const (
	below bound = iota
	above
)

// boundKey is the cursor that starts a scan at a time boundary.
//
// The Store's After is exclusive in both directions, so the key is placed one
// tick outside the instant asked for — below it for a forward scan, above it
// for a reverse one. Both windows then include an entry stamped exactly at the
// boundary, which is what "since 09:00" means to the person asking.
func boundKey(at time.Time, side bound) string {
	nanos := at.UTC().UnixNano()
	if side == above {
		nanos++
	} else {
		nanos--
	}
	// The suffix is the highest a real key can carry, so the boundary key sorts
	// past every entry written in its own nanosecond.
	return fmt.Sprintf("%020d-ffffffff", nanos)
}

func timeFromID(id string) (time.Time, error) {
	field, _, ok := strings.Cut(id, "-")
	if !ok {
		return time.Time{}, fmt.Errorf("audit: malformed entry id %q", id)
	}
	var nanos int64
	if _, err := fmt.Sscanf(field, "%d", &nanos); err != nil {
		return time.Time{}, fmt.Errorf("audit: malformed entry id %q: %w", id, err)
	}
	return time.Unix(0, nanos).UTC(), nil
}

// chainHash is the entry's hash over its content and its predecessor's hash.
//
// It covers every field except Hash itself, in a fixed order — a hash over a
// JSON encoding would depend on Go's field ordering staying put, which is not a
// property to bet tamper evidence on.
func chainHash(e Entry) string {
	var buf []byte
	for _, field := range []string{
		e.Prev, e.ID, e.Time.UTC().Format(time.RFC3339Nano), e.Actor, e.Role,
		e.Via, e.TokenID, e.Action, e.Target, string(e.Result),
		fmt.Sprint(e.Status), e.Source, e.Detail,
	} {
		// Length-prefixed so ("ab","c") and ("a","bc") do not hash alike — the
		// difference between two adjacent fields is exactly what an edit moves.
		buf = append(buf, fmt.Sprintf("%d:%s\n", len(field), field)...)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}
