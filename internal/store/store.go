// Package store defines the Store interface and its bbolt implementation.
// All state mutations go through Store with monotonic indexes (Raft-FSM-
// compatible, PRD §18). Metrics and logs NEVER touch the Store. Read
// transactions must be bounded/paginated — bbolt is single-writer.
// (PRD §5.2.3, §15.2.)
//
// The interface is deliberately narrow and byte-oriented: one atomic Apply for
// every mutation, plus bounded reads. That shape is what makes a Raft-backed
// implementation a drop-in later (PRD §5.2.3) — an Apply batch is exactly an
// FSM command — and what makes Store-level CDC possible at all: bbolt has no
// WAL, so replication ships the change records emitted here (PRD §15.3).
//
// Callers work with typed values through the generic helpers in codec.go
// rather than handling bytes themselves.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Kind names a bucket. The set is fixed by PRD §5.2.3; unknown kinds are
// rejected at the boundary rather than silently creating buckets, so a typo
// cannot quietly fork the schema.
type Kind string

// The buckets fixed by PRD §5.2.3.
const (
	KindProject  Kind = "projects"
	KindService  Kind = "services"
	KindAlloc    Kind = "allocs"
	KindEvent    Kind = "events"
	KindCert     Kind = "certs"
	KindSecret   Kind = "secrets"
	KindPipeline Kind = "pipelines"
	KindAudit    Kind = "audit"
	KindKV       Kind = "kv"
)

// Kinds lists every valid bucket, in PRD order.
func Kinds() []Kind {
	return []Kind{
		KindProject, KindService, KindAlloc, KindEvent,
		KindCert, KindSecret, KindPipeline, KindAudit, KindKV,
	}
}

func (k Kind) valid() bool {
	for _, known := range Kinds() {
		if k == known {
			return true
		}
	}
	return false
}

// Op is the kind of a mutation.
type Op uint8

// Mutation kinds. The zero value is deliberately invalid so a half-built
// Mutation is rejected rather than silently treated as a put.
const (
	// OpPut writes (or overwrites) a record.
	OpPut Op = iota + 1
	// OpDelete removes a record; deleting a missing key is a no-op.
	OpDelete
)

func (o Op) String() string {
	switch o {
	case OpPut:
		return "put"
	case OpDelete:
		return "delete"
	default:
		return fmt.Sprintf("op(%d)", uint8(o))
	}
}

// Errors callers are expected to branch on.
var (
	// ErrNotFound is returned by Get for a missing key.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a mutation's precondition fails: another
	// writer changed the record first. Callers re-read and retry.
	ErrConflict = errors.New("store: conflict")
	// ErrInvalid marks a malformed request (unknown kind, empty key, ...).
	ErrInvalid = errors.New("store: invalid request")
	// ErrClosed is returned once the store is closed.
	ErrClosed = errors.New("store: closed")
)

// Record is a stored object plus the index of the mutation that produced it.
// Value is owned by the caller: implementations return copies, never slices
// into a live bbolt page (which is only valid inside its transaction).
type Record struct {
	Kind  Kind
	Key   string
	Index uint64
	Value []byte
}

// Mutation is one write in an Apply batch.
//
// Preconditions make optimistic concurrency explicit; the reconciler needs it
// to avoid clobbering a concurrent API write:
//
//	PrevIndex > 0        — the record must currently be at exactly that index
//	ExpectAbsent == true — the record must not exist (create-only)
//
// Both unset means an unconditional upsert.
type Mutation struct {
	Op           Op
	Kind         Kind
	Key          string
	Value        []byte
	PrevIndex    uint64
	ExpectAbsent bool
}

func (m Mutation) validate() error {
	if !m.Kind.valid() {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalid, m.Kind)
	}
	if m.Key == "" {
		return fmt.Errorf("%w: empty key in %s %s", ErrInvalid, m.Op, m.Kind)
	}
	if m.Op != OpPut && m.Op != OpDelete {
		return fmt.Errorf("%w: bad op %d", ErrInvalid, m.Op)
	}
	if m.PrevIndex > 0 && m.ExpectAbsent {
		return fmt.Errorf("%w: PrevIndex and ExpectAbsent are mutually exclusive", ErrInvalid)
	}
	return nil
}

// Change is one CDC record. The replicator (PRD §15.3) ships these as segments;
// every mutation produces exactly one, and Index is the same monotonic value
// stamped on the record.
type Change struct {
	Index uint64
	Op    Op
	Kind  Kind
	Key   string
	// Value is the written payload for OpPut, nil for OpDelete.
	Value []byte
	Time  time.Time
}

// ListOptions bounds a read. Reads are always paginated: bbolt holds a read
// transaction open for the duration, and a long one pins pages against the
// single writer (AGENTS.md constraint #2).
type ListOptions struct {
	// Prefix restricts the scan to keys with this prefix.
	Prefix string
	// After resumes after this key (exclusive). Use Page.NextAfter.
	After string
	// Limit caps returned records. Zero means DefaultListLimit; values above
	// MaxListLimit are clamped rather than rejected.
	Limit int
	// KeysOnly omits values — cheap existence scans and key enumeration.
	KeysOnly bool
}

// Pagination bounds. A caller that asks for more than MaxListLimit is clamped,
// not rejected: the point is to keep read transactions short (AGENTS.md #2).
const (
	// DefaultListLimit applies when ListOptions.Limit is unset.
	DefaultListLimit = 100
	// MaxListLimit caps any single page.
	MaxListLimit = 1000
)

func (o ListOptions) limit() int {
	switch {
	case o.Limit <= 0:
		return DefaultListLimit
	case o.Limit > MaxListLimit:
		return MaxListLimit
	default:
		return o.Limit
	}
}

// Page is one bounded slice of a listing.
type Page struct {
	Records []Record
	// NextAfter feeds the next call's ListOptions.After. Empty when the scan
	// reached the end.
	NextAfter string
	// More reports whether another page may exist.
	More bool
}

// Store is the single door to platform state.
//
// Implementations serialize writes; Apply is atomic across its whole batch and
// allocates exactly one index for it, so a multi-record change (service + its
// allocs) replicates and replays as a unit.
type Store interface {
	// Get returns one record, or ErrNotFound.
	Get(ctx context.Context, kind Kind, key string) (Record, error)
	// List returns a bounded page of records in key order.
	List(ctx context.Context, kind Kind, opts ListOptions) (Page, error)
	// Apply commits a batch atomically and returns the index it was stamped
	// with. An empty batch is a no-op returning the current index.
	Apply(ctx context.Context, muts ...Mutation) (uint64, error)
	// Index reports the latest allocated index.
	Index(ctx context.Context) (uint64, error)
	// Changes returns CDC records with Index > since, oldest first, bounded by
	// limit — the replicator's read path (PRD §15.3).
	Changes(ctx context.Context, since uint64, limit int) ([]Change, error)
	// PruneChanges drops CDC records with Index <= upto, once the replicator
	// has durably shipped them. Without it the change log grows forever.
	PruneChanges(ctx context.Context, upto uint64) (int, error)
	// Close releases the database.
	Close() error
}
