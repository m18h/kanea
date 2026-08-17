package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// Typed access. Callers work with domain structs; the Store stays byte-oriented
// so that a Raft FSM can replay an Apply batch without knowing any of them.
//
// JSON is the payload encoding: state is small, human-readable dumps are worth
// a lot during incident response, and field additions stay backward-compatible
// (PRD §15.4 pairs this with bucket schema versions for the breaking cases).

// Reader is the read surface the typed helpers need. Taking the narrowest
// interface lets a caller pass its own consumer-defined subset of Store rather
// than the whole thing.
type Reader interface {
	Get(ctx context.Context, kind Kind, key string) (Record, error)
	List(ctx context.Context, kind Kind, opts ListOptions) (Page, error)
}

// Applier is the write surface: one atomic batch.
type Applier interface {
	Apply(ctx context.Context, muts ...Mutation) (uint64, error)
}

// GetValue reads and decodes one record, returning its index alongside the
// value so the caller can pass it back as Mutation.PrevIndex for a safe update.
func GetValue[T any](ctx context.Context, s Reader, kind Kind, key string) (T, uint64, error) {
	var out T
	rec, err := s.Get(ctx, kind, key)
	if err != nil {
		return out, 0, err
	}
	if err := json.Unmarshal(rec.Value, &out); err != nil {
		return out, 0, fmt.Errorf("decode %s/%s: %w", kind, key, err)
	}
	return out, rec.Index, nil
}

// ListValues decodes a bounded page. The returned Page carries the pagination
// cursor; values come back in the parallel slice, in the same order.
func ListValues[T any](ctx context.Context, s Reader, kind Kind, opts ListOptions) ([]T, Page, error) {
	page, err := s.List(ctx, kind, opts)
	if err != nil {
		return nil, Page{}, err
	}
	out := make([]T, 0, len(page.Records))
	for _, rec := range page.Records {
		var v T
		if err := json.Unmarshal(rec.Value, &v); err != nil {
			return nil, Page{}, fmt.Errorf("decode %s/%s: %w", kind, rec.Key, err)
		}
		out = append(out, v)
	}
	return out, page, nil
}

// PutMutation builds an unconditional upsert for a typed value.
func PutMutation[T any](kind Kind, key string, value T) (Mutation, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Mutation{}, fmt.Errorf("encode %s/%s: %w", kind, key, err)
	}
	return Mutation{Op: OpPut, Kind: kind, Key: key, Value: raw}, nil
}

// CreateMutation builds a create-only put: it fails with ErrConflict if the key
// already exists.
func CreateMutation[T any](kind Kind, key string, value T) (Mutation, error) {
	m, err := PutMutation(kind, key, value)
	if err != nil {
		return Mutation{}, err
	}
	m.ExpectAbsent = true
	return m, nil
}

// UpdateMutation builds a compare-and-set put: it fails with ErrConflict unless
// the record is still at prevIndex. This is how the reconciler avoids clobbering
// a concurrent API write.
func UpdateMutation[T any](kind Kind, key string, value T, prevIndex uint64) (Mutation, error) {
	m, err := PutMutation(kind, key, value)
	if err != nil {
		return Mutation{}, err
	}
	m.PrevIndex = prevIndex
	return m, nil
}

// DeleteMutation builds an unconditional delete. Deleting a missing key is a
// no-op, not an error.
func DeleteMutation(kind Kind, key string) Mutation {
	return Mutation{Op: OpDelete, Kind: kind, Key: key}
}

// PutValue is the one-call convenience for a single unconditional write.
// Batches should build mutations and pass them to Apply together, so they
// commit (and replicate) atomically.
func PutValue[T any](ctx context.Context, s Applier, kind Kind, key string, value T) (uint64, error) {
	m, err := PutMutation(kind, key, value)
	if err != nil {
		return 0, err
	}
	return s.Apply(ctx, m)
}

// PutRawMutation builds an upsert for a value that is already encoded.
//
// It exists for callers holding bytes rather than a Go value: the ACME manager
// serialises its own records so that internal/acme need not know what a Store
// is. The payload is checked here rather than trusted: a record that is not
// valid JSON would survive the write and fail every later read, which turns a
// caller's bug into a corrupt bucket.
func PutRawMutation(kind Kind, key string, raw []byte) (Mutation, error) {
	if !json.Valid(raw) {
		return Mutation{}, fmt.Errorf("encode %s/%s: value is not valid JSON", kind, key)
	}
	return Mutation{Op: OpPut, Kind: kind, Key: key, Value: raw}, nil
}
