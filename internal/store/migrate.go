package store

import (
	"context"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

// Schema migrations (PRD §15.4).
//
// Forward-only, one transaction each, and never automatic in the sense that
// matters: the caller decides when, because the thing that has to happen first
// (a copy of the database as it was) is not something this package can do for
// itself while holding the write lock.
//
// A migration that fails leaves the schema version where it was, so the next
// start tries again against the same state rather than against half of it.

// Migration is one forward step.
type Migration struct {
	// To is the schema version this produces. Migrations run in ascending
	// order, and each must be exactly one above the last.
	To uint64
	// Description goes in the log, and is what an operator reads when a start
	// takes longer than usual.
	Description string
	// Apply transforms the database inside a write transaction. It must be
	// idempotent where it can be: a crash between the data change and the
	// version bump is possible, and the next start will run it again.
	Apply func(tx *bolt.Tx) error
}

// migrations is the ordered set this binary knows.
//
// Empty, because v1 is the first schema. It is not a placeholder: the framework
// has to exist before the first migration does, or the first schema change
// arrives with nowhere to put the pre-migration snapshot logic and gets done by
// hand on somebody's node.
var migrations []Migration

// Pending describes an outstanding migration.
type Pending struct {
	From uint64
	To   uint64
	// Steps are the migrations that will run, in order.
	Steps []Migration
}

// Needed reports whether anything has to run.
func (p Pending) Needed() bool { return len(p.Steps) > 0 }

// Describe renders the plan for a log line.
func (p Pending) Describe() string {
	if !p.Needed() {
		return "none"
	}
	return fmt.Sprintf("v%d → v%d (%d step(s))", p.From, p.To, len(p.Steps))
}

// SchemaVersion is the schema this binary writes.
func SchemaVersion() uint64 { return schemaVersion }

// PendingMigration reports what a store needs before it is current.
//
// It is separate from Open so the caller can put a backup between the two. A
// migration is the one routine operation that rewrites state in place, and the
// copy taken beforehand is the only way back from one that goes wrong.
func PendingMigration(ctx context.Context, s Store) (Pending, error) {
	bs, ok := s.(*boltStore)
	if !ok {
		return Pending{}, fmt.Errorf("%w: %T cannot report a schema version", ErrInvalid, s)
	}
	if err := bs.check(ctx); err != nil {
		return Pending{}, err
	}

	var have uint64
	err := bs.db.View(func(tx *bolt.Tx) error {
		have = decodeUint64(tx.Bucket(bucketMeta).Get(metaKeySchema))
		return nil
	})
	if err != nil {
		return Pending{}, fmt.Errorf("read schema version: %w", err)
	}
	return planMigration(have)
}

// planMigration selects the steps from a starting version.
func planMigration(have uint64) (Pending, error) {
	switch {
	case have > schemaVersion:
		// Unreachable through Open, which refuses this, and checked again
		// because "unreachable" is a claim about today's call sites, and this
		// is the one that would rewrite a newer database with older code.
		return Pending{}, fmt.Errorf(
			"%w: on-disk schema v%d is newer than this binary's v%d; upgrade kanea",
			ErrInvalid, have, schemaVersion)
	case have == schemaVersion:
		return Pending{From: have, To: have}, nil
	}

	ordered := append([]Migration(nil), migrations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].To < ordered[j].To })

	plan := Pending{From: have, To: have}
	for _, m := range ordered {
		if m.To <= have {
			continue
		}
		if m.To != plan.To+1 {
			// A gap means a migration was deleted or misnumbered, and running
			// the rest would apply a transformation to a shape it was not
			// written for.
			return Pending{}, fmt.Errorf(
				"%w: no migration from schema v%d to v%d", ErrInvalid, plan.To, plan.To+1)
		}
		plan.Steps = append(plan.Steps, m)
		plan.To = m.To
	}
	if plan.To != schemaVersion {
		return Pending{}, fmt.Errorf(
			"%w: this binary writes schema v%d but knows no migration past v%d",
			ErrInvalid, schemaVersion, plan.To)
	}
	return plan, nil
}

// Migrate runs the pending migrations.
//
// Each step is one transaction that includes its own version bump: a crash
// between a step's data change and its version marker would otherwise leave a
// database that is neither version, and no amount of care in the step itself
// can fix that from outside the transaction.
func Migrate(ctx context.Context, s Store) (Pending, error) {
	bs, ok := s.(*boltStore)
	if !ok {
		return Pending{}, fmt.Errorf("%w: %T cannot be migrated", ErrInvalid, s)
	}
	plan, err := PendingMigration(ctx, s)
	if err != nil || !plan.Needed() {
		return plan, err
	}

	for _, step := range plan.Steps {
		bs.log.Warn("migrating the state schema",
			"to", step.To, "description", step.Description,
			"detail", "do not interrupt this; a pre-migration copy was taken first")

		err := bs.db.Update(func(tx *bolt.Tx) error {
			if err := step.Apply(tx); err != nil {
				return fmt.Errorf("migration to v%d (%s): %w", step.To, step.Description, err)
			}
			return tx.Bucket(bucketMeta).Put(metaKeySchema, encodeUint64(step.To))
		})
		if err != nil {
			// The version is unchanged, so the next start retries this same
			// step against the same state rather than against half of it.
			return plan, err
		}
		bs.log.Info("migrated the state schema", "to", step.To)
	}
	return plan, nil
}
