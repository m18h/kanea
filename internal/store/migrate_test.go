package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The migration framework ships with no migrations, because v1 is the first
// schema. These tests are about the machinery — the planner, the transaction
// boundary and the downgrade guard — which has to be right before the first
// migration exists, not after.

func openAt(t *testing.T, path string) Store {
	t.Helper()
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// setVersion writes a schema version directly, standing in for a database
// written by another build.
func setVersion(t *testing.T, path string, version uint64) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaKeySchema, encodeUint64(version))
	}); err != nil {
		t.Fatalf("set version: %v", err)
	}
}

func TestANewerDatabaseIsRefused(t *testing.T) {
	// The one mismatch that is always fatal. An older binary that wrote to a
	// newer database would drop the fields the newer one added, on the first
	// update, permanently.
	path := filepath.Join(t.TempDir(), "state.db")
	s := openAt(t, path)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	setVersion(t, path, schemaVersion+1)

	_, err := Open(Options{Path: path})
	if err == nil {
		t.Fatal("a newer database was opened by an older binary")
	}
	if !strings.Contains(err.Error(), "upgrade kanea") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

func TestACurrentDatabaseHasNothingPending(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "state.db"))
	pending, err := PendingMigration(context.Background(), s)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if pending.Needed() {
		t.Errorf("a freshly created store wants migrating: %s", pending.Describe())
	}
	if pending.Describe() != "none" {
		t.Errorf("Describe() = %q, want %q", pending.Describe(), "none")
	}
}

// withSchema raises the binary's schema version and registers migrations for a
// test, restoring both afterwards.
func withSchema(t *testing.T, version uint64, steps ...Migration) {
	t.Helper()
	savedVersion, savedSteps := schemaVersion, migrations
	t.Cleanup(func() { schemaVersion, migrations = savedVersion, savedSteps })
	schemaVersion, migrations = version, steps
}

func TestPlannerRefusesAGap(t *testing.T) {
	// A gap means a migration was deleted or misnumbered. Running the rest
	// would apply a transformation to a shape it was not written for.
	withSchema(t, 3, Migration{To: 3, Description: "skips v2"})

	_, err := planMigration(1)
	if err == nil {
		t.Fatal("a gap in the migration chain was accepted")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestPlannerRefusesToStopShortOfTheBinarysSchema(t *testing.T) {
	// Migrations that do not reach the version this binary writes would leave a
	// database the next Open refuses, in a loop.
	withSchema(t, 2)

	if _, err := planMigration(schemaVersion - 1); err == nil {
		t.Fatal("a plan that never reaches the current schema was accepted")
	}
}

func TestMigrationAndItsVersionBumpShareATransaction(t *testing.T) {
	// A crash between a step's data change and its version marker would leave a
	// database that is neither version, and nothing inside the step can fix
	// that from outside the transaction. So a failing step must leave both
	// untouched.
	path := filepath.Join(t.TempDir(), "state.db")
	s := openAt(t, path)
	ctx := context.Background()
	was := schemaVersion

	// The store is on the old schema; the binary now claims the new one, with a
	// migration between them that fails half way.
	withSchema(t, was+1, Migration{
		To: was + 1, Description: "writes then fails",
		Apply: func(tx *bolt.Tx) error {
			if err := tx.Bucket([]byte(KindService)).Put([]byte("p/s"), []byte("half-done")); err != nil {
				return err
			}
			return errors.New("the migration failed after writing")
		},
	})

	if _, err := Migrate(ctx, s); err == nil {
		t.Fatal("a failing migration reported success")
	}

	// Neither the write nor the version bump survived.
	if _, err := s.Get(ctx, KindService, "p/s"); !errors.Is(err, ErrNotFound) {
		t.Error("a failed migration's partial write was committed")
	}
	pending, err := PendingMigration(ctx, s)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if pending.From != was {
		t.Errorf("the schema version moved despite the failure: %d", pending.From)
	}
}

func TestMigrationRunsAndBumpsTheVersion(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()
	was := schemaVersion
	withSchema(t, was+1, Migration{
		To: was + 1, Description: "writes a marker",
		Apply: func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(KindKV)).Put([]byte("migrated"), []byte("yes"))
		},
	})

	plan, err := Migrate(ctx, s)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(plan.Steps) != 1 || plan.To != was+1 {
		t.Fatalf("plan = %+v, want one step to v%d", plan, was+1)
	}

	// Running again is a no-op: the version moved.
	again, err := PendingMigration(ctx, s)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if again.Needed() {
		t.Errorf("the migration wants to run twice: %s", again.Describe())
	}
}
