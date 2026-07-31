package store_test

import (
	"encoding/binary"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// bumpSchemaVersion rewrites the on-disk schema version behind the Store's back,
// so the open-path guard can be tested without a second binary. It pokes at
// internal bucket names on purpose: this is the one test that must know them.
func bumpSchemaVersion(t *testing.T, path string, version uint64) {
	t.Helper()

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, version)
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("_meta")).Put([]byte("schema_version"), buf)
	}); err != nil {
		t.Fatalf("write schema version: %v", err)
	}
}
