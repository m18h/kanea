package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

// schemaVersion is the on-disk layout version (PRD §15.4). Migrations are
// forward-only and run at startup; an unknown-newer version is refused rather
// than guessed at, because a downgrade that silently rewrites state is
// unrecoverable.
//
// A var rather than a const so a test can stand a future schema up against the
// migration machinery, which otherwise could not be exercised until the first
// real migration existed, which is the worst moment to find out it is wrong.
// It is package-private and nothing writes to it outside a test.
var schemaVersion uint64 = 1

// Internal buckets. The leading underscore keeps them out of the Kind space, so
// a caller can never address them through the public API.
var (
	bucketMeta    = []byte("_meta")
	bucketChanges = []byte("_changes")

	metaKeySchema = []byte("schema_version")
	metaKeyIndex  = []byte("index")
)

// Options configures Open. Only Path is required.
type Options struct {
	// Path to the database file. Parent directories are created (0750).
	Path string
	// Timeout bounds waiting for the file lock; another kanead holding it is a
	// misconfiguration we want reported, not a hang. Default 5s.
	Timeout time.Duration
	// ReadOnly opens without the write lock (inspection, `kanea doctor`).
	ReadOnly bool
	// Logger receives open/migration events. Defaults to a discard logger.
	Logger *slog.Logger
	// Now is injectable for tests. Defaults to time.Now.
	Now func() time.Time
}

// boltStore is the bbolt-backed Store. Writes serialize on bbolt's single
// writer; reads run in concurrent read transactions.
type boltStore struct {
	db  *bolt.DB
	log *slog.Logger
	now func() time.Time
	// closed is atomic: Close can race with in-flight calls from other
	// goroutines, and "database not open" from bbolt is a worse error than ours.
	closed atomic.Bool
}

// check is the common guard: cancelled context or closed store, before any
// transaction is opened.
func (s *boltStore) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrClosed
	}
	return nil
}

// Open opens or creates the database, applying forward migrations.
func Open(opts Options) (Store, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("%w: empty store path", ErrInvalid)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o750); err != nil {
		return nil, fmt.Errorf("store dir: %w", err)
	}

	// The file holds the secrets and certs buckets; 0600 is set at creation,
	// but an existing file keeps whatever an operator (or a backup tool)
	// left on it. Warned, not refused (K-52): an upgraded daemon must not
	// refuse to boot over permissions it can only report, and the finding is
	// also a `kanea doctor` check.
	if info, err := os.Lstat(opts.Path); err == nil && info.Mode().Perm()&0o077 != 0 {
		opts.Logger.Warn("state database is readable by group or other",
			"path", opts.Path, "mode", fmt.Sprintf("%04o", info.Mode().Perm()),
			"detail", "it holds encrypted secrets and certificates; chmod 0600")
	}

	// 0600: the secrets and certs buckets live in this file.
	db, err := bolt.Open(opts.Path, 0o600, &bolt.Options{
		Timeout:  opts.Timeout,
		ReadOnly: opts.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", opts.Path, err)
	}

	s := &boltStore{db: db, log: opts.Logger, now: opts.Now}
	if !opts.ReadOnly {
		if err := s.init(); err != nil {
			return nil, errors.Join(err, db.Close())
		}
	}
	return s, nil
}

// init creates buckets and runs migrations in one transaction.
func (s *boltStore) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range append([][]byte{bucketMeta, bucketChanges}, kindBuckets()...) {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		meta := tx.Bucket(bucketMeta)

		found := meta.Get(metaKeySchema)
		if found == nil {
			if err := meta.Put(metaKeySchema, encodeUint64(schemaVersion)); err != nil {
				return err
			}
			s.log.Info("store initialised", "schema_version", schemaVersion)
			return nil
		}

		have := decodeUint64(found)
		if have > schemaVersion {
			// The one version mismatch that is always fatal. A newer database
			// opened by an older binary is a downgrade, and a downgrade that
			// silently writes is unrecoverable: the fields the newer version
			// added are dropped by the older one's encoder on the first update.
			return fmt.Errorf("%w: on-disk schema v%d is newer than this binary's v%d; upgrade kanea",
				ErrInvalid, have, schemaVersion)
		}
		if have < schemaVersion {
			// Not migrated here (PRD §15.4). Opening and migrating in one step
			// would leave nowhere to put the copy that makes a bad migration
			// survivable, and taking that copy needs the database open. So Open
			// checks that a path exists and the caller runs it: see
			// PendingMigration and Migrate.
			if _, err := planMigration(have); err != nil {
				return err
			}
			s.log.Warn("the state schema is out of date",
				"on_disk", have, "binary", schemaVersion,
				"detail", "kanead migrates it at startup, after taking a copy")
		}
		return nil
	})
}

func kindBuckets() [][]byte {
	out := make([][]byte, 0, len(Kinds()))
	for _, k := range Kinds() {
		out = append(out, []byte(k))
	}
	return out
}

func (s *boltStore) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // idempotent: a double Close is not an error
	}
	return s.db.Close()
}

func (s *boltStore) Get(ctx context.Context, kind Kind, key string) (Record, error) {
	if err := s.check(ctx); err != nil {
		return Record{}, err
	}
	if !kind.valid() {
		return Record{}, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
	}
	if key == "" {
		return Record{}, fmt.Errorf("%w: empty key", ErrInvalid)
	}

	var rec Record
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(kind)).Get([]byte(key))
		if raw == nil {
			return fmt.Errorf("%w: %s/%s", ErrNotFound, kind, key)
		}
		index, value, err := decodeRecord(raw)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", kind, key, err)
		}
		rec = Record{Kind: kind, Key: key, Index: index, Value: value}
		return nil
	})
	return rec, err
}

func (s *boltStore) List(ctx context.Context, kind Kind, opts ListOptions) (Page, error) {
	if err := s.check(ctx); err != nil {
		return Page{}, err
	}
	if !kind.valid() {
		return Page{}, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
	}

	limit := opts.limit()
	page := Page{Records: make([]Record, 0, limit)}
	err := s.db.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket([]byte(kind)).Cursor()
		prefix := []byte(opts.Prefix)

		step := cur.Next
		if opts.Reverse {
			step = cur.Prev
		}

		var k, v []byte
		switch {
		case opts.After != "" && opts.Reverse:
			// Seek lands on or after After, so one step back is the first key
			// strictly below it; After stays exclusive. A Seek that falls off
			// the end means After is above every key, and the scan starts at the
			// last one.
			if k, _ = cur.Seek([]byte(opts.After)); k == nil {
				k, v = cur.Last()
			} else {
				k, v = cur.Prev()
			}
		case opts.After != "":
			// Seek lands on or after After; skip the exact match to make After
			// exclusive and resumption idempotent.
			k, v = cur.Seek([]byte(opts.After))
			if k != nil && string(k) == opts.After {
				k, v = cur.Next()
			}
		case opts.Reverse && len(prefix) > 0:
			// Land just past the prefix range and step back into it. Seeking the
			// prefix itself would land on its *first* key, which is the wrong end.
			if end := prefixEnd(prefix); end == nil {
				k, v = cur.Last()
			} else if k, _ = cur.Seek(end); k == nil {
				k, v = cur.Last()
			} else {
				k, v = cur.Prev()
			}
		case opts.Reverse:
			k, v = cur.Last()
		case len(prefix) > 0:
			k, v = cur.Seek(prefix)
		default:
			k, v = cur.First()
		}

		for ; k != nil; k, v = step() {
			if len(prefix) > 0 && !bytes.HasPrefix(k, prefix) {
				break // keys are ordered: past the prefix means done
			}
			if len(page.Records) == limit {
				page.More = true
				return nil
			}
			index, value, err := decodeRecord(v)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", kind, k, err)
			}
			rec := Record{Kind: kind, Key: string(k), Index: index}
			if !opts.KeysOnly {
				rec.Value = value
			}
			page.Records = append(page.Records, rec)
			page.NextAfter = rec.Key
		}
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	if !page.More {
		page.NextAfter = ""
	}
	return page, nil
}

func (s *boltStore) Apply(ctx context.Context, muts ...Mutation) (uint64, error) {
	if err := s.check(ctx); err != nil {
		return 0, err
	}
	// Validate everything before opening the write transaction: a bad batch
	// must not take the writer lock, and must not half-apply.
	for i, m := range muts {
		if err := m.validate(); err != nil {
			return 0, fmt.Errorf("mutation %d: %w", i, err)
		}
	}
	if len(muts) == 0 {
		return s.Index(ctx)
	}

	var index uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		index = decodeUint64(meta.Get(metaKeyIndex)) + 1

		// Preconditions first, so a conflict aborts before any write.
		for i, m := range muts {
			if m.PrevIndex == 0 && !m.ExpectAbsent {
				continue
			}
			raw := tx.Bucket([]byte(m.Kind)).Get([]byte(m.Key))
			switch {
			case m.ExpectAbsent && raw != nil:
				return fmt.Errorf("%w: %s/%s already exists (mutation %d)", ErrConflict, m.Kind, m.Key, i)
			case m.PrevIndex > 0 && raw == nil:
				return fmt.Errorf("%w: %s/%s gone, expected index %d (mutation %d)",
					ErrConflict, m.Kind, m.Key, m.PrevIndex, i)
			case m.PrevIndex > 0:
				if have := decodeUint64(raw[:8]); have != m.PrevIndex {
					return fmt.Errorf("%w: %s/%s at index %d, expected %d (mutation %d)",
						ErrConflict, m.Kind, m.Key, have, m.PrevIndex, i)
				}
			}
		}

		changes := tx.Bucket(bucketChanges)
		now := s.now().UTC()
		seq := uint32(0)
		for _, m := range muts {
			b := tx.Bucket([]byte(m.Kind))
			switch m.Op {
			case OpPut:
				if err := b.Put([]byte(m.Key), encodeRecord(index, m.Value)); err != nil {
					return err
				}
			case OpDelete:
				if b.Get([]byte(m.Key)) == nil {
					continue // no-op delete: nothing to replicate
				}
				if err := b.Delete([]byte(m.Key)); err != nil {
					return err
				}
			}
			ch := Change{Index: index, Op: m.Op, Kind: m.Kind, Key: m.Key, Time: now}
			if m.Op == OpPut {
				ch.Value = m.Value
			}
			encoded, err := json.Marshal(ch)
			if err != nil {
				return fmt.Errorf("encode change: %w", err)
			}
			if err := changes.Put(changeKey(index, seq), encoded); err != nil {
				return err
			}
			seq++
		}
		return meta.Put(metaKeyIndex, encodeUint64(index))
	})
	if err != nil {
		return 0, err
	}
	return index, nil
}

func (s *boltStore) Index(ctx context.Context) (uint64, error) {
	if err := s.check(ctx); err != nil {
		return 0, err
	}
	var index uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		index = decodeUint64(tx.Bucket(bucketMeta).Get(metaKeyIndex))
		return nil
	})
	return index, err
}

func (s *boltStore) Changes(ctx context.Context, since uint64, limit int) ([]Change, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = DefaultListLimit
	} else if limit > MaxListLimit {
		limit = MaxListLimit
	}

	out := make([]Change, 0, limit)
	err := s.db.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket(bucketChanges).Cursor()
		// Changes are keyed index||seq, so seeking past the last seq of `since`
		// starts exactly at the next index.
		for k, v := cur.Seek(changeKey(since+1, 0)); k != nil; k, v = cur.Next() {
			if len(out) == limit {
				return nil
			}
			var ch Change
			if err := json.Unmarshal(v, &ch); err != nil {
				return fmt.Errorf("decode change %x: %w", k, err)
			}
			out = append(out, ch)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *boltStore) PruneChanges(ctx context.Context, upto uint64) (int, error) {
	if err := s.check(ctx); err != nil {
		return 0, err
	}
	pruned := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketChanges)
		cur := b.Cursor()
		for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
			if decodeUint64(k[:8]) > upto {
				return nil
			}
			if err := cur.Delete(); err != nil {
				return err
			}
			pruned++
		}
		return nil
	})
	return pruned, err
}

// Compact rewrites the database into dst. bbolt never shrinks in place, so
// without this the file (and every backup derived from it) grows forever
// (PRD §5.2.3). The caller swaps the file in; this only produces it.
func Compact(ctx context.Context, s Store, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bs, ok := s.(*boltStore)
	if !ok {
		return fmt.Errorf("%w: compaction needs the bbolt store", ErrInvalid)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("compact dir: %w", err)
	}
	out, err := bolt.Open(dst, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("compact open %s: %w", dst, err)
	}
	if err := bolt.Compact(out, bs.db, 0); err != nil {
		return errors.Join(fmt.Errorf("compact: %w", err), out.Close())
	}
	// Close, not defer: a compacted copy that failed to flush is worse than no
	// copy, and the caller is about to swap this file in.
	if err := out.Close(); err != nil {
		return fmt.Errorf("compact close %s: %w", dst, err)
	}
	return nil
}

// prefixEnd returns the first key that sorts after every key with this prefix,
// which is where a reverse scan of the prefix range begins. It is nil when the
// prefix is all 0xff bytes and therefore has no successor: the caller then
// starts at the last key in the bucket, which is inside the range anyway.
func prefixEnd(prefix []byte) []byte {
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xff {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}

// ---- encoding ----
//
// Records are stored as an 8-byte big-endian index followed by the payload, so
// a precondition check reads only the header. Change records are JSON: they
// leave the process as replication segments, where self-describing beats compact.

func encodeRecord(index uint64, value []byte) []byte {
	buf := make([]byte, 8+len(value))
	binary.BigEndian.PutUint64(buf[:8], index)
	copy(buf[8:], value)
	return buf
}

func decodeRecord(raw []byte) (uint64, []byte, error) {
	if len(raw) < 8 {
		return 0, nil, fmt.Errorf("%w: record shorter than its header (%d bytes)", ErrInvalid, len(raw))
	}
	// Copy: the caller outlives the transaction that owns this page.
	value := make([]byte, len(raw)-8)
	copy(value, raw[8:])
	return binary.BigEndian.Uint64(raw[:8]), value, nil
}

func encodeUint64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

func decodeUint64(raw []byte) uint64 {
	if len(raw) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw[:8])
}

// changeKey orders CDC records by (index, seq): one Apply batch shares an index,
// and seq preserves within-batch order.
func changeKey(index uint64, seq uint32) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[:8], index)
	binary.BigEndian.PutUint32(buf[8:], seq)
	return buf
}
