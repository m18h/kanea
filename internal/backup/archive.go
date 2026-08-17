package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/store"
)

// The archive layout (PRD §15.3).
//
//	manifests/<id>.json          the index: what this archive contains and its hashes
//	snapshots/<id>.snap          an encrypted, compacted copy of the whole Store
//
// A manifest is written last and is the only thing a restore looks for. That
// ordering is the commit point: an archive whose snapshot uploaded and whose
// manifest did not is invisible, which is correct, because a restore that found
// it would have no hashes to verify it against.

// Object name prefixes.
const (
	prefixManifests = "manifests/"
	prefixSnapshots = "snapshots/"
)

// FormatVersion is the archive layout's version. It is checked on restore, so
// a future layout produces a clear refusal rather than a partial recovery.
const FormatVersion = 1

// Manifest describes one archive.
type Manifest struct {
	Format int    `json:"format"`
	ID     string `json:"id"`
	// KeyID fingerprints the master key this was encrypted under. Checked
	// before anything is decrypted, so "you have the wrong key" and "these
	// bytes are damaged" are different messages.
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
	// Index is the Store index the snapshot was taken at. A restore replays
	// segments with a higher index onto it, and nothing lower.
	Index uint64 `json:"index"`
	// Reason records what asked for this archive: a schedule, an operator, a
	// pre-migration safety copy (§15.4).
	Reason string `json:"reason,omitempty"`
	// Snapshot is the state part. Every archive has one.
	Snapshot Part `json:"snapshot"`
	// Node identifies the node this came from, so a bucket shared by two nodes
	// does not silently restore the wrong one.
	Node string `json:"node,omitempty"`
	// Version is the Kanea build that wrote it.
	Version string `json:"version,omitempty"`
	// Counts is a human-readable summary: how many services, allocs, secrets.
	// It exists so `kanea backup list` can say what an archive holds without
	// decrypting it, which is what an operator actually needs when choosing
	// which one to restore.
	Counts map[string]int `json:"counts,omitempty"`
	// MAC authenticates the whole manifest (v1.74). Empty on archives written
	// before it existed; a restore accepts those with a loud warning, because
	// everything above this line is bucket-side writable without it: KeyID,
	// Index, CreatedAt and the snapshot's own name and hash all decide what a
	// restore trusts, and all of them came from the same unauthenticated
	// document.
	MAC string `json:"mac,omitempty"`
}

// Part is one stored object and how to verify it.
type Part struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// SHA256 is over the *ciphertext*, so an archive can be verified by anyone
	// holding the bucket and nothing else: including a node that has lost its
	// master key and needs to know whether the backup is worth recovering the
	// key for.
	SHA256 string `json:"sha256"`
}

// ErrNoArchives is returned when a bucket holds nothing to restore.
var ErrNoArchives = errors.New("backup: no archives found")

// Snapshotter takes the Store snapshot an archive is built from.
//
// An interface because the operation is "hand me a consistent copy of the
// database on disk", and bbolt's answer to that (a compacting copy) is not the
// only possible one: a future Raft store answers it differently.
type Snapshotter interface {
	// Snapshot writes a consistent copy of the state to path and reports the
	// index it is consistent as of.
	Snapshot(ctx context.Context, path string) (uint64, error)
}

// StoreSnapshotter snapshots a bbolt Store by compacting it into a new file.
type StoreSnapshotter struct{ Store store.Store }

// Snapshot compacts the Store into path.
func (s StoreSnapshotter) Snapshot(ctx context.Context, path string) (uint64, error) {
	// The index is read first. Compact runs in a read transaction, so anything
	// committed after this point is not in the copy; recording the earlier
	// index means a restore replays a few changes it already has rather than
	// missing changes it does not: the safe direction, because applying a
	// change twice is a no-op and skipping one loses state.
	index, err := s.Store.Index(ctx)
	if err != nil {
		return 0, fmt.Errorf("backup: read index: %w", err)
	}
	if err := store.Compact(ctx, s.Store, path); err != nil {
		return 0, fmt.Errorf("backup: snapshot: %w", err)
	}
	return index, nil
}

// Config configures an archiver.
type Config struct {
	Sink Sink
	Keys Keys
	// Snapshotter produces the state copy. Required.
	Snapshotter Snapshotter
	// WorkDir is where the plaintext snapshot is staged before encryption.
	// It must be on a filesystem with room for a copy of the database.
	WorkDir string
	// Node and Version are recorded in the manifest.
	Node    string
	Version string
	Logger  *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
}

// Archiver writes and reads archives.
type Archiver struct {
	sink        Sink
	keys        Keys
	snapshotter Snapshotter
	workDir     string
	node        string
	version     string
	log         *slog.Logger
	now         func() time.Time
}

// New builds an archiver.
func New(cfg Config) (*Archiver, error) {
	switch {
	case cfg.Sink == nil:
		return nil, errors.New("backup: a sink is required")
	case cfg.Snapshotter == nil:
		return nil, errors.New("backup: a snapshotter is required")
	case cfg.Keys.stream == nil:
		return nil, errors.New("backup: keys are required")
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = os.TempDir()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Archiver{
		sink: cfg.Sink, keys: cfg.Keys, snapshotter: cfg.Snapshotter,
		workDir: cfg.WorkDir, node: cfg.Node, version: cfg.Version,
		log: cfg.Logger, now: cfg.Now,
	}, nil
}

// Sink reports where this archiver writes, for messages.
func (a *Archiver) Sink() string { return a.sink.Describe() }

// ErrNotConfigured means no destination is configured; the API maps it to the
// same 503 an absent backup subsystem always answered with.
var ErrNotConfigured = errors.New(
	"backup: no destination is configured (set one with --backup-dir/--backup-s3, or PUT /v1/settings/backup)")

// Probe verifies the sink end to end: write a small object, list it back,
// delete it. It runs through the sink's real Put (the reader-ownership defect
// the s3-interop job caught was invisible to every fake) so a destination
// that passes has proven auth, addressing style and writability, which is what
// a hot swap (v1.46) needs to know before it stops working replication.
func (a *Archiver) Probe(ctx context.Context) error {
	name := fmt.Sprintf("probe/%d", a.now().UTC().UnixNano())
	const body = "kanea destination probe"
	if err := a.sink.Put(ctx, name, int64(len(body)), strings.NewReader(body)); err != nil {
		return fmt.Errorf("backup: probe write to %s: %w", a.sink.Describe(), err)
	}
	objects, err := a.sink.List(ctx, "probe/")
	if err != nil {
		return fmt.Errorf("backup: probe listing on %s: %w", a.sink.Describe(), err)
	}
	found := false
	for _, o := range objects {
		if o.Name == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("backup: probe object never appeared in %s's listing", a.sink.Describe())
	}
	if err := a.sink.Delete(ctx, name); err != nil {
		return fmt.Errorf("backup: probe cleanup on %s: %w", a.sink.Describe(), err)
	}
	return nil
}

// Create takes a snapshot and uploads it as a new archive.
func (a *Archiver) Create(ctx context.Context, reason string, counts map[string]int) (Manifest, error) {
	at := a.now().UTC()
	id := archiveID(at)

	staged := filepath.Join(a.workDir, "kanea-snapshot-"+id)
	index, err := a.snapshotter.Snapshot(ctx, staged)
	if err != nil {
		return Manifest{}, err
	}
	// The staged copy is the whole database in plaintext. It goes as soon as it
	// is uploaded, success or failure: leaving it behind would put an
	// unencrypted copy of every secret in a temp directory, which is the one
	// cleanup failure on this path that is worth saying out loud.
	defer a.discard(staged, "plaintext snapshot")

	part, err := a.upload(ctx, prefixSnapshots+id+".snap", staged)
	if err != nil {
		return Manifest{}, err
	}

	manifest := Manifest{
		Format: FormatVersion, ID: id, KeyID: a.keys.ID, CreatedAt: at,
		Index: index, Reason: reason, Snapshot: part,
		Node: a.node, Version: a.version, Counts: counts,
	}
	manifest.MAC = a.signManifest(manifest)
	if err := a.putManifest(ctx, manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// upload encrypts a local file into the sink and returns its Part.
func (a *Archiver) upload(ctx context.Context, name, path string) (_ Part, err error) {
	// Encrypted into a staging file rather than streamed straight to the sink:
	// the sink's Put needs a size and the manifest needs the ciphertext hash,
	// and neither is known until the encryption has run. The alternative is
	// buffering the whole ciphertext in memory, which is the thing the chunked
	// format exists to avoid.
	source, err := os.Open(path) // #nosec G304; a path this package just wrote
	if err != nil {
		return Part{}, fmt.Errorf("backup: open snapshot: %w", err)
	}
	defer func() { err = errors.Join(err, source.Close()) }()

	// O_RDWR, not O_WRONLY: the ciphertext is written, then rewound and read
	// back to feed the sink, because Put needs a length the encryption only
	// produces by running.
	sealed := path + ".enc"
	target, err := os.OpenFile(sealed, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304; same
	if err != nil {
		return Part{}, fmt.Errorf("backup: stage ciphertext: %w", err)
	}
	defer func() {
		err = errors.Join(err, target.Close())
		a.discard(sealed, "staged ciphertext")
	}()

	sum, size, err := encryptStream(target, source, a.keys)
	if err != nil {
		return Part{}, err
	}
	if _, err := target.Seek(0, io.SeekStart); err != nil {
		return Part{}, fmt.Errorf("backup: rewind ciphertext: %w", err)
	}
	if err := a.sink.Put(ctx, name, size, target); err != nil {
		return Part{}, err
	}
	return Part{Name: name, Size: size, SHA256: sum}, nil
}

// putManifest writes the manifest, which is what makes an archive real.
//
// Unencrypted, deliberately. It holds no secret (hashes, sizes, an index, a
// key fingerprint and counts) and it is what someone recovering from a bucket
// with no key needs to read to know what is there and whether it is intact.
// It is MAC'd (v1.74): readable by anyone, writable only by the key.
func (a *Archiver) putManifest(ctx context.Context, m Manifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: encode manifest: %w", err)
	}
	return a.sink.Put(ctx, prefixManifests+m.ID+".json", int64(len(body)), strings.NewReader(string(body)))
}

// signManifest computes the manifest's MAC. The canonical form is the compact
// encoding of the struct with the MAC field empty: one deterministic byte
// string, and no dependence on how the stored document happened to be spaced.
func (a *Archiver) signManifest(m Manifest) string {
	m.MAC = ""
	canonical, err := json.Marshal(m)
	if err != nil {
		// A struct of strings, numbers and one map of ints cannot fail to
		// encode; the error branch exists so the compiler agrees.
		return ""
	}
	sum := hmac.New(sha256.New, a.keys.mac)
	sum.Write(canonical)
	return hex.EncodeToString(sum.Sum(nil))
}

// verifyManifestMAC authenticates a manifest read back from the sink. A
// manifest with no MAC predates v1.74 and verifies as legacy: the caller
// decides whether to warn (a restore does; a listing does not).
func (a *Archiver) verifyManifestMAC(m Manifest) error {
	if m.MAC == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(m.MAC), []byte(a.signManifest(m))) != 1 {
		return fmt.Errorf("%w: manifest %s failed authentication: its metadata does not "+
			"match the key's MAC, so it was written or altered off-node", ErrCorrupt, m.ID)
	}
	return nil
}

// List returns the archives in the sink, newest first.
func (a *Archiver) List(ctx context.Context) ([]Manifest, error) {
	objects, err := a.sink.List(ctx, prefixManifests)
	if err != nil {
		return nil, err
	}

	out := make([]Manifest, 0, len(objects))
	for _, obj := range objects {
		m, err := a.manifest(ctx, obj.Name)
		if err != nil {
			// One unreadable manifest must not hide the rest: the archive an
			// operator needs is quite possibly one of the others, and a list
			// that fails entirely leaves them with nothing to choose from.
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Latest returns the newest archive.
func (a *Archiver) Latest(ctx context.Context) (Manifest, error) {
	all, err := a.List(ctx)
	if err != nil {
		return Manifest{}, err
	}
	if len(all) == 0 {
		return Manifest{}, fmt.Errorf("%w in %s", ErrNoArchives, a.sink.Describe())
	}
	return all[0], nil
}

// Find returns one archive by id, or the newest when id is empty.
func (a *Archiver) Find(ctx context.Context, id string) (Manifest, error) {
	if id == "" {
		return a.Latest(ctx)
	}
	return a.manifest(ctx, prefixManifests+id+".json")
}

func (a *Archiver) manifest(ctx context.Context, name string) (_ Manifest, err error) {
	body, err := a.sink.Get(ctx, name)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { err = errors.Join(err, body.Close()) }()

	var m Manifest
	// Bounded: a manifest is a few hundred bytes, and this is the one object a
	// restore reads before it has verified anything.
	if err := json.NewDecoder(io.LimitReader(body, maxManifestBytes)).Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("backup: decode %s: %w", name, err)
	}
	if m.Format != FormatVersion {
		return Manifest{}, fmt.Errorf("backup: %s is format %d; this build reads format %d",
			name, m.Format, FormatVersion)
	}
	if err := a.verifyManifestMAC(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

const maxManifestBytes = 1 << 20

// Verify checks an archive's parts against the manifest without decrypting.
//
// No key needed, on purpose: "are the bytes intact" is a question an operator
// asks before going to find the escrowed key, and it should be answerable
// first (§15.3's backup verification).
func (a *Archiver) Verify(ctx context.Context, m Manifest) error {
	return a.verifyPart(ctx, m.Snapshot)
}

func (a *Archiver) verifyPart(ctx context.Context, part Part) (err error) {
	body, err := a.sink.Get(ctx, part.Name)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, body.Close()) }()

	hash := sha256.New()
	size, err := io.Copy(hash, body)
	if err != nil {
		return fmt.Errorf("backup: read %s: %w", part.Name, err)
	}
	if size != part.Size {
		return fmt.Errorf("%w: %s is %d bytes, the manifest says %d",
			ErrCorrupt, part.Name, size, part.Size)
	}
	// Constant-time is not about secrecy here (the hash is public) but the
	// comparison is free and the habit is worth keeping consistent.
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(part.SHA256)) != 1 {
		return fmt.Errorf("%w: %s does not match its manifest hash", ErrCorrupt, part.Name)
	}
	return nil
}

// Fetch verifies an archive's snapshot and writes the decrypted database to
// path.
//
// Verification first, then decryption: the hash catches a damaged object with a
// message that names the object, while decryption catches it with an
// authentication failure that could equally mean the wrong key.
func (a *Archiver) Fetch(ctx context.Context, m Manifest, path string) (err error) {
	if m.KeyID != "" && m.KeyID != a.keys.ID {
		return fmt.Errorf("%w: archive %s was encrypted under key %s, this node holds %s "+
			"(recover the escrowed key from the `kanea init` ceremony; see docs/DR_RUNBOOK.md)",
			ErrKey, m.ID, m.KeyID, a.keys.ID)
	}
	if err := a.verifyPart(ctx, m.Snapshot); err != nil {
		return err
	}

	body, err := a.sink.Get(ctx, m.Snapshot.Name)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, body.Close()) }()

	target, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304; caller's path
	if err != nil {
		return fmt.Errorf("backup: create %s: %w", path, err)
	}
	defer func() {
		err = errors.Join(err, target.Close())
		if err != nil {
			// A half-decrypted database must not be left where something could
			// mistake it for a restored one.
			a.discard(path, "partial restore")
		}
	}()

	if err := decryptStream(target, body, a.keys); err != nil {
		return err
	}
	return target.Sync()
}

// Prune keeps the newest `keep` archives and deletes the rest.
func (a *Archiver) Prune(ctx context.Context, keep int) (int, error) {
	if keep <= 0 {
		return 0, fmt.Errorf("backup: retention must keep at least one archive, got %d", keep)
	}
	all, err := a.List(ctx)
	if err != nil {
		return 0, err
	}
	if len(all) <= keep {
		return 0, nil
	}

	removed := 0
	for _, m := range all[keep:] {
		// The manifest goes last. An archive whose parts are gone but whose
		// manifest remains would be offered by List and fail at restore; one
		// whose manifest is gone is simply not offered, which is the truth.
		if err := a.sink.Delete(ctx, m.Snapshot.Name); err != nil {
			return removed, err
		}
		if err := a.sink.Delete(ctx, prefixManifests+m.ID+".json"); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// discard removes a temporary file, complaining if it cannot.
//
// Failures are logged rather than returned: every caller is already returning
// the outcome of the operation the file belonged to, and replacing "the upload
// failed" with "the cleanup failed" would hide the thing worth acting on. They
// are never silent, because two of the three files this removes hold plaintext
// state.
func (a *Archiver) discard(path, what string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.log.Error("cannot remove a temporary file",
			"what", what, "path", path, "error", err)
	}
}

// archiveID is a sortable, human-readable identifier.
//
// Time-ordered so the object names sort the way the archives do, which makes a
// bucket listing readable without a tool.
func archiveID(at time.Time) string {
	return at.UTC().Format("20060102T150405Z")
}
