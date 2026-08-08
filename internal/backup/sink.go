package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Sink is where archives are written.
//
// Object storage semantics, not filesystem semantics: names are opaque keys,
// writes are whole-object, and there is no rename. That is the smaller of the
// two contracts, and writing the replicator against it means the S3 sink and
// the filesystem sink cannot diverge in behaviour the way they would if the
// interface allowed partial writes.
type Sink interface {
	// Put writes an object. It must be atomic from a reader's point of view:
	// a concurrent List must never see a half-written object.
	//
	// It reads the body and does not own it: the caller closes. Stated because
	// the natural S3 implementation gets this wrong — net/http closes a request
	// body that is already an io.ReadCloser, which silently takes the caller's
	// file handle with it.
	Put(ctx context.Context, name string, size int64, body io.Reader) error
	// Get opens an object for reading.
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	// List returns objects under a prefix, sorted by name.
	List(ctx context.Context, prefix string) ([]Object, error)
	// Delete removes an object. Deleting one that does not exist is not an
	// error: retention runs repeatedly and must be idempotent.
	Delete(ctx context.Context, name string) error
	// Describe names this sink for logs and errors, without its credentials.
	Describe() string
}

// Object is one stored object.
type Object struct {
	Name     string
	Size     int64
	Modified time.Time
}

// ErrNotFound is returned by Get for an object that is not there.
var ErrNotFound = errors.New("backup: no such object")

// ---- filesystem sink ----

// FileSink stores archives in a local directory.
//
// It is not a lesser sink for testing. A directory on a separate disk, an NFS
// mount, or a USB drive an operator rotates are all real backup targets for a
// single-node platform, and §15.3's requirement is that state leaves the
// process — not that it leaves the building. It is also the only sink a restore
// test can use in CI without a bucket.
type FileSink struct {
	root string
	log  *slog.Logger
}

// NewFileSink creates the directory if it does not exist.
func NewFileSink(root string, log *slog.Logger) (*FileSink, error) {
	if root == "" {
		return nil, errors.New("backup: a directory is required")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("backup: resolve %s: %w", root, err)
	}
	// 0700: an archive holds every secret on the node, and a backup directory
	// the rest of the machine can read is not a backup, it is a disclosure.
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("backup: create %s: %w", abs, err)
	}
	return &FileSink{root: abs, log: log}, nil
}

// Describe names the sink without exposing anything sensitive.
func (f *FileSink) Describe() string { return "file://" + f.root }

// resolve maps an object name onto a path inside the root.
//
// Object names come from manifests, and a manifest comes from the bucket — so
// on restore they are attacker-influenced. A name containing ".." must not be
// able to write outside the backup directory, which is why this checks the
// resolved path rather than trusting the join.
func (f *FileSink) resolve(name string) (string, error) {
	// Rejected rather than normalised. `path.Clean` would confine "../escaped"
	// to "escaped" — safe, but it means two different names address the same
	// object, and a manifest naming one part could then be made to overwrite
	// another. Every name this package generates is a plain `prefix/id.ext`, so
	// anything else is either a bug or an attempt.
	if name == "" || name != path.Clean(name) || path.IsAbs(name) ||
		strings.HasPrefix(name, "../") || strings.Contains(name, "\x00") {
		return "", fmt.Errorf("backup: invalid object name %q", name)
	}
	full := filepath.Join(f.root, filepath.FromSlash(name))
	// Belt and braces: the check above should make this unreachable, and it
	// stays because "unreachable" is a claim about today's code.
	if !strings.HasPrefix(full, f.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("backup: object name %q escapes the backup directory", name)
	}
	return full, nil
}

// Put writes an object atomically: a temporary file in the same directory, then
// a rename. A reader never sees a partial archive, and a crash mid-write leaves
// a temporary file rather than a corrupt one that looks complete.
func (f *FileSink) Put(_ context.Context, name string, _ int64, body io.Reader) (err error) {
	full, err := f.resolve(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return fmt.Errorf("backup: create %s: %w", filepath.Dir(full), err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(full), ".partial-*")
	if err != nil {
		return fmt.Errorf("backup: temp file: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		// The write already failed; this is only about not leaving litter. A
		// leftover .partial- file is inert — List skips them — so the failure
		// is logged rather than allowed to replace the error that matters.
		if rmErr := os.Remove(tmp.Name()); rmErr != nil {
			f.log.Warn("cannot remove a partial archive file",
				"path", tmp.Name(), "error", rmErr)
		}
	}()

	if err = tmp.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("backup: chmod: %w", err), tmp.Close())
	}
	if _, err = io.Copy(tmp, body); err != nil {
		return errors.Join(fmt.Errorf("backup: write %s: %w", name, err), tmp.Close())
	}
	// Synced before the rename. An archive that is visible but not on disk is
	// exactly the archive a restore will need after the power cut that lost it.
	if err = tmp.Sync(); err != nil {
		return errors.Join(fmt.Errorf("backup: sync %s: %w", name, err), tmp.Close())
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("backup: close %s: %w", name, err)
	}
	if err = os.Rename(tmp.Name(), full); err != nil {
		return fmt.Errorf("backup: publish %s: %w", name, err)
	}
	return nil
}

// Get opens an object.
func (f *FileSink) Get(_ context.Context, name string) (io.ReadCloser, error) {
	full, err := f.resolve(name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(full) // #nosec G304 — resolve confines the path to the sink root
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("backup: open %s: %w", name, err)
	}
	return file, nil
}

// List walks the directory, skipping partial writes.
func (f *FileSink) List(_ context.Context, prefix string) ([]Object, error) {
	var out []Object
	err := filepath.WalkDir(f.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(f.root, p)
		if relErr != nil {
			return relErr
		}
		name := filepath.ToSlash(rel)
		// A partial file is one a Put died in the middle of. It is not an
		// object and must never be offered as one.
		if strings.HasPrefix(filepath.Base(name), ".partial-") {
			return nil
		}
		if !strings.HasPrefix(name, prefix) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		out = append(out, Object{Name: name, Size: info.Size(), Modified: info.ModTime()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("backup: list %s: %w", f.root, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Delete removes an object, tolerating one that is already gone.
func (f *FileSink) Delete(_ context.Context, name string) error {
	full, err := f.resolve(name)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("backup: delete %s: %w", name, err)
	}
	return nil
}
