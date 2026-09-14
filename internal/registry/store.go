package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The content store: files under one 0700 root.
//
//	<dir>/blobs/sha256/<hex>                       content, digest-verified on the way in
//	<dir>/repos/<project>/<service>/manifests/<hex> marker: file body is the media type
//	<dir>/repos/<project>/<service>/tags/<tag>      file body is "sha256:<hex>"
//	<dir>/uploads/<id>                              in-flight sessions, wiped at boot
//
// Blobs are one global content-addressed set shared by every repository (which
// is what makes a cross-repo mount free); the repos tree records which
// repository references what. Everything here is derived, node-local state
// (§18 rules 5/7): never replicated, never backed up, rebuilt by rebuilding.

// Bounds (the attacker-chosen-keys rule): every caller-chosen name is shaped,
// and every collection a caller can grow is capped.
const (
	// maxUploads caps concurrent upload sessions; BuildKit's default push
	// parallelism sits well under it, and the §21 footprint term is this
	// number times an HTTP buffer.
	maxUploads = 8
	// uploadExpiry bounds an abandoned session's life, and doubles as the
	// orphan sweep's age guard: a blob younger than this may belong to a push
	// whose manifest has not landed yet.
	uploadExpiry = time.Hour
	// keepManifests is the per-repository retention (§5.2.14).
	keepManifests = 5
	// maxManifestBytes bounds a manifest PUT body. Real manifests are
	// kilobytes; four MiB is generous and still nothing like a blob.
	maxManifestBytes = 4 << 20
	// maxTags caps tags per repository.
	maxTags = 64
)

var (
	errTooManyUploads = errors.New("registry: too many concurrent uploads")
	errTooManyTags    = errors.New("registry: too many tags in this repository")
	errDigestMismatch = errors.New("registry: uploaded content does not match its declared digest")
)

// Name shapes. The label expression is DNS-1123, duplicated here rather than
// imported from jobspec (the CapabilityNone rule: matching a constant by
// import would point the dependency the wrong way). The tag expression is the
// distribution spec's.
var (
	labelRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagRE    = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func validLabel(s string) bool  { return labelRE.MatchString(s) }
func validTag(s string) bool    { return tagRE.MatchString(s) }
func validDigest(s string) bool { return digestRE.MatchString(s) }

// contentStore owns the files and the in-flight sessions.
type contentStore struct {
	dir string
	now func() time.Time

	mu      sync.Mutex
	uploads map[string]*upload
}

// upload is one in-flight blob session.
//
// The running hash lives here in memory, which is why a session does not
// survive a daemon restart: uploads/ is wiped at boot precisely because a
// half-written file whose hash state is gone can never verify.
type upload struct {
	id      string
	path    string
	created time.Time

	mu   sync.Mutex
	size int64
	hash hash.Hash
}

func newContentStore(dir string, now func() time.Time) (*contentStore, error) {
	for _, sub := range []string{
		filepath.Join(dir, "blobs", "sha256"),
		filepath.Join(dir, "repos"),
		filepath.Join(dir, "uploads"),
	} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			return nil, fmt.Errorf("registry: %s: %w", sub, err)
		}
	}
	// Wipe stranded sessions: their hash state died with the last process, so
	// they can never verify, and leaving them is leaving unverified bytes.
	entries, err := os.ReadDir(filepath.Join(dir, "uploads"))
	if err != nil {
		return nil, fmt.Errorf("registry: read uploads: %w", err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(dir, "uploads", entry.Name())); err != nil {
			return nil, fmt.Errorf("registry: clear stranded upload: %w", err)
		}
	}
	return &contentStore{dir: dir, now: now, uploads: map[string]*upload{}}, nil
}

// blobFile is where a digest's content lives.
func (s *contentStore) blobFile(dgst string) string {
	return filepath.Join(s.dir, "blobs", "sha256", strings.TrimPrefix(dgst, "sha256:"))
}

// statBlob reports a blob's size, or false.
func (s *contentStore) statBlob(dgst string) (int64, time.Time, bool) {
	fi, err := os.Stat(s.blobFile(dgst))
	if err != nil {
		return 0, time.Time{}, false
	}
	return fi.Size(), fi.ModTime(), true
}

// startUpload opens a session.
func (s *contentStore) startUpload() (*upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Expire abandoned sessions first, so a crashed client cannot hold the
	// cap forever.
	for id, u := range s.uploads {
		if s.now().Sub(u.created) > uploadExpiry {
			delete(s.uploads, id)
			_ = os.Remove(u.path) //nolint:errcheck // an expired session's file; the boot sweep is the backstop
		}
	}
	if len(s.uploads) >= maxUploads {
		return nil, errTooManyUploads
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("registry: upload id: %w", err)
	}
	id := hex.EncodeToString(raw)
	path := filepath.Join(s.dir, "uploads", id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304; a path this store composed from random hex
	if err != nil {
		return nil, fmt.Errorf("registry: open upload: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("registry: open upload: %w", err)
	}

	u := &upload{id: id, path: path, created: s.now(), hash: sha256.New()}
	s.uploads[id] = u
	return u, nil
}

// getUpload finds a live session.
func (s *contentStore) getUpload(id string) (*upload, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.uploads[id]
	return u, ok
}

// dropUpload forgets a session and removes its file.
func (s *contentStore) dropUpload(id string) {
	s.mu.Lock()
	u, ok := s.uploads[id]
	delete(s.uploads, id)
	s.mu.Unlock()
	if ok {
		_ = os.Remove(u.path) //nolint:errcheck // best-effort; the boot sweep is the backstop
	}
}

// append streams body bytes into the session, through the running hash.
func (u *upload) append(body io.Reader) (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	f, err := os.OpenFile(u.path, os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304; a path this store composed
	if err != nil {
		return u.size, fmt.Errorf("registry: open upload: %w", err)
	}
	n, err := io.Copy(io.MultiWriter(f, u.hash), body)
	u.size += n
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return u.size, fmt.Errorf("registry: write upload: %w", err)
	}
	return u.size, nil
}

// offset is how many bytes the session holds.
func (u *upload) offset() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.size
}

// commitUpload verifies the session against its declared digest and moves it
// into the blob set.
//
// A mismatch deletes the bytes (fail closed: unverified content never lands
// in blobs/). An already-present blob makes the commit a delete of the
// duplicate: an existing blob is never rewritten (the steady-state rule).
func (s *contentStore) commitUpload(u *upload, dgst string) error {
	u.mu.Lock()
	computed := "sha256:" + hex.EncodeToString(u.hash.Sum(nil))
	u.mu.Unlock()

	if computed != dgst {
		s.dropUpload(u.id)
		return fmt.Errorf("%w: declared %s, got %s", errDigestMismatch, dgst, computed)
	}

	target := s.blobFile(dgst)
	if _, err := os.Stat(target); err == nil {
		s.dropUpload(u.id)
		return nil
	}
	if err := os.Rename(u.path, target); err != nil {
		s.dropUpload(u.id)
		return fmt.Errorf("registry: commit blob: %w", err)
	}
	s.mu.Lock()
	delete(s.uploads, u.id)
	s.mu.Unlock()
	return nil
}

// repoDir is a repository's tree.
func (s *contentStore) repoDir(project, service string) string {
	return filepath.Join(s.dir, "repos", project, service)
}

// manifestMarker is where a repository records that it references a manifest.
func (s *contentStore) manifestMarker(project, service, dgst string) string {
	return filepath.Join(s.repoDir(project, service), "manifests", strings.TrimPrefix(dgst, "sha256:"))
}

// statManifest reports a referenced manifest's media type and size, or false.
func (s *contentStore) statManifest(project, service, dgst string) (string, int64, bool) {
	mediaType, err := os.ReadFile(s.manifestMarker(project, service, dgst)) // #nosec G304; every path segment is a validated label or hex
	if err != nil {
		return "", 0, false
	}
	size, _, ok := s.statBlob(dgst)
	if !ok {
		return "", 0, false
	}
	return string(mediaType), size, true
}

// resolveTag reads a tag, or false.
func (s *contentStore) resolveTag(project, service, tag string) (string, bool) {
	body, err := os.ReadFile(filepath.Join(s.repoDir(project, service), "tags", tag)) // #nosec G304; every path segment is a validated label or tag
	if err != nil {
		return "", false
	}
	dgst := strings.TrimSpace(string(body))
	if !validDigest(dgst) {
		return "", false
	}
	return dgst, true
}

// putManifest records a manifest under a repository, and under a tag when the
// push named one.
//
// The body must already be committed as a blob: the stored bytes are the
// digest's preimage and are returned verbatim on GET, because re-serialising
// a manifest changes its digest and breaks every pull of it.
func (s *contentStore) putManifest(project, service, dgst, mediaType, tag string) error {
	dir := s.repoDir(project, service)
	for _, sub := range []string{filepath.Join(dir, "manifests"), filepath.Join(dir, "tags")} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			return fmt.Errorf("registry: %s: %w", sub, err)
		}
	}

	marker := s.manifestMarker(project, service, dgst)
	if current, err := os.ReadFile(marker); err == nil && string(current) == mediaType { // #nosec G304; a path this store composed
		// Re-pushed unchanged: no write, but the retention window orders by
		// recency, and a manifest someone just pushed again is recent.
		if err := os.Chtimes(marker, s.now(), s.now()); err != nil {
			return fmt.Errorf("registry: refresh manifest: %w", err)
		}
	} else if err := writeFileAtomic(marker, []byte(mediaType)); err != nil {
		return err
	}

	if tag == "" {
		return nil
	}
	tagFile := filepath.Join(dir, "tags", tag)
	if current, err := os.ReadFile(tagFile); err == nil { // #nosec G304; a path this store composed from a validated tag
		if strings.TrimSpace(string(current)) == dgst {
			return nil
		}
	} else {
		entries, err := os.ReadDir(filepath.Join(dir, "tags"))
		if err != nil {
			return fmt.Errorf("registry: read tags: %w", err)
		}
		if len(entries) >= maxTags {
			return errTooManyTags
		}
	}
	return writeFileAtomic(tagFile, []byte(dgst))
}

// writeFileAtomic is temp-then-rename in the target's directory, so a reader
// never observes a half-written file.
func writeFileAtomic(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return fmt.Errorf("registry: write %s: %w", path, err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()           //nolint:errcheck // the write already failed
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup of a failed write
		return fmt.Errorf("registry: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup of a failed write
		return fmt.Errorf("registry: write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup of a failed write
		return fmt.Errorf("registry: write %s: %w", path, err)
	}
	return nil
}
