// Package secrets stores credentials encrypted at rest (PRD §14, A02).
//
// Two properties shape everything here. Secrets are **referenced, never
// inlined** (§6.2, R3): a job spec names `secret:shop/db-password` and the
// value is resolved in-process at alloc start. And they are **write-only over
// the API** (§13.3, §16.3): an operator or an agent can set a secret and list
// what exists, but nothing outside this process can read a value back — so a
// compromised token cannot exfiltrate what it could only overwrite.
package secrets

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kanea-dev/kanea/internal/store"
)

// Prefix marks a secret reference in a job spec.
const Prefix = "secret:"

// SharedScope is the one namespace every project may read (R5).
const SharedScope = "shared"

// Errors callers distinguish.
var (
	// ErrNotFound means no secret exists at that path.
	ErrNotFound = errors.New("secrets: not found")
	// ErrInvalidPath marks a malformed reference.
	ErrInvalidPath = errors.New("secrets: invalid path")
	// ErrUndecryptable means the record exists but this key cannot open it —
	// almost always a master key that was replaced or restored from elsewhere.
	ErrUndecryptable = errors.New("secrets: cannot decrypt")
)

// record is one stored secret. The value is never held in plaintext here.
type record struct {
	// Nonce is unique per write. XChaCha20's 24-byte nonce is large enough to
	// be chosen randomly without birthday concerns, which is why it is used
	// rather than a counter that would have to survive restores.
	Nonce []byte `json:"nonce"`
	// Ciphertext includes the Poly1305 tag.
	Ciphertext []byte    `json:"ciphertext"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
}

// Info describes a secret without revealing it. This is what listing returns.
type Info struct {
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// Config configures a Store.
type Config struct {
	// Store persists the encrypted records.
	Store store.Store
	// KeyPath is the master key file. Generated on first use.
	KeyPath string
	Logger  *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
}

// Store reads and writes encrypted secrets.
type Store struct {
	store store.Store
	aead  interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
	log *slog.Logger
	now func() time.Time
}

// Open loads the master key and returns a usable store.
func Open(cfg Config) (*Store, error) {
	if cfg.Store == nil {
		return nil, errors.New("secrets: a store is required")
	}
	if cfg.KeyPath == "" {
		return nil, errors.New("secrets: a master key path is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	key, created, err := loadOrCreateKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	if created {
		// Said loudly because the escrow ceremony that makes this recoverable
		// is M10: right now, losing this file loses every secret and makes
		// every encrypted backup unreadable (§15.3).
		cfg.Logger.Warn("generated a new secrets master key",
			"path", cfg.KeyPath,
			"detail", "back this file up now — without it every stored secret and "+
				"every encrypted backup is unrecoverable (key escrow arrives with `kanea init`)")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyUnusable, err)
	}
	return &Store{store: cfg.Store, aead: aead, log: cfg.Logger, now: cfg.Now}, nil
}

// Put writes a secret, creating or replacing it.
func (s *Store) Put(ctx context.Context, secretPath string, value []byte) error {
	clean, err := CleanPath(secretPath)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		// An empty secret is almost always a shell pipeline that produced
		// nothing, and storing it would fail at alloc start with a far less
		// obvious error.
		return fmt.Errorf("%w: %s has no value", ErrInvalidPath, clean)
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("secrets: nonce: %w", err)
	}

	now := s.now()
	created := now
	if existing, err := s.load(ctx, clean); err == nil {
		created = existing.Created
	}

	// The path is authenticated data, not just a key: a ciphertext copied to
	// another path fails to open rather than silently becoming that other
	// secret's value.
	rec := record{
		Nonce:      nonce,
		Ciphertext: s.aead.Seal(nil, nonce, value, []byte(clean)),
		Created:    created,
		Updated:    now,
	}

	mut, err := store.PutMutation(store.KindSecret, clean, rec)
	if err != nil {
		return err
	}
	if _, err := s.store.Apply(ctx, mut); err != nil {
		return fmt.Errorf("secrets: write %s: %w", clean, err)
	}
	// The path is logged; the value never is (§6.2, R3).
	s.log.Info("secret written", "path", clean)
	return nil
}

// Resolve returns a secret's value.
//
// In-process only. Nothing reachable from the API calls this — that is what
// "write-only over the API" means, and it is enforced by not exposing a read
// route rather than by a permission check that could be misconfigured.
func (s *Store) Resolve(ctx context.Context, ref string) ([]byte, error) {
	clean, err := CleanPath(ref)
	if err != nil {
		return nil, err
	}
	rec, err := s.load(ctx, clean)
	if err != nil {
		return nil, err
	}

	value, err := s.aead.Open(nil, rec.Nonce, rec.Ciphertext, []byte(clean))
	if err != nil {
		// Authentication failure, not a decode error: the record was written
		// under a different key, or tampered with. Both mean "do not use this".
		return nil, fmt.Errorf("%w: %s (wrong master key, or the record was altered)",
			ErrUndecryptable, clean)
	}
	return value, nil
}

// Exists reports whether a secret is set, without decrypting it.
//
// Validation needs this — a spec referencing a secret that was never created
// should fail at plan time — and it must not require the ability to read.
func (s *Store) Exists(ctx context.Context, ref string) (bool, error) {
	clean, err := CleanPath(ref)
	if err != nil {
		return false, err
	}
	if _, err := s.load(ctx, clean); err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// List returns metadata for every secret under a prefix.
//
// Metadata, never values. This is the API's view of the store: an operator can
// see that `shop/db-password` exists and when it changed, which is what they
// need to manage it, and cannot see what it is.
func (s *Store) List(ctx context.Context, prefix string) ([]Info, error) {
	var out []Info
	opts := store.ListOptions{Prefix: prefix}
	for {
		page, err := s.store.List(ctx, store.KindSecret, opts)
		if err != nil {
			return nil, fmt.Errorf("secrets: list: %w", err)
		}
		for _, rec := range page.Records {
			var stored record
			if err := json.Unmarshal(rec.Value, &stored); err != nil {
				// One unreadable record must not hide every other secret from
				// an operator trying to work out what is wrong.
				s.log.Error("cannot decode secret metadata", "path", rec.Key, "error", err)
				continue
			}
			out = append(out, Info{Path: rec.Key, Created: stored.Created, Updated: stored.Updated})
		}
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// Delete removes a secret.
func (s *Store) Delete(ctx context.Context, secretPath string) error {
	clean, err := CleanPath(secretPath)
	if err != nil {
		return err
	}
	if _, err := s.load(ctx, clean); err != nil {
		return err
	}
	if _, err := s.store.Apply(ctx, store.DeleteMutation(store.KindSecret, clean)); err != nil {
		return fmt.Errorf("secrets: delete %s: %w", clean, err)
	}
	s.log.Info("secret deleted", "path", clean)
	return nil
}

// load reads one raw record.
func (s *Store) load(ctx context.Context, clean string) (record, error) {
	rec, err := s.store.Get(ctx, store.KindSecret, clean)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return record{}, fmt.Errorf("%w: %s", ErrNotFound, clean)
		}
		return record{}, fmt.Errorf("secrets: read %s: %w", clean, err)
	}
	var stored record
	if err := json.Unmarshal(rec.Value, &stored); err != nil {
		return record{}, fmt.Errorf("secrets: decode %s: %w", clean, err)
	}
	return stored, nil
}

// CleanPath validates a secret reference and returns its canonical path.
//
// Accepts both `secret:shop/db-password` and `shop/db-password`, because the
// first is what a job spec writes and the second is what an operator types.
func CleanPath(ref string) (string, error) {
	trimmed := strings.TrimSpace(ref)
	trimmed = strings.TrimPrefix(trimmed, Prefix)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty reference", ErrInvalidPath)
	}

	// Cleaned before checking rather than after: `shop/../etc/passwd` must be
	// rejected for what it resolves to, not accepted for how it is spelled.
	clean := path.Clean(trimmed)
	if clean != trimmed {
		return "", fmt.Errorf("%w: %q is not in its simplest form (%q)", ErrInvalidPath, ref, clean)
	}
	if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, ".") {
		return "", fmt.Errorf("%w: %q must be a relative path", ErrInvalidPath, ref)
	}

	parts := strings.Split(clean, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("%w: %q must be <project>/<name> or %s/<name>",
			ErrInvalidPath, ref, SharedScope)
	}
	for _, part := range parts {
		if err := checkSegment(part); err != nil {
			return "", fmt.Errorf("%w: %q: %w", ErrInvalidPath, ref, err)
		}
	}
	return clean, nil
}

// Scope returns the project (or "shared") a reference belongs to. R5 scoping is
// enforced at spec validation; this is what it reads.
func Scope(ref string) (string, error) {
	clean, err := CleanPath(ref)
	if err != nil {
		return "", err
	}
	scope, _, _ := strings.Cut(clean, "/")
	return scope, nil
}

// checkSegment keeps a path to characters that are safe in a filename, because
// secrets are injected as tmpfs files named after them (R3).
func checkSegment(part string) error {
	switch {
	case part == "":
		return errors.New("empty path segment")
	case len(part) > maxSegment:
		return fmt.Errorf("segment %q is longer than %d characters", part, maxSegment)
	}
	for _, r := range part {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if !ok {
			return fmt.Errorf("segment %q holds %q; use letters, digits, '-', '_' or '.'", part, r)
		}
	}
	return nil
}

const maxSegment = 64
