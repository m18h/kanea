package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyFileName is the master key's name under the data directory (PRD §14, A02).
const KeyFileName = "master.key"

// ErrKeyUnusable marks a master key that cannot be trusted.
var ErrKeyUnusable = errors.New("secrets: master key is unusable")

// loadOrCreateKey reads the master key, generating one on first use.
//
// The key is the whole of the encryption at rest: every secret in the Store is
// unreadable without it, and every secret is readable with it. Two consequences
// are enforced here rather than documented and hoped for: the file must not be
// readable by anyone else, and a key that exists is never silently replaced.
func loadOrCreateKey(path string) ([]byte, bool, error) {
	body, err := os.ReadFile(path) // #nosec G304; the path is operator configuration
	switch {
	case err == nil:
		if err := checkKeyPermissions(path); err != nil {
			return nil, false, err
		}
		if len(body) != chacha20poly1305.KeySize {
			// Refusing beats deriving something from whatever is there: a
			// truncated key file means the real one was lost, and pretending
			// otherwise would encrypt new secrets under a key nobody escrowed.
			return nil, false, fmt.Errorf("%w: %s holds %d bytes, want %d",
				ErrKeyUnusable, path, len(body), chacha20poly1305.KeySize)
		}
		return body, false, nil

	case errors.Is(err, fs.ErrNotExist):
		key, genErr := generateKey(path)
		return key, true, genErr

	default:
		return nil, false, fmt.Errorf("%w: read %s: %w", ErrKeyUnusable, path, err)
	}
}

// generateKey writes a new master key.
//
// Created with O_EXCL so two daemons racing on first start cannot each write a
// key and leave one of them encrypting under a key the other has overwritten.
func generateKey(path string) ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("%w: generate: %w", ErrKeyUnusable, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("%w: key directory: %w", ErrKeyUnusable, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304; operator configuration
	if err != nil {
		return nil, fmt.Errorf("%w: create %s: %w", ErrKeyUnusable, path, err)
	}
	defer func() {
		// Already closed on the success path; this covers the early returns.
		if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			// Nothing useful to do: the key is either written and synced, or
			// the caller is already returning the write error.
			_ = err
		}
	}()

	if _, err := f.Write(key); err != nil {
		return nil, fmt.Errorf("%w: write %s: %w", ErrKeyUnusable, path, err)
	}
	// Synced before anything is encrypted under it. A key lost to a power cut
	// after the first secret was written would make that secret permanently
	// unreadable, which is worse than failing to start.
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("%w: sync %s: %w", ErrKeyUnusable, path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("%w: close %s: %w", ErrKeyUnusable, path, err)
	}
	return key, nil
}

// checkKeyPermissions refuses a key file others can read.
//
// A master key at 0644 is not encryption at rest; it is a file everyone on the
// node can decrypt every secret with. Refusing to start is the right answer:
// continuing would mean the platform reports secrets as encrypted while they
// are effectively public.
func checkKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: stat %s: %w", ErrKeyUnusable, path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s is mode %04o; it must not be readable by group or other "+
			"(chmod 0600 %s)", ErrKeyUnusable, path, perm, path)
	}
	return nil
}

// LoadKey reads an existing master key, without creating one.
//
// The distinction from loadOrCreateKey matters at exactly one moment: a restore
// on a fresh node. Creating a key there would succeed, encrypt nothing, and
// leave the operator holding a node that cannot read a single one of its own
// backups, with no error to tell them why. So this refuses, and the message
// points at the ceremony that produced the key they need to put back.
func LoadKey(path string) ([]byte, error) {
	body, err := os.ReadFile(path) // #nosec G304; the path is operator configuration
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no master key at %s; restore the one escrowed by "+
			"`kanea init` before continuing (docs/DR_RUNBOOK.md starts with this step)",
			ErrKeyUnusable, path)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrKeyUnusable, path, err)
	}
	if err := checkKeyPermissions(path); err != nil {
		return nil, err
	}
	if len(body) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: %s holds %d bytes, want %d",
			ErrKeyUnusable, path, len(body), chacha20poly1305.KeySize)
	}
	return body, nil
}
