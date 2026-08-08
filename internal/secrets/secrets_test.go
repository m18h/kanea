package secrets_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/store"
)

func newStore(t *testing.T) (*secrets.Store, string, store.Store) {
	t.Helper()

	dir := t.TempDir()
	st, err := store.Open(store.Options{Path: filepath.Join(dir, "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keyPath := filepath.Join(dir, secrets.KeyFileName)
	s, err := secrets.Open(secrets.Config{Store: st, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("open secrets: %v", err)
	}
	return s, keyPath, st
}

func TestPutAndResolveRoundTrip(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "shop/db-password", []byte("hunter2")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Resolve(ctx, "shop/db-password")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "hunter2" {
		t.Errorf("Resolve = %q", got)
	}

	// A job spec writes the prefixed form; both must reach the same secret.
	got, err = s.Resolve(ctx, "secret:shop/db-password")
	if err != nil || string(got) != "hunter2" {
		t.Errorf("Resolve(prefixed) = %q, %v", got, err)
	}
}

// The point of encryption at rest: the value must not be recoverable from the
// database without the master key.
func TestValuesAreNotStoredInPlaintext(t *testing.T) {
	s, _, raw := newStore(t)
	ctx := context.Background()

	const value = "a-very-distinctive-secret-value"
	if err := s.Put(ctx, "shop/token", []byte(value)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rec, err := raw.Get(ctx, store.KindSecret, "shop/token")
	if err != nil {
		t.Fatalf("read raw record: %v", err)
	}
	if strings.Contains(string(rec.Value), value) {
		t.Fatal("the plaintext value is present in the stored record")
	}
}

// Listing is the API's view. It must show that a secret exists and never what
// it is (PRD §13.3, §16.3).
func TestListReturnsMetadataOnly(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "shop/one", []byte("value-one")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(ctx, "shop/two", []byte("value-two")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	infos, err := s.List(ctx, "shop/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(infos))
	}
	for _, info := range infos {
		if info.Path == "" || info.Updated.IsZero() {
			t.Errorf("incomplete metadata: %+v", info)
		}
	}
	// The Info type carries no value field at all, which is the enforcement:
	// there is nothing to accidentally serialise.
}

// A ciphertext moved to another path must not open. Without the path as
// authenticated data, copying a record would silently rename a secret's value.
func TestCiphertextIsBoundToItsPath(t *testing.T) {
	s, _, raw := newStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "shop/real", []byte("shop-value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rec, err := raw.Get(ctx, store.KindSecret, "shop/real")
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Copy the encrypted record to a different path.
	mut, err := store.PutRawMutation(store.KindSecret, "other/stolen", rec.Value)
	if err != nil {
		t.Fatalf("mutation: %v", err)
	}
	if _, err := raw.Apply(ctx, mut); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if _, err := s.Resolve(ctx, "other/stolen"); !errors.Is(err, secrets.ErrUndecryptable) {
		t.Fatalf("Resolve of a moved record = %v, want ErrUndecryptable", err)
	}
}

// A different master key must not open existing records — that is what makes
// the key worth escrowing.
func TestADifferentKeyCannotDecrypt(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Path: filepath.Join(dir, "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keyPath := filepath.Join(dir, "master.key")
	first, err := secrets.Open(secrets.Config{Store: st, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	if err := first.Put(ctx, "shop/token", []byte("value")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Simulate the key being lost and regenerated.
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	second, err := secrets.Open(secrets.Config{Store: st, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if _, err := second.Resolve(ctx, "shop/token"); !errors.Is(err, secrets.ErrUndecryptable) {
		t.Fatalf("Resolve with a new key = %v, want ErrUndecryptable", err)
	}
	// And the record is still listed, so an operator can see what they lost
	// rather than finding the secrets silently gone.
	infos, err := second.List(ctx, "")
	if err != nil || len(infos) != 1 {
		t.Errorf("List = %v, %v; the record should still be visible", infos, err)
	}
}

// A key file others can read is not encryption at rest.
func TestOpenRefusesAWorldReadableKey(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Path: filepath.Join(dir, "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keyPath := filepath.Join(dir, "master.key")
	if _, err := secrets.Open(secrets.Config{Store: st, KeyPath: keyPath}); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err = secrets.Open(secrets.Config{Store: st, KeyPath: keyPath})
	if !errors.Is(err, secrets.ErrKeyUnusable) {
		t.Fatalf("Open with a 0644 key = %v, want ErrKeyUnusable", err)
	}
	if !strings.Contains(err.Error(), "chmod 0600") {
		t.Errorf("error %v does not say how to fix it", err)
	}
}

// A truncated key means the real one was lost. Deriving something from what is
// left would encrypt new secrets under a key nobody escrowed.
func TestOpenRefusesATruncatedKey(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Path: filepath.Join(dir, "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("too short"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := secrets.Open(secrets.Config{Store: st, KeyPath: keyPath}); !errors.Is(err, secrets.ErrKeyUnusable) {
		t.Fatalf("Open = %v, want ErrKeyUnusable", err)
	}
}

func TestExistsDoesNotRequireDecryption(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "shop/token", []byte("value")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err := s.Exists(ctx, "secret:shop/token")
	if err != nil || !ok {
		t.Errorf("Exists = %v, %v", ok, err)
	}
	ok, err = s.Exists(ctx, "shop/absent")
	if err != nil || ok {
		t.Errorf("Exists(absent) = %v, %v", ok, err)
	}
}

func TestDelete(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "shop/token", []byte("value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "shop/token"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Resolve(ctx, "shop/token"); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Resolve after delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "shop/token"); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		name, in, want string
		ok             bool
	}{
		{"project scoped", "shop/db-password", "shop/db-password", true},
		{"prefixed", "secret:shop/db-password", "shop/db-password", true},
		{"shared", "shared/registry", "shared/registry", true},
		{"nested", "shop/db/password", "shop/db/password", true},
		{"dots in a name", "shop/tls.key", "shop/tls.key", true},

		{"empty", "", "", false},
		{"no scope", "password", "", false},
		// Rejected for what it resolves to, not for how it is spelled.
		{"traversal", "shop/../etc/passwd", "", false},
		{"absolute", "/shop/password", "", false},
		{"leading dot", "./shop/password", "", false},
		{"empty segment", "shop//password", "", false},
		{"space", "shop/db password", "", false},
		{"slash injection", "shop/a\\b", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := secrets.CleanPath(tc.in)
			if tc.ok != (err == nil) {
				t.Fatalf("CleanPath(%q) = %q, %v; want ok=%v", tc.in, got, err, tc.ok)
			}
			if tc.ok && got != tc.want {
				t.Errorf("CleanPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestScope(t *testing.T) {
	for in, want := range map[string]string{
		"shop/db-password":        "shop",
		"secret:shop/db-password": "shop",
		"shared/registry":         "shared",
	} {
		got, err := secrets.Scope(in)
		if err != nil || got != want {
			t.Errorf("Scope(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// An empty value is almost always a shell pipeline that produced nothing, and
// storing it would fail much later with a far less obvious error.
func TestPutRefusesAnEmptyValue(t *testing.T) {
	s, _, _ := newStore(t)
	if err := s.Put(context.Background(), "shop/token", nil); err == nil {
		t.Fatal("an empty secret was accepted")
	}
}

// Rewriting keeps the creation time, so "when was this first set" survives a
// rotation.
func TestPutPreservesCreationTime(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "shop/token", []byte("first")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before, err := s.List(ctx, "shop/")
	if err != nil || len(before) != 1 {
		t.Fatalf("List: %v %v", before, err)
	}

	if err := s.Put(ctx, "shop/token", []byte("second")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	after, err := s.List(ctx, "shop/")
	if err != nil || len(after) != 1 {
		t.Fatalf("List: %v %v", after, err)
	}

	if !after[0].Created.Equal(before[0].Created) {
		t.Errorf("Created changed on rewrite: %v -> %v", before[0].Created, after[0].Created)
	}
	value, err := s.Resolve(ctx, "shop/token")
	if err != nil || string(value) != "second" {
		t.Errorf("Resolve = %q, %v; want the new value", value, err)
	}
}
