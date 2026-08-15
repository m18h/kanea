package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The zero value permits nothing. A host volume must do nothing at all until an
// operator has named a directory — the driver being available is not consent.
func TestHostPathPolicyIsClosedByDefault(t *testing.T) {
	var policy HostPathPolicy

	if policy.Enabled() {
		t.Error("the zero policy reports itself as enabled")
	}
	_, err := policy.Resolve("/srv/anything")
	if !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("Resolve = %v, want ErrHostPathNotAllowed", err)
	}
	if !strings.Contains(err.Error(), "allowed_host_paths") {
		t.Errorf("error %v does not say how to enable it", err)
	}
}

func TestHostPathPolicyAllowsConfiguredDirectories(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "config")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	policy, err := NewHostPathPolicy([]string{root})
	if err != nil {
		t.Fatalf("NewHostPathPolicy: %v", err)
	}

	for _, path := range []string{root, child} {
		resolved, err := policy.Resolve(path)
		if err != nil {
			t.Fatalf("Resolve(%q) = %v, want nil", path, err)
		}
		if resolved == "" {
			t.Errorf("Resolve(%q) returned an empty path", path)
		}
	}
}

// The escape that a string-prefix check would miss.
func TestHostPathPolicyRefusesASiblingWithASharedPrefix(t *testing.T) {
	parent := t.TempDir()
	allowed := filepath.Join(parent, "data")
	sibling := filepath.Join(parent, "database") // shares the "data" prefix
	for _, dir := range []string{allowed, sibling} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatalf("NewHostPathPolicy: %v", err)
	}
	if _, err := policy.Resolve(sibling); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("Resolve(%q) = %v; a shared string prefix is not containment", sibling, err)
	}
}

// The escape that checking the spelling instead of the destination would miss:
// a symlink inside an allowed directory pointing anywhere on the node.
func TestHostPathPolicyFollowsSymlinksBeforeChecking(t *testing.T) {
	parent := t.TempDir()
	allowed := filepath.Join(parent, "allowed")
	secret := filepath.Join(parent, "secret")
	for _, dir := range []string{allowed, secret} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	escape := filepath.Join(allowed, "escape")
	if err := os.Symlink(secret, escape); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatalf("NewHostPathPolicy: %v", err)
	}

	// The path *looks* like it is inside the allowed directory. It is not.
	if _, err := policy.Resolve(escape); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("Resolve(%q) = %v; a symlink out of the allowlist must be refused", escape, err)
	}
}

// Creating the directory on demand turns a typo into a volume that is silently
// empty — the failure PRD §8 spends most of its words on.
func TestHostPathPolicyRefusesAMissingDirectory(t *testing.T) {
	root := t.TempDir()
	policy, err := NewHostPathPolicy([]string{root})
	if err != nil {
		t.Fatalf("NewHostPathPolicy: %v", err)
	}

	missing := filepath.Join(root, "typo")
	_, err = policy.Resolve(missing)
	if !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("Resolve = %v, want a refusal", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error %v does not explain that the directory is missing", err)
	}
	if _, statErr := os.Stat(missing); statErr == nil {
		t.Error("the missing directory was created")
	}
}

// Bind-mounting a socket — /run/containerd/containerd.sock being the one that
// matters — is a full node takeover, so only directories are accepted.
func TestHostPathPolicyRefusesNonDirectories(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "containerd.sock")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	policy, err := NewHostPathPolicy([]string{root})
	if err != nil {
		t.Fatalf("NewHostPathPolicy: %v", err)
	}
	if _, err := policy.Resolve(file); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("Resolve(%q) = %v, want a refusal", file, err)
	}
}

// An allowlist entry of "/" would permit every path on the node and turn the
// control into a formality, so it is refused at construction rather than
// quietly accepted.
func TestNewHostPathPolicyRefusesRoot(t *testing.T) {
	for _, prefix := range []string{"/", "//", "/."} {
		if _, err := NewHostPathPolicy([]string{prefix}); err == nil {
			t.Errorf("NewHostPathPolicy(%q) = nil, want a refusal", prefix)
		}
	}
}

func TestNewHostPathPolicyRefusesRelativeAndMissingPrefixes(t *testing.T) {
	if _, err := NewHostPathPolicy([]string{"srv/data"}); err == nil {
		t.Error("accepted a relative prefix")
	}
	if _, err := NewHostPathPolicy([]string{filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Error("accepted a prefix that does not exist")
	}
}

func TestNewHostPathPolicyIgnoresBlankEntries(t *testing.T) {
	root := t.TempDir()
	policy, err := NewHostPathPolicy([]string{"", "  ", root})
	if err != nil {
		t.Fatalf("NewHostPathPolicy: %v", err)
	}
	if len(policy.Allowed()) != 1 {
		t.Fatalf("allowed = %v, want just the real entry", policy.Allowed())
	}
}

func TestWithinPrefix(t *testing.T) {
	tests := []struct {
		path, prefix string
		want         bool
	}{
		{"/srv/data", "/srv/data", true},
		{"/srv/data/sub", "/srv/data", true},
		{"/srv/data/sub", "/srv/data/", true},
		{"/srv/database", "/srv/data", false},
		{"/srv", "/srv/data", false},
		{"/other", "/srv/data", false},
	}
	for _, tc := range tests {
		if got := withinPrefix(tc.path, tc.prefix); got != tc.want {
			t.Errorf("withinPrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

// --- create = true (R15, PRD v1.69) ---

func TestResolveOrCreateMakesADirectoryInsideAnAllowedPrefix(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "srv")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(allowed, "media", "plex")
	got, err := policy.ResolveOrCreate(want, true)
	if err != nil {
		t.Fatalf("ResolveOrCreate: %v", err)
	}
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat the created directory: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("%s is not a directory", got)
	}
}

// The check that carries the whole security argument: the allowlist is
// consulted against the nearest existing ancestor BEFORE anything is created,
// so a refused path must leave nothing behind.
func TestResolveOrCreateRefusesOutsideThePrefixWithoutCreating(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "srv")
	elsewhere := filepath.Join(root, "elsewhere")
	for _, dir := range []string{allowed, elsewhere} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}

	forbidden := filepath.Join(elsewhere, "data")
	if _, err := policy.ResolveOrCreate(forbidden, true); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("error = %v, want ErrHostPathNotAllowed", err)
	}
	if _, err := os.Stat(forbidden); !os.IsNotExist(err) {
		t.Errorf("%s was created despite being refused", forbidden)
	}
}

// A symlinked ancestor pointing out of the allowlist is the escape the
// resolution order exists to close — and it has to be closed on the create
// path too, where the target itself cannot be resolved because it is absent.
func TestResolveOrCreateRefusesASymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "srv")
	secret := filepath.Join(root, "secret")
	for _, dir := range []string{allowed, secret} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secret, filepath.Join(allowed, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}

	escape := filepath.Join(allowed, "link", "data")
	if _, err := policy.ResolveOrCreate(escape, true); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("error = %v, want ErrHostPathNotAllowed", err)
	}
	if _, err := os.Stat(filepath.Join(secret, "data")); !os.IsNotExist(err) {
		t.Error("a directory was created through a symlink out of the allowlist")
	}
}

// Without the flag, nothing changes. R15's default is the whole point.
func TestResolveOrCreateWithoutCreateIsUnchanged(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "srv")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(allowed, "nope")
	if _, err := policy.ResolveOrCreate(missing, false); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("error = %v, want ErrHostPathNotAllowed", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("a directory was created with create = false")
	}
}

// An existing directory takes the ordinary path, so create is not a way to
// bypass any of Resolve's checks.
func TestResolveOrCreateOnAnExistingPathIsJustResolve(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "srv")
	file := filepath.Join(allowed, "afile")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := NewHostPathPolicy([]string{allowed})
	if err != nil {
		t.Fatal(err)
	}

	// A file is not a directory, and create must not change that verdict.
	if _, err := policy.ResolveOrCreate(file, true); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Errorf("error = %v, want ErrHostPathNotAllowed for a file", err)
	}
}

func TestResolveOrCreateRefusesWhenNoPrefixIsConfigured(t *testing.T) {
	var policy HostPathPolicy // the zero value permits nothing
	dir := filepath.Join(t.TempDir(), "data")

	if _, err := policy.ResolveOrCreate(dir, true); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Fatalf("error = %v, want ErrHostPathNotAllowed", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("a directory was created with no allowlist at all")
	}
}
