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
