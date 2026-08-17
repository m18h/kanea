//go:build linux

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// K-20: the pin, not the mount, is where the race is lost or won, and it
// needs no privileges to verify.
func TestPinHostRefusesASymlinkedPath(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "data")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	// The pinned object must be the real directory; a symlink in the path -
	// the swap a workload would race in - is refused outright.
	if _, err := pinHost(link, []string{root}); err == nil {
		t.Fatal("a symlinked path was pinned")
	}

	fd, err := pinHost(realDir, []string{root})
	if err != nil {
		t.Fatalf("pin the real directory: %v", err)
	}
	defer func() { _ = os.NewFile(uintptr(fd), "pinned").Close() }()

	// And a directory outside every allowed prefix is refused even though it
	// exists and is real: the fd's own path is what the allowlist answers.
	outside := t.TempDir()
	if _, err := pinHost(outside, []string{root}); !errors.Is(err, ErrHostPathNotAllowed) {
		t.Errorf("pin outside the allowlist = %v, want ErrHostPathNotAllowed", err)
	}
}
