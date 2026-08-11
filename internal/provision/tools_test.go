package provision

import (
	"os"
	"path/filepath"
	"testing"
)

// A stock Debian box handed `kanea init` a PATH without /usr/sbin, and the
// install failed over a useradd that was sitting right there. PATH is an
// environment variable, not a statement about what is installed — these tests
// pin the fallback that closes that gap.
func TestLookupToolFallsBackToSbinDirs(t *testing.T) {
	writeExecutable := func(t *testing.T, dir, name string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := []struct {
		name  string
		setup func(t *testing.T) (onPath, fallback string) // dirs for PATH and the fallback list
		want  func(onPath, fallback string) string         // "" means an error is expected
	}{
		{
			name: "PATH wins when the tool is on it",
			setup: func(t *testing.T) (string, string) {
				onPath, fallback := t.TempDir(), t.TempDir()
				writeExecutable(t, onPath, "kanea-testtool", 0o755)
				writeExecutable(t, fallback, "kanea-testtool", 0o755)
				return onPath, fallback
			},
			want: func(onPath, _ string) string { return filepath.Join(onPath, "kanea-testtool") },
		},
		{
			name: "found in a fallback dir when PATH misses it",
			setup: func(t *testing.T) (string, string) {
				fallback := t.TempDir()
				writeExecutable(t, fallback, "kanea-testtool", 0o755)
				return t.TempDir(), fallback
			},
			want: func(_, fallback string) string { return filepath.Join(fallback, "kanea-testtool") },
		},
		{
			name: "a non-executable file is not a tool",
			setup: func(t *testing.T) (string, string) {
				fallback := t.TempDir()
				writeExecutable(t, fallback, "kanea-testtool", 0o644)
				return t.TempDir(), fallback
			},
			want: func(_, _ string) string { return "" },
		},
		{
			name: "a directory with the right name is not a tool",
			setup: func(t *testing.T) (string, string) {
				fallback := t.TempDir()
				if err := os.Mkdir(filepath.Join(fallback, "kanea-testtool"), 0o755); err != nil {
					t.Fatal(err)
				}
				return t.TempDir(), fallback
			},
			want: func(_, _ string) string { return "" },
		},
		{
			name: "missing everywhere is an error",
			setup: func(t *testing.T) (string, string) {
				return t.TempDir(), t.TempDir()
			},
			want: func(_, _ string) string { return "" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			onPath, fallback := tt.setup(t)
			t.Setenv("PATH", onPath)
			got, err := lookupToolIn("kanea-testtool", []string{fallback})
			want := tt.want(onPath, fallback)
			if want == "" {
				if err == nil {
					t.Fatalf("lookupToolIn returned %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("lookupToolIn: %v", err)
			}
			if got != want {
				t.Errorf("lookupToolIn = %q, want %q", got, want)
			}
		})
	}
}
