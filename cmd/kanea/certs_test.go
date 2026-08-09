package main

import (
	"testing"

	"github.com/m18h/kanea/internal/acme"
)

// The v1.32 default was Let's Encrypt *staging*, so a node configured entirely
// correctly served certificates every browser rejects. The aliases exist so an
// operator never has to paste a URL to get the right one.
func TestResolveDirectory(t *testing.T) {
	tests := []struct{ in, want string }{
		{DirectoryProduction, acme.LetsEncryptProduction},
		{DirectoryStaging, acme.LetsEncryptStaging},
		// A private or test CA is still just a URL, passed through untouched.
		{"https://ca.internal/acme/directory", "https://ca.internal/acme/directory"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := resolveDirectory(tc.in); got != tc.want {
			t.Errorf("resolveDirectory(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
