package main

import (
	"slices"
	"testing"
)

// The v1.51 precedence doctrine applied to DNS upstreams (v1.66): the flag
// wins, the server config's dns stanza otherwise. The resolv.conf fallback is
// deliberately not exercised here — it reads the host this test runs on.
func TestUpstreamResolversPrecedence(t *testing.T) {
	fromFile := []string{"10.0.0.53", "10.0.0.54:5353"}

	got, err := upstreamResolvers("1.1.1.1, 9.9.9.9", fromFile)
	if err != nil {
		t.Fatalf("flag path: %v", err)
	}
	if want := []string{"1.1.1.1", "9.9.9.9"}; !slices.Equal(got, want) {
		t.Fatalf("with a flag = %v, want %v — the flag wins", got, want)
	}

	got, err = upstreamResolvers("", fromFile)
	if err != nil {
		t.Fatalf("file path: %v", err)
	}
	if !slices.Equal(got, fromFile) {
		t.Fatalf("without a flag = %v, want the stanza's %v", got, fromFile)
	}
}
