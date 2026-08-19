package main

import (
	"slices"
	"testing"
)

// The v1.51 precedence doctrine applied to DNS upstreams (v1.66): the flag
// wins, the server config's dns stanza otherwise. The resolv.conf fallback is
// deliberately not exercised here: it reads the host this test runs on.
func TestUpstreamResolversPrecedence(t *testing.T) {
	fromFile := []string{"10.0.0.53", "10.0.0.54:5353"}

	got, err := upstreamResolvers("1.1.1.1, 9.9.9.9", fromFile)
	if err != nil {
		t.Fatalf("flag path: %v", err)
	}
	if want := []string{"1.1.1.1", "9.9.9.9"}; !slices.Equal(got, want) {
		t.Fatalf("with a flag = %v, want %v; the flag wins", got, want)
	}

	got, err = upstreamResolvers("", fromFile)
	if err != nil {
		t.Fatalf("file path: %v", err)
	}
	if !slices.Equal(got, fromFile) {
		t.Fatalf("without a flag = %v, want the stanza's %v", got, fromFile)
	}
}

// The v1.81 question, pinned: keeping loopback in the resolv.conf fallback
// changed only what happens when nothing is configured. A stanza still wins
// outright — including on the node whose resolv.conf holds only
// systemd-resolved's stub, which is exactly where the fallback now differs.
func TestTheStanzaStillWinsOverTheHostsResolvers(t *testing.T) {
	pinned := []string{"213.186.33.99"}

	got, err := upstreamResolvers("", pinned)
	if err != nil {
		t.Fatalf("stanza path: %v", err)
	}
	if !slices.Equal(got, pinned) {
		t.Fatalf("got %v, want the stanza's %v; the host's resolvers are the last resort", got, pinned)
	}

	// And the stub the fallback now keeps never displaces a pinned value: the
	// only way to reach HostResolvers is for both earlier sources to be empty.
	if got, _ := upstreamResolvers("9.9.9.9", pinned); !slices.Equal(got, []string{"9.9.9.9"}) {
		t.Fatalf("the flag must still beat the stanza, got %v", got)
	}
}
