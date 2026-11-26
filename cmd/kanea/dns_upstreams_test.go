package main

import (
	"slices"
	"testing"
)

// The dns stanza's upstreams are the forwarding targets when it names any
// (v1.66). The resolv.conf fallback is deliberately not exercised here: it
// reads the host this test runs on.
//
// The v1.81 question stays pinned by the same assertion: keeping loopback in
// the resolv.conf fallback changed only what happens when nothing is
// configured. A stanza wins outright, including on the node whose
// resolv.conf holds only systemd-resolved's stub, which is exactly where the
// fallback differs.
func TestTheStanzaWinsOverTheHostsResolvers(t *testing.T) {
	for _, pinned := range [][]string{
		{"213.186.33.99"},
		{"10.0.0.53", "10.0.0.54:5353"},
	} {
		got, err := upstreamResolvers(pinned)
		if err != nil {
			t.Fatalf("stanza path: %v", err)
		}
		if !slices.Equal(got, pinned) {
			t.Fatalf("got %v, want the stanza's %v; the host's resolvers are the last resort", got, pinned)
		}
	}
}
