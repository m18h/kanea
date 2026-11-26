package main

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/m18h/kanea/internal/datapath"
	"github.com/m18h/kanea/internal/reconciler"
)

// The mode is the platform's, not the operator's: Linux is the only kernel
// with the datapath, and nothing else may select it.
func TestNetworkModeFollowsThePlatform(t *testing.T) {
	cases := []struct{ goos, want string }{
		{"linux", networkEBPF},
		{"darwin", networkNetns},
		{"freebsd", networkNetns},
		{"windows", networkNetns},
	}
	for _, c := range cases {
		if got := networkModeFor(c.goos); got != c.want {
			t.Errorf("networkModeFor(%q) = %q, want %q", c.goos, got, c.want)
		}
	}
}

// netns mode must not reach for the datapath: off Linux datapath.New refuses,
// and kanead would not start. An empty datapath.Config would fail New on
// Linux too, so this passes only if the mode never calls it.
func TestBuildNetworkNetnsNeverLoadsTheDatapath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	net, err := buildNetwork(context.Background(), networkNetns, datapath.Config{}, logger)
	if err != nil {
		t.Fatalf("buildNetwork(netns): %v", err)
	}
	if _, ok := net.(reconciler.NetnsNetwork); !ok {
		t.Fatalf("buildNetwork(netns) = %T, want reconciler.NetnsNetwork", net)
	}
}

// With no datapath there are no service frontends, so a resolver would serve
// an empty zone: netns mode has none, whatever dns.listen says.
func TestBuildDNSIsOffInNetnsMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dns, err := buildDNS(networkNetns, "", nil, netip.MustParsePrefix("10.244.0.0/24"), logger)
	if err != nil {
		t.Fatalf("buildDNS(netns): %v", err)
	}
	if dns != nil {
		t.Fatal("buildDNS(netns) built a resolver; want none")
	}
}
