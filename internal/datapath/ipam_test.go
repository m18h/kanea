package datapath

import (
	"net/netip"
	"testing"
)

func TestReserveSkipsNetworkHostAndBroadcast(t *testing.T) {
	// /29: .0 network, .1 host anchor, .7 broadcast; usable is .2 through .6.
	p := newIPAM(netip.MustParsePrefix("10.0.0.0/29"))
	want := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	for i, w := range want {
		ip, err := p.Reserve(allocN(i))
		if err != nil {
			t.Fatalf("Reserve #%d: %v", i, err)
		}
		if ip.String() != w {
			t.Fatalf("Reserve #%d = %s, want %s", i, ip, w)
		}
	}
}

func TestReserveIsExhaustedNotWrapped(t *testing.T) {
	p := newIPAM(netip.MustParsePrefix("10.0.0.0/29"))
	for i := 0; i < 5; i++ {
		if _, err := p.Reserve(allocN(i)); err != nil {
			t.Fatalf("Reserve #%d: %v", i, err)
		}
	}
	if _, err := p.Reserve("one-too-many"); err == nil {
		t.Fatal("Reserve = nil beyond the pool, want exhaustion")
	}
}

func TestReserveIsStablePerAlloc(t *testing.T) {
	p := newIPAM(netip.MustParsePrefix("10.0.0.0/24"))
	first, err := p.Reserve("shop-web-0")
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.Reserve("shop-web-0")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("second Reserve = %s, want the existing %s", again, first)
	}
}

func TestReleaseFreesTheLowestAddressForReuse(t *testing.T) {
	p := newIPAM(netip.MustParsePrefix("10.0.0.0/24"))
	if _, err := p.Reserve("a-000"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve("b-000"); err != nil {
		t.Fatal(err)
	}
	p.Release("a-000")
	ip, err := p.Reserve("c-000")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.2" {
		t.Fatalf("Reserve after release = %s, want the freed 10.0.0.2", ip)
	}
}

func TestRebuildFromAliases(t *testing.T) {
	p := newIPAM(netip.MustParsePrefix("10.0.0.0/24"))
	p.Rebuild([]Link{
		{Name: "kn0011aabbccd", Alias: "kanea/shop-web-0/10.0.0.4"},
		{Name: "kn0011aabbcce", Alias: "kanea/shop-web-1/10.0.0.2"},
		// Everything below is not ours to account for.
		{Name: "eth0", Alias: "kanea/impostor-0/10.0.0.3"},          // foreign name
		{Name: "kn0011aabbccf", Alias: "veth-something"},            // foreign alias
		{Name: "kn0011aabbcd0", Alias: "kanea/other-0/192.168.1.9"}, // outside the pool
		{Name: "kn0011aabbcd1", Alias: "kanea//10.0.0.6"},           // empty alloc id
	})

	if got := p.Len(); got != 2 {
		t.Fatalf("rebuilt %d reservations, want 2", got)
	}
	if ip, ok := p.Lookup("shop-web-0"); !ok || ip.String() != "10.0.0.4" {
		t.Fatalf("shop-web-0 = %v (ok=%v), want 10.0.0.4", ip, ok)
	}
	// The lowest free is .3: .2 is re-reserved, .3 was only claimed by a
	// foreign link.
	ip, err := p.Reserve("new-000")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "10.0.0.3" {
		t.Fatalf("Reserve after rebuild = %s, want 10.0.0.3", ip)
	}
}

func TestParseAlias(t *testing.T) {
	cases := []struct {
		alias string
		id    string
		ip    string
		ip6   string
		ok    bool
	}{
		// The v4-only form must stay parseable forever: it is the durable
		// record written by nodes that predate v1.41.
		{"kanea/shop-web-0/10.0.0.4", "shop-web-0", "10.0.0.4", "", true},
		// The dual-stack form (v1.41).
		{"kanea/shop-web-0/10.0.0.4,fd10:244::4", "shop-web-0", "10.0.0.4", "fd10:244::4", true},
		{"kanea/shop-web-0/not-an-ip", "", "", "", false},
		// v6 cannot stand alone: v4 is the required family.
		{"kanea/shop-web-0/fd00::1", "", "", "", false},
		// A garbage v6 half fails the whole alias, not silently half of it.
		{"kanea/shop-web-0/10.0.0.4,not-an-ip", "", "", "", false},
		{"kanea/shop-web-0/10.0.0.4,10.0.0.5", "", "", "", false}, // two v4s is not dual-stack
		{"kanea//10.0.0.4", "", "", "", false},
		{"kanea/shop-web-0", "", "", "", false},
		{"veth-something", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, tc := range cases {
		id, ip, ip6, ok := parseAlias(tc.alias)
		if ok != tc.ok {
			t.Errorf("parseAlias(%q) ok = %v, want %v", tc.alias, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		got6 := ""
		if ip6.IsValid() {
			got6 = ip6.String()
		}
		if id != tc.id || ip.String() != tc.ip || got6 != tc.ip6 {
			t.Errorf("parseAlias(%q) = %s %s %s, want %s %s %s",
				tc.alias, id, ip, got6, tc.id, tc.ip, tc.ip6)
		}
	}
}

// The alias round-trips both forms, and a v4-only render is byte-identical
// to what a pre-v1.41 node wrote.
func TestAliasForRoundTrips(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.4")
	v6 := netip.MustParseAddr("fd10:244::4")

	if got := aliasFor("shop-web-0", v4, netip.Addr{}); got != "kanea/shop-web-0/10.0.0.4" {
		t.Errorf("v4-only alias = %q: the pre-v1.41 form changed", got)
	}
	id, ip, ip6, ok := parseAlias(aliasFor("shop-web-0", v4, v6))
	if !ok || id != "shop-web-0" || ip != v4 || ip6 != v6 {
		t.Errorf("dual alias round trip = %s %s %s (ok=%v)", id, ip, ip6, ok)
	}
}

func allocN(i int) string {
	return string(rune('a'+i)) + "-alloc"
}
