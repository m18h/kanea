package datapath

import (
	"net/netip"
	"testing"
)

func TestReserveSkipsNetworkHostAndBroadcast(t *testing.T) {
	// /29: .0 network, .1 host anchor, .7 broadcast — usable is .2 through .6.
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
		ok    bool
	}{
		{"kanea/shop-web-0/10.0.0.4", "shop-web-0", "10.0.0.4", true},
		{"kanea/shop-web-0/not-an-ip", "", "", false},
		{"kanea/shop-web-0/fd00::1", "", "", false}, // v6 is not a v1 attachment
		{"kanea//10.0.0.4", "", "", false},
		{"kanea/shop-web-0", "", "", false},
		{"veth-something", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		id, ip, ok := parseAlias(tc.alias)
		if ok != tc.ok {
			t.Errorf("parseAlias(%q) ok = %v, want %v", tc.alias, ok, tc.ok)
			continue
		}
		if ok && (id != tc.id || ip.String() != tc.ip) {
			t.Errorf("parseAlias(%q) = %s %s, want %s %s", tc.alias, id, ip, tc.id, tc.ip)
		}
	}
}

func allocN(i int) string {
	return string(rune('a'+i)) + "-alloc"
}
