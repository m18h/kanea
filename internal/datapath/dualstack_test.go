package datapath

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// Dual-stack (PRD v1.41): the v6 half rides inside the existing attach steps,
// the alias is the one durable record for both families, and a live upgrade
// adopts a v4-only attachment rather than re-plumbing a running workload.

// newDualStackFixture is newFixture with the v6 trio configured.
func newDualStackFixture(t *testing.T) *fixture {
	t.Helper()
	log := &oplog{}
	f := &fixture{
		log:   log,
		nl:    newFakeNl(log),
		maps:  newFakeMaps(log),
		netns: newFakeNetns(log),
		store: newFakeStore(),
	}
	d, err := newDatapath(Config{
		NodeCIDR:     netip.MustParsePrefix("10.200.0.0/24"),
		ClusterCIDR:  netip.MustParsePrefix("10.200.0.0/16"),
		ServiceCIDR:  netip.MustParsePrefix("10.201.0.0/16"),
		NodeCIDR6:    netip.MustParsePrefix("fd10:244::/64"),
		ClusterCIDR6: netip.MustParsePrefix("fd10:244::/56"),
		ServiceCIDR6: netip.MustParsePrefix("fd10:245::/64"),
		Store:        f.store,
	}, seams{
		nl:    f.nl,
		maps:  f.maps,
		fw:    fakeFw{log: log},
		netns: f.netns,
	})
	if err != nil {
		t.Fatalf("newDatapath: %v", err)
	}
	f.d = d
	return f
}

// The trio is all-or-nothing: a v6 alloc address without a v6 VIP pool is a
// half-configured stack whose failures are silent, so it is refused by name.
func TestV6TrioIsAllOrNothing(t *testing.T) {
	base := Config{
		NodeCIDR:    netip.MustParsePrefix("10.200.0.0/24"),
		ClusterCIDR: netip.MustParsePrefix("10.200.0.0/16"),
		ServiceCIDR: netip.MustParsePrefix("10.201.0.0/16"),
		Store:       newFakeStore(),
	}

	one := base
	one.NodeCIDR6 = netip.MustParsePrefix("fd10:244::/64")
	if _, err := newDatapath(one, seams{}); err == nil || !strings.Contains(err.Error(), "trio") {
		t.Errorf("one v6 flag = %v, want the all-or-nothing refusal", err)
	}

	two := one
	two.ClusterCIDR6 = netip.MustParsePrefix("fd10:244::/56")
	if _, err := newDatapath(two, seams{}); err == nil || !strings.Contains(err.Error(), "trio") {
		t.Errorf("two v6 flags = %v, want the all-or-nothing refusal", err)
	}

	// A v4 prefix in a *6 flag is a typo worth naming.
	bad := base
	bad.NodeCIDR6 = netip.MustParsePrefix("10.99.0.0/24")
	bad.ClusterCIDR6 = netip.MustParsePrefix("fd10:244::/56")
	bad.ServiceCIDR6 = netip.MustParsePrefix("fd10:245::/64")
	if _, err := newDatapath(bad, seams{}); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("v4 prefix in a *6 flag = %v, want an IPv6 refusal", err)
	}
}

// Init on a dual-stack node: the host anchor carries both addresses, both
// host identities land before anything can pass traffic, and config6 carries
// the real service CIDR6 instead of the disabled zero.
func TestDualStackInit(t *testing.T) {
	f := newDualStackFixture(t)
	if err := f.d.Init(t.Context()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	want := []string{
		"ensure-host 10.200.0.1 fd10:244::1",
		"put-identity 10.200.0.1",
		"put-identity fd10:244::1",
		"set-config",
		"set-config6",
		"masquerade 10.200.0.0/16 via " + HostInterface,
	}
	if got := f.log.taken(); !slices.Equal(got, want) {
		t.Fatalf("init steps = %v, want %v", got, want)
	}

	id, ok := f.maps.idents[netip.MustParseAddr("fd10:244::1")]
	if !ok || id.Flags&dpmap.IdentityFlagHost == 0 {
		t.Fatalf("v6 host identity = %+v (present=%v), want the host flag set", id, ok)
	}
	wantCfg := dpmap.Config6{
		ServiceCIDRNet:  netip.MustParseAddr("fd10:245::").As16(),
		ServiceCIDRMask: maskFor16(netip.MustParsePrefix("fd10:245::/64")),
	}
	if f.maps.cfg6 != wantCfg {
		t.Errorf("config6 = %+v, want %+v", f.maps.cfg6, wantCfg)
	}
}

// A v4-only node writes the all-zero config6 — the disabled switch — so a
// pinned map left by an earlier dual-stack process cannot keep meaning "on".
func TestV4OnlyInitDisablesConfig6(t *testing.T) {
	f := newFixture(t)
	if err := f.d.Init(t.Context()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if f.maps.cfg6 != (dpmap.Config6{}) {
		t.Errorf("config6 on a v4-only node = %+v, want all-zero (disabled)", f.maps.cfg6)
	}
}

// The dual-stack attach: both identities before the veth, both families in
// the peer configuration, both host routes last, and the alias carrying both
// addresses.
func TestDualStackAttachOrdering(t *testing.T) {
	f := newDualStackFixture(t)
	attach(t, f)

	host := hostDevName(testSpec.ID)
	want := []string{
		"put-identity 10.200.0.2",
		"put-identity fd10:244::2",
		"create-veth " + host,
		"attach-programs " + host,
		"netns-create " + testSpec.ID,
		"move-peer " + host + "p",
		"configure-peer 10.200.0.2 fd10:244::2",
		"set-host-up " + host,
		"install-route 10.200.0.2",
		"install-route fd10:244::2",
	}
	if got := f.log.taken(); !slices.Equal(got, want) {
		t.Fatalf("attach steps = %v, want %v", got, want)
	}

	link, ok := f.nl.link[host]
	if !ok {
		t.Fatal("no link created")
	}
	id, ip, ip6, ok := parseAlias(link.Alias)
	if !ok || id != testSpec.ID || ip.String() != "10.200.0.2" || ip6.String() != "fd10:244::2" {
		t.Fatalf("alias = %q (parsed %s %s %s), want both families", link.Alias, id, ip, ip6)
	}
}

// The upgrade matrix (v1.41): a v4-only alias with its identity present is a
// COMPLETE pre-dual-stack attachment. Enabling v6 must adopt it — never
// re-plumb, because that yanks the veth under a running workload. The alloc
// gains v6 at its next replacement.
func TestV4OnlyAttachmentIsAdoptedNotReplumbed(t *testing.T) {
	f := newDualStackFixture(t)

	ip := netip.MustParseAddr("10.200.0.2")
	f.nl.addLink(hostDevName(testSpec.ID), aliasFor(testSpec.ID, ip, netip.Addr{}))
	// Seed the identity the way the pre-upgrade attach left it.
	projectID, err := f.d.ids.ProjectID(t.Context(), testSpec.Project)
	if err != nil {
		t.Fatal(err)
	}
	serviceID, err := f.d.ids.ServiceID(t.Context(), testSpec.Project, testSpec.Service)
	if err != nil {
		t.Fatal(err)
	}
	f.maps.idents[ip] = dpmap.Identity{ProjectID: projectID, ServiceID: serviceID}
	f.log.reset()

	attach(t, f)

	for _, step := range f.log.taken() {
		for _, forbidden := range []string{"delete-veth", "create-veth", "configure-peer"} {
			if strings.HasPrefix(step, forbidden) {
				t.Fatalf("the adopt re-plumbed: %v", f.log.taken())
			}
		}
	}
	if got, ok := f.d.ipam.Lookup(testSpec.ID); !ok || got != ip {
		t.Errorf("v4 reservation = %v (ok=%v), want adopted 10.200.0.2", got, ok)
	}
	if got, ok := f.d.ipam6.Lookup(testSpec.ID); ok {
		t.Errorf("v6 reservation = %v, want none — the alloc gains v6 at its next replacement", got)
	}
}

// A dual alias rebuilds both ipam instances, each adopting its own family.
func TestDualAliasRebuildsBothFamilies(t *testing.T) {
	f := newDualStackFixture(t)
	f.nl.addLink(hostDevName("shop-web-0"),
		aliasFor("shop-web-0", netip.MustParseAddr("10.200.0.2"), netip.MustParseAddr("fd10:244::2")))
	if err := f.d.Init(t.Context()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	if got, ok := f.d.ipam.Lookup("shop-web-0"); !ok || got.String() != "10.200.0.2" {
		t.Errorf("v4 rebuild = %v (ok=%v)", got, ok)
	}
	if got, ok := f.d.ipam6.Lookup("shop-web-0"); !ok || got.String() != "fd10:244::2" {
		t.Errorf("v6 rebuild = %v (ok=%v)", got, ok)
	}
}

// Detach deletes both identities, guided by the alias when the in-memory
// reservation is gone (the restart case).
func TestDualStackDetachDeletesBothIdentities(t *testing.T) {
	f := newDualStackFixture(t)
	attach(t, f)
	f.log.reset()

	if err := f.d.Detach(t.Context(), testSpec); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	steps := f.log.taken()
	for _, want := range []string{"delete-identity 10.200.0.2", "delete-identity fd10:244::2"} {
		if !slices.Contains(steps, want) {
			t.Errorf("detach steps %v are missing %q", steps, want)
		}
	}
}

// ipam over a v6 prefix: no broadcast to skip (the zero Addr never matches),
// the network address is skipped by construction, and the .1 anchor is never
// handed out.
func TestIPAMOverAV6Prefix(t *testing.T) {
	p := newIPAM(netip.MustParsePrefix("fd10:244::/120"))

	first, err := p.Reserve("a-alloc")
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "fd10:244::2" {
		t.Errorf("first v6 reservation = %s, want fd10:244::2 (::1 is the anchor)", first)
	}
	second, err := p.Reserve("b-alloc")
	if err != nil {
		t.Fatal(err)
	}
	if second.String() != "fd10:244::3" {
		t.Errorf("second v6 reservation = %s", second)
	}
}

// SyncServices programs a v6 frontend beside the v4 one when the service has
// a VIP6 twin — same frontend id, family-split backend sets. (The network
// vocabulary gains VIP6 in the next commit; this pins the map layer's half:
// a v6 SvcAddr flips into the fake and coexists with the v4 entry.)
func TestAppliedCacheKeepsFamiliesApart(t *testing.T) {
	f := newDualStackFixture(t)

	v4 := dpmap.SvcAddr{IP: netip.MustParseAddr("10.201.0.1"), Port: 80, Proto: protoTCP}
	v6 := dpmap.SvcAddr{IP: netip.MustParseAddr("fd10:245::1"), Port: 80, Proto: protoTCP}

	if err := f.maps.ApplyFlip(v4, dpmap.FlipPlan(7,
		nil, []dpmap.Backend{{IP: netip.MustParseAddr("10.200.0.2"), Port: 8080}}, 0)); err != nil {
		t.Fatal(err)
	}
	if err := f.maps.ApplyFlip(v6, dpmap.FlipPlan(7,
		nil, []dpmap.Backend{{IP: netip.MustParseAddr("fd10:244::2"), Port: 8080}}, 0)); err != nil {
		t.Fatal(err)
	}

	services, err := f.maps.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 2 {
		t.Fatalf("services = %v, want the two family twins as separate entries", services)
	}
	if services[v4].SvcID != 7 || services[v6].SvcID != 7 {
		t.Errorf("the twins should share one frontend id: %+v", services)
	}
}
