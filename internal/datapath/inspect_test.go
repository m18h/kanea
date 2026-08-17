package datapath

import (
	"net/netip"
	"testing"

	"github.com/m18h/kanea/internal/datapath/dpmap"
)

func TestAttachmentsReportsAnAttachedAlloc(t *testing.T) {
	f := newFixture(t)
	attach(t, f)

	got, err := f.d.Attachments(t.Context())
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	att, ok := got[testSpec.ID]
	if !ok {
		t.Fatalf("Attachments = %v, want %s", got, testSpec.ID)
	}
	if att.IPv4 != "10.200.0.2" || !att.Ready {
		t.Fatalf("attachment = %+v, want 10.200.0.2 and Ready", att)
	}
	if att.Service.Project != "shop" || att.Service.Service != "web" {
		t.Fatalf("attachment service = %v, want shop/web", att.Service)
	}
}

func TestAttachmentsReportsOnlyProvablyKaneaInterfaces(t *testing.T) {
	// The reaper deletes what this reports; a foreign interface in the result
	// is a foreign interface torn down. Both marks are required.
	f := newFixture(t)
	attach(t, f)
	f.nl.addLink("eth0", "kanea/impostor-0/10.200.0.9") // our alias on a foreign name
	f.nl.addLink("kn00deadbeef0", "veth-something")     // our prefix, foreign alias
	f.nl.addLink("knb", "")                             // our prefix, no alias
	f.nl.addLink("docker0", "")                         // nothing of ours

	got, err := f.d.Attachments(t.Context())
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Attachments = %v, want only %s", got, testSpec.ID)
	}
	if _, ok := got[testSpec.ID]; !ok {
		t.Fatalf("Attachments = %v, want %s", got, testSpec.ID)
	}
}

func TestAttachmentsWithoutIdentityIsNotReady(t *testing.T) {
	// The interface exists but its identity is gone: traffic is dropped (the
	// tc program fails closed), so the attachment is reported (the reaper
	// must see it to reclaim it) but never as fit for traffic.
	f := newFixture(t)
	f.nl.addLink(hostDevName("shop-web-0"), aliasFor("shop-web-0", netip.MustParseAddr("10.200.0.2"), netip.Addr{}))

	got, err := f.d.Attachments(t.Context())
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	att, ok := got["shop-web-0"]
	if !ok {
		t.Fatalf("Attachments = %v, want shop-web-0 present", got)
	}
	if att.Ready {
		t.Fatal("Ready = true with no identity: an identity miss is a drop, not a working attachment")
	}
}

func TestAttachmentsNeverReportsTheHostIdentityAsAnAlloc(t *testing.T) {
	f := newFixture(t)
	// A confused link claiming the host's address must not read as Ready: the
	// host identity is not an alloc identity.
	hostIP := netip.MustParseAddr("10.200.0.1")
	f.maps.idents[hostIP] = dpmap.Identity{Flags: dpmap.IdentityFlagHost}
	f.nl.addLink(hostDevName("weird-000"), aliasFor("weird-000", hostIP, netip.Addr{}))

	got, err := f.d.Attachments(t.Context())
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	if att := got["weird-000"]; att.Ready {
		t.Fatalf("attachment = %+v: the host flag must not read as a ready alloc", att)
	}
}
