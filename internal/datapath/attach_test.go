package datapath

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/runtime"
)

var testSpec = runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}

func attach(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.d.Attach(t.Context(), testSpec); err != nil {
		t.Fatalf("Attach: %v", err)
	}
}

func TestAttachOrdering(t *testing.T) {
	f := newFixture(t)
	attach(t, f)

	host := hostDevName(testSpec.ID)
	want := []string{
		"put-identity 10.200.0.2",
		"create-veth " + host,
		"attach-programs " + host,
		"netns-create " + testSpec.ID,
		"move-peer " + host + "p",
		"configure-peer 10.200.0.2",
		"set-host-up " + host,
		"install-route 10.200.0.2",
	}
	if got := f.log.taken(); !slices.Equal(got, want) {
		t.Fatalf("attach steps = %v, want %v", got, want)
	}
}

// One test per load-bearing edge, so a reordering names the property it broke
// rather than "the list changed".

func TestAttachWritesTheIdentityBeforeTheVethExists(t *testing.T) {
	f := newFixture(t)
	attach(t, f)
	identity, veth := f.log.indexOf("put-identity"), f.log.indexOf("create-veth")
	if identity == -1 || veth == -1 || identity > veth {
		t.Fatalf("identity at %d, veth at %d: the veth must never exist without its identity (an identity miss is a drop, but only if the miss cannot happen first)", identity, veth)
	}
}

func TestAttachAttachesPolicyBeforeThePeerMoves(t *testing.T) {
	f := newFixture(t)
	attach(t, f)
	programs, move := f.log.indexOf("attach-programs"), f.log.indexOf("move-peer")
	if programs == -1 || move == -1 || programs > move {
		t.Fatalf("programs at %d, move at %d: the peer must not reach the netns before policy guards its veth", programs, move)
	}
}

func TestAttachAttachesPolicyBeforeAnythingComesUp(t *testing.T) {
	f := newFixture(t)
	attach(t, f)
	programs, up := f.log.indexOf("attach-programs"), f.log.indexOf("set-host-up")
	if programs == -1 || up == -1 || programs > up {
		t.Fatalf("programs at %d, up at %d: an unguarded link must never come up", programs, up)
	}
}

func TestAttachInstallsTheRouteLast(t *testing.T) {
	f := newFixture(t)
	attach(t, f)
	steps := f.log.taken()
	if len(steps) == 0 || !strings.HasPrefix(steps[len(steps)-1], "install-route") {
		t.Fatalf("last step = %v, want install-route: reachability must imply everything else already happened", steps)
	}
}

func TestAttachIsIdempotent(t *testing.T) {
	f := newFixture(t)
	attach(t, f)
	f.log.reset()

	attach(t, f)
	if got := f.log.taken(); len(got) != 0 {
		t.Fatalf("second Attach touched the node: %v", got)
	}
}

func TestAttachRedoesAHalfFinishedAttach(t *testing.T) {
	// The link exists with the right alias but the identity is gone: that is
	// an interrupted attach, and leaving it standing would look attached and
	// pass nothing. It must be torn down and redone in full.
	f := newFixture(t)
	f.nl.addLink(hostDevName(testSpec.ID), aliasFor(testSpec.ID, netip.MustParseAddr("10.200.0.2"), netip.Addr{}))

	attach(t, f)
	got := f.log.taken()
	if len(got) == 0 || !strings.HasPrefix(got[0], "delete-veth") {
		t.Fatalf("steps = %v, want the stale link deleted first", got)
	}
	if f.log.indexOf("install-route") == -1 {
		t.Fatalf("steps = %v, want a full re-attach", got)
	}
}

func TestAttachTearsDownPartialStateOnError(t *testing.T) {
	boom := errors.New("boom")
	// Every step that can fail after the reservation exists.
	steps := []string{
		"create-veth", "attach-programs", "netns-create",
		"move-peer", "configure-peer", "set-host-up", "install-route",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t)
			if step == "netns-create" {
				f.netns.fail["netns-create"] = boom
			} else {
				f.nl.failAt(step, boom)
			}

			if err := f.d.Attach(t.Context(), testSpec); !errors.Is(err, boom) {
				t.Fatalf("Attach = %v, want the injected failure", err)
			}
			for _, cleanup := range []string{"delete-veth", "delete-identity", "netns-delete"} {
				if f.log.indexOf(cleanup) == -1 {
					t.Errorf("teardown after %s failure never ran %s: %v", step, cleanup, f.log.taken())
				}
			}
			// The reservation is released: a retry starts clean.
			f.d.mu.Lock()
			_, held := f.d.ipam.Lookup(testSpec.ID)
			f.d.mu.Unlock()
			if held {
				t.Errorf("reservation survived a failed attach")
			}
		})
	}
}

func TestAttachFailsWhenTheIdentityCannotBeWritten(t *testing.T) {
	boom := errors.New("boom")
	f := newFixture(t)
	f.maps.fail["put-identity"] = boom

	if err := f.d.Attach(t.Context(), testSpec); !errors.Is(err, boom) {
		t.Fatalf("Attach = %v, want the injected failure", err)
	}
	if f.log.indexOf("create-veth") != -1 {
		t.Fatalf("veth was created without an identity: %v", f.log.taken())
	}
}

func TestDetachOrdering(t *testing.T) {
	f := newFixture(t)
	attach(t, f)
	f.log.reset()

	if err := f.d.Detach(t.Context(), testSpec); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	host := hostDevName(testSpec.ID)
	want := []string{
		"delete-veth " + host,
		"delete-identity 10.200.0.2",
		"netns-delete " + testSpec.ID,
	}
	if got := f.log.taken(); !slices.Equal(got, want) {
		t.Fatalf("detach steps = %v, want %v", got, want)
	}
}

func TestDetachToleratesPartialState(t *testing.T) {
	ip := netip.MustParseAddr("10.200.0.2")
	cases := []struct {
		name  string
		setup func(f *fixture)
		// identityStays: with neither a link nor a reservation there is no
		// way to find the address, so the entry survives; harmless, because
		// an identity without an interface denies traffic and the next
		// allocation of the address overwrites it.
		identityStays bool
	}{
		{"nothing exists", func(*fixture) {}, false},
		{"identity only", func(f *fixture) {
			f.maps.idents[ip] = identityFor(t, f, testSpec)
		}, true},
		{"veth only", func(f *fixture) {
			f.nl.addLink(hostDevName(testSpec.ID), aliasFor(testSpec.ID, ip, netip.Addr{}))
		}, false},
		{"veth and identity", func(f *fixture) {
			f.nl.addLink(hostDevName(testSpec.ID), aliasFor(testSpec.ID, ip, netip.Addr{}))
			f.maps.idents[ip] = identityFor(t, f, testSpec)
		}, false},
		{"everything but the route", func(f *fixture) {
			f.nl.addLink(hostDevName(testSpec.ID), aliasFor(testSpec.ID, ip, netip.Addr{}))
			f.maps.idents[ip] = identityFor(t, f, testSpec)
			if _, err := f.netns.Create(testSpec.ID); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			if err := f.d.Detach(t.Context(), testSpec); err != nil {
				t.Fatalf("Detach = %v, want nil: teardown runs on paths where part of it already happened", err)
			}
			if len(f.nl.link) != 0 {
				t.Errorf("links survived detach: %v", f.nl.link)
			}
			if _, present := f.maps.idents[ip]; present != tc.identityStays {
				t.Errorf("identity present = %v after detach, want %v", present, tc.identityStays)
			}
		})
	}
}

func TestDetachFindsTheAddressFromTheAliasAfterARestart(t *testing.T) {
	// A restart lost the in-memory reservation; the alias on the link is the
	// durable copy, and the identity must still be removed.
	f := newFixture(t)
	ip := netip.MustParseAddr("10.200.0.5")
	f.nl.addLink(hostDevName(testSpec.ID), aliasFor(testSpec.ID, ip, netip.Addr{}))
	f.maps.idents[ip] = identityFor(t, f, testSpec)

	if err := f.d.Detach(t.Context(), testSpec); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if _, present := f.maps.idents[ip]; present {
		t.Fatal("identity survived: the alias was not consulted")
	}
}

func TestDetachIgnoresEmptyAllocID(t *testing.T) {
	f := newFixture(t)
	if err := f.d.Detach(t.Context(), runtime.AllocSpec{}); err != nil {
		t.Fatalf("Detach = %v, want nil", err)
	}
	if got := f.log.taken(); len(got) != 0 {
		t.Fatalf("Detach with no id touched the node: %v", got)
	}
}

func TestValidateAttach(t *testing.T) {
	cases := []struct {
		name string
		spec runtime.AllocSpec
		ok   bool
	}{
		{"valid", runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}, true},
		{"short id", runtime.AllocSpec{ID: "ab", Project: "shop", Service: "web"}, false},
		{"slash in id", runtime.AllocSpec{ID: "shop/web-0", Project: "shop", Service: "web"}, false},
		{"empty project", runtime.AllocSpec{ID: "shop-web-0", Service: "web"}, false},
		{"empty service", runtime.AllocSpec{ID: "shop-web-0", Project: "shop"}, false},
		{"separator in project", runtime.AllocSpec{ID: "shop-web-0", Project: "a b", Service: "web"}, false},
		{"separator in service", runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "w=b"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAttach(tc.spec)
			if tc.ok && err != nil {
				t.Fatalf("validateAttach = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("validateAttach = nil, want an error")
			}
		})
	}
}

// identityFor mints the identity Attach would write for the spec.
func identityFor(t *testing.T, f *fixture, spec runtime.AllocSpec) dpmap.Identity {
	t.Helper()
	projectID, err := f.d.ids.ProjectID(t.Context(), spec.Project)
	if err != nil {
		t.Fatal(err)
	}
	serviceID, err := f.d.ids.ServiceID(t.Context(), spec.Project, spec.Service)
	if err != nil {
		t.Fatal(err)
	}
	return dpmap.Identity{ProjectID: projectID, ServiceID: serviceID}
}
