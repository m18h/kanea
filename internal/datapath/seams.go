package datapath

import (
	"net/netip"

	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// Link is one host interface as the datapath sees it: the name and the
// ownership alias. Only "kn"-prefixed links are ever reported.
type Link struct {
	Name  string
	Alias string
}

// Nl is the netlink plumbing seam. The linux implementation drives
// vishvananda/netlink; tests substitute a recorder, because the *ordering* of
// these calls is the property this package exists to keep.
type Nl interface {
	// EnsureHost creates the kanea0 dummy if needed, gives it hostIP/32,
	// brings it up, and installs the blackhole route for the service CIDR so
	// un-rewritten VIP traffic cannot escape via the default route.
	EnsureHost(hostIP netip.Addr) error
	// CreateVeth creates the veth pair with the host side DOWN and the alias
	// set on the host side, returning both MAC addresses. The host side must
	// not come up here: policy is not attached yet.
	CreateVeth(host, peer, alias string) (hostMAC, peerMAC string, err error)
	// AttachPrograms installs the clsact qdisc and the two tc filters on the
	// host device: kanea_to_container on egress, kanea_from_container on
	// ingress.
	AttachPrograms(hostDev string) error
	// MovePeer moves the peer into the netns at netnsPath, renames it eth0
	// and sets its MTU.
	MovePeer(peer, netnsPath string) error
	// ConfigurePeer gives eth0 in the netns its /32, the scope-link route to
	// the gateway, the default route via it, and a PERMANENT neighbor entry
	// mapping the gateway to the host veth's MAC.
	ConfigurePeer(netnsPath string, ip, gw netip.Addr, hostMAC string) error
	// SetHostUp installs the PERMANENT neighbor entry for the pod on the host
	// device and brings the device up.
	SetHostUp(hostDev string, podIP netip.Addr, podMAC string) error
	// InstallRoute installs the host /32 route to the pod — the last step of
	// an attach, because it is the one that makes the alloc reachable.
	InstallRoute(podIP netip.Addr, hostDev string, srcIP netip.Addr) error
	// DeleteVeth removes the host device (the peer dies with it). Absent is
	// success: teardown runs on paths where part of it already happened.
	DeleteVeth(hostDev string) error
	// List returns the "kn"-prefixed links with their aliases.
	List() ([]Link, error)
}

// Maps is the map-write seam. kanead is the sole writer of every datapath map
// (PRD v1.36); the linux implementation writes the pinned kernel maps, tests
// substitute an in-memory model.
type Maps interface {
	PutIdentity(ip netip.Addr, id dpmap.Identity) error
	DeleteIdentity(ip netip.Addr) error
	// ApplyFlip executes a dpmap.FlipPlan in order against one service entry.
	// The svc_v4 key is supplied here because dpmap.Op deliberately does not
	// carry it — the plan is key-neutral, the executor is not.
	ApplyFlip(key dpmap.SvcKey, ops []dpmap.Op) error
	// DeleteService removes the svc_v4 entry itself, turning the VIP back
	// into a plain address. The caller deletes the orphaned backends via
	// ApplyFlip afterwards.
	DeleteService(key dpmap.SvcKey) error
	PutAllow(dst, src uint32) error
	DeleteAllow(dst, src uint32) error
	// Allows returns the current allow_v4 key set, for diffing.
	Allows() (map[dpmap.AllowKey]struct{}, error)
	// Identities returns the current identity_v4 contents, for rebuild and
	// inspection.
	Identities() (map[netip.Addr]dpmap.Identity, error)
	// Services returns the current svc_v4 contents, for diffing.
	Services() (map[dpmap.SvcKey]dpmap.SvcVal, error)
	SetConfig(cfg dpmap.Config) error
}

// Firewall owns the one nftables rule the datapath needs: masquerade for
// cluster traffic leaving the node. Kernel conntrack does the NAT.
type Firewall interface {
	EnsureMasquerade(clusterCIDR netip.Prefix, hostDev string) error
	Teardown() error
}

// Netns is the namespace seam, implemented on linux by runtime.CreateNetns and
// friends — namespace creation stays the runtime's, not the datapath's.
type Netns interface {
	// Create makes (or finds) the alloc's persistent netns and returns its path.
	Create(allocID string) (string, error)
	// Path returns where the alloc's netns lives, whether or not it exists.
	Path(allocID string) string
	// Delete removes the netns. Missing is success.
	Delete(allocID string) error
}
