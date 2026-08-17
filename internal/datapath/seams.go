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
	// EnsureHost creates the kanea0 dummy if needed, gives it hostIP/32 (and
	// hostIP6/128 with NODAD when dual-stack: a zero hostIP6 means v4-only),
	// brings it up, and installs the blackhole routes for the service CIDRs
	// so un-rewritten VIP traffic cannot escape via the default route. With
	// v6 enabled it also turns v6 forwarding on and writes the netns-side
	// prerequisites the kernel owns.
	EnsureHost(hostIP, hostIP6 netip.Addr) error
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
	// mapping the gateway to the host veth's MAC. Zero ip6/gw6 means v4-only,
	// and the netns then gets disable_ipv6 instead of a second family; set,
	// eth0 additionally gets ip6/128 (NODAD, accept_ra=0, no autoconf), an
	// AF_INET6 PERMANENT neighbor for gw6, and a cluster-CIDR6 route via it;
	// deliberately NOT a v6 default route (PRD v1.41: internal-only, external
	// v6 fails fast to Happy Eyeballs).
	ConfigurePeer(netnsPath string, ip, gw, ip6, gw6 netip.Addr, hostMAC string) error
	// SetHostUp installs the PERMANENT neighbor entries for the pod on the
	// host device (both families when podIP6 is set) and brings the device up.
	SetHostUp(hostDev string, podIP, podIP6 netip.Addr, podMAC string) error
	// InstallRoute installs the host route to one pod address (/32 or /128 by
	// family): the last step of an attach, because it is the one that makes
	// the alloc reachable. Called once per family.
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
	// PutIdentity and DeleteIdentity dispatch on the address family inside
	// the implementation: identity_v4 or identity_v6 by ip.Is4(). One method,
	// because a caller never cares which map holds an identity: only that
	// the address has one.
	PutIdentity(ip netip.Addr, id dpmap.Identity) error
	DeleteIdentity(ip netip.Addr) error
	// ApplyFlip executes a dpmap.FlipPlan in order against one service entry,
	// in the family the key's address selects (svc_v4/svc_backends or
	// svc_v6/svc_backends6). The key is supplied here because dpmap.Op
	// deliberately does not carry it: the plan is key-neutral, the executor
	// is not.
	ApplyFlip(key dpmap.SvcAddr, ops []dpmap.Op) error
	// DeleteService removes the service entry itself, turning the VIP back
	// into a plain address. The caller deletes the orphaned backends via
	// ApplyFlip afterwards.
	DeleteService(key dpmap.SvcAddr) error
	PutAllow(dst, src uint32) error
	DeleteAllow(dst, src uint32) error
	// Allows returns the current allow_v4 key set, for diffing. (The map is
	// service-id-keyed and family-neutral; the name is historical.)
	Allows() (map[dpmap.AllowKey]struct{}, error)
	// Identities returns the merged identity_v4 + identity_v6 contents, for
	// rebuild and inspection: the netip.Addr key carries the family.
	Identities() (map[netip.Addr]dpmap.Identity, error)
	// Services returns the merged svc_v4 + svc_v6 contents, for diffing.
	Services() (map[dpmap.SvcAddr]dpmap.SvcVal, error)
	SetConfig(cfg dpmap.Config) error
	// SetConfig6 writes config6: always, because its all-zero mask is the
	// v6 enable switch and a node whose v6 was turned off must overwrite
	// whatever an earlier process pinned.
	SetConfig6(cfg dpmap.Config6) error
	// SetClusterCIDR and SetClusterCIDR6 write the cluster maps (v1.65):
	// what to_container treats as internal for the source-identity deny and
	// from_container refuses to see forged past. SetClusterCIDR6 is written
	// unconditionally like SetConfig6, and for the same reason.
	SetClusterCIDR(cfg dpmap.CIDR) error
	SetClusterCIDR6(cfg dpmap.CIDR6) error
}

// Firewall owns the one nftables rule the datapath needs: masquerade for
// cluster traffic leaving the node. Kernel conntrack does the NAT.
type Firewall interface {
	EnsureMasquerade(clusterCIDR netip.Prefix, hostDev string) error
	Teardown() error
}

// Netns is the namespace seam, implemented on linux by runtime.CreateNetns and
// friends: namespace creation stays the runtime's, not the datapath's.
type Netns interface {
	// Create makes (or finds) the alloc's persistent netns and returns its path.
	Create(allocID string) (string, error)
	// Path returns where the alloc's netns lives, whether or not it exists.
	Path(allocID string) string
	// Delete removes the netns. Missing is success.
	Delete(allocID string) error
}
