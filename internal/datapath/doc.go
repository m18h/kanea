// Package datapath is Kanea's own eBPF datapath (PRD v1.36 §5.2.5): three
// programs, pinned maps under /sys/fs/bpf/kanea, netlink plumbing and one
// nftables rule — no cilium, no etcd, no CNI, no network agent.
//
// IP is identity. kanead allocates every address, so the identity map is
// written by the allocator itself before the interface that will carry the
// address even exists: there is no identity protocol, no label race and no
// settle window. The attach order is deny-closed by construction — identity
// write, veth created with the host side down, tc policy attached, addresses
// and static neighbors, link up, and the host /32 route last — because an
// identity miss in the tc program is a drop, so a partially attached alloc
// cannot pass traffic it will later be denied.
//
// The orchestration in this package is portable: it speaks to small
// consumer-side seams (Nl, Maps, Firewall, Netns) so the ordering, IPAM and
// diff logic is tested on any platform. The real implementations — vishvananda
// /netlink, cilium/ebpf map and link work, google/nftables — are behind
// //go:build linux.
//
// Unlike runtime's bare-netns mode, this driver satisfies
// reconciler.NetworkInspector safely: every interface it creates is marked
// twice (the "kn" name prefix and the "kanea/<alloc>/<ip>" ifalias), and
// Attachments reports only links carrying both marks. That property is
// load-bearing — the reaper deletes what Attachments reports, so enumeration
// must only ever report provably-Kanea interfaces.
package datapath
