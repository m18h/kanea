//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/m18h/kanea/internal/datapath/bpf"
)

// vethMTU is the MTU on both sides of every alloc veth. There is no overlay
// and no encapsulation, so the standard ethernet MTU stands.
const vethMTU = 1500

// netlinkOps is the real Nl over vishvananda/netlink.
type netlinkOps struct {
	serviceCIDR   netip.Prefix
	toContainer   *ebpf.Program
	fromContainer *ebpf.Program
}

func (n *netlinkOps) EnsureHost(hostIP netip.Addr) error {
	la := netlink.NewLinkAttrs()
	la.Name = HostInterface
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la}); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", HostInterface, err)
	}
	lnk, err := netlink.LinkByName(HostInterface)
	if err != nil {
		return fmt.Errorf("find %s: %w", HostInterface, err)
	}
	addr := &netlink.Addr{IPNet: ipNet32(hostIP)}
	if err := netlink.AddrReplace(lnk, addr); err != nil {
		return fmt.Errorf("address %s on %s: %w", hostIP, HostInterface, err)
	}
	if err := netlink.LinkSetUp(lnk); err != nil {
		return fmt.Errorf("bring %s up: %w", HostInterface, err)
	}
	// The blackhole keeps un-rewritten service-CIDR traffic from escaping via
	// the default route; the egress BPF program refuses the same thing from
	// allocs, this covers the host.
	route := &netlink.Route{Dst: prefixToIPNet(n.serviceCIDR), Type: unix.RTN_BLACKHOLE}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("blackhole %s: %w", n.serviceCIDR, err)
	}
	return nil
}

func (n *netlinkOps) CreateVeth(host, peer, alias string) (string, string, error) {
	la := netlink.NewLinkAttrs()
	la.Name = host
	la.MTU = vethMTU
	// The host side is created DOWN and stays DOWN until SetHostUp: policy is
	// not attached yet, and a link that cannot carry a packet needs none.
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: peer}); err != nil {
		return "", "", fmt.Errorf("create veth %s: %w", host, err)
	}
	hostLink, err := netlink.LinkByName(host)
	if err != nil {
		return "", "", fmt.Errorf("find %s: %w", host, err)
	}
	if err := netlink.LinkSetAlias(hostLink, alias); err != nil {
		return "", "", fmt.Errorf("alias %s: %w", host, err)
	}
	peerLink, err := netlink.LinkByName(peer)
	if err != nil {
		return "", "", fmt.Errorf("find %s: %w", peer, err)
	}
	if err := netlink.LinkSetMTU(peerLink, vethMTU); err != nil {
		return "", "", fmt.Errorf("mtu on %s: %w", peer, err)
	}
	return hostLink.Attrs().HardwareAddr.String(), peerLink.Attrs().HardwareAddr.String(), nil
}

func (n *netlinkOps) AttachPrograms(hostDev string) error {
	lnk, err := netlink.LinkByName(hostDev)
	if err != nil {
		return fmt.Errorf("find %s: %w", hostDev, err)
	}
	idx := lnk.Attrs().Index
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: idx,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("clsact on %s: %w", hostDev, err)
	}
	// Egress toward the alloc is where policy lives; ingress from the alloc
	// is the egress guard. Both direct-action.
	filters := []struct {
		parent uint32
		prog   *ebpf.Program
		name   string
	}{
		{netlink.HANDLE_MIN_EGRESS, n.toContainer, bpf.ProgToContainer},
		{netlink.HANDLE_MIN_INGRESS, n.fromContainer, bpf.ProgFromContainer},
	}
	for _, f := range filters {
		if f.prog == nil {
			return fmt.Errorf("datapath: program %s not loaded", f.name)
		}
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: idx,
				Parent:    f.parent,
				Handle:    1,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           f.prog.FD(),
			Name:         f.name,
			DirectAction: true,
		}
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("filter %s on %s: %w", f.name, hostDev, err)
		}
	}
	return nil
}

func (n *netlinkOps) MovePeer(peer, netnsPath string) error {
	peerLink, err := netlink.LinkByName(peer)
	if err != nil {
		return fmt.Errorf("find %s: %w", peer, err)
	}
	nsFile, err := os.Open(netnsPath) // #nosec G304 — the path comes from runtime.NetnsPath, not a request
	if err != nil {
		return fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	defer nsFile.Close() //nolint:errcheck // read-only handle
	if err := netlink.LinkSetNsFd(peerLink, int(nsFile.Fd())); err != nil {
		return fmt.Errorf("move %s into %s: %w", peer, netnsPath, err)
	}
	h, err := netlink.NewHandleAt(netns.NsHandle(nsFile.Fd()))
	if err != nil {
		return fmt.Errorf("enter netns %s: %w", netnsPath, err)
	}
	defer h.Close()
	moved, err := h.LinkByName(peer)
	if err != nil {
		return fmt.Errorf("find %s in %s: %w", peer, netnsPath, err)
	}
	if err := h.LinkSetMTU(moved, vethMTU); err != nil {
		return fmt.Errorf("mtu on %s: %w", peer, err)
	}
	if err := h.LinkSetName(moved, "eth0"); err != nil {
		return fmt.Errorf("rename %s to eth0: %w", peer, err)
	}
	return nil
}

func (n *netlinkOps) ConfigurePeer(netnsPath string, ip, gw netip.Addr, hostMAC string) error {
	mac, err := net.ParseMAC(hostMAC)
	if err != nil {
		return fmt.Errorf("host mac %q: %w", hostMAC, err)
	}
	nsFile, err := os.Open(netnsPath) // #nosec G304 — the path comes from runtime.NetnsPath, not a request
	if err != nil {
		return fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	defer nsFile.Close() //nolint:errcheck // read-only handle
	h, err := netlink.NewHandleAt(netns.NsHandle(nsFile.Fd()))
	if err != nil {
		return fmt.Errorf("enter netns %s: %w", netnsPath, err)
	}
	defer h.Close()

	eth0, err := h.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("find eth0 in %s: %w", netnsPath, err)
	}
	idx := eth0.Attrs().Index
	if err := h.AddrReplace(eth0, &netlink.Addr{IPNet: ipNet32(ip)}); err != nil {
		return fmt.Errorf("address %s on eth0: %w", ip, err)
	}
	if err := h.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("bring eth0 up: %w", err)
	}
	// The gateway never answers ARP (the host veth carries no address), so
	// the neighbor entry is PERMANENT: the resolution is ours, not the wire's.
	neigh := &netlink.Neigh{
		LinkIndex:    idx,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           gw.AsSlice(),
		HardwareAddr: mac,
	}
	if err := h.NeighSet(neigh); err != nil {
		return fmt.Errorf("neighbor %s: %w", gw, err)
	}
	gwRoute := &netlink.Route{LinkIndex: idx, Dst: ipNet32(gw), Scope: netlink.SCOPE_LINK}
	if err := h.RouteReplace(gwRoute); err != nil {
		return fmt.Errorf("gateway route %s: %w", gw, err)
	}
	defRoute := &netlink.Route{LinkIndex: idx, Gw: gw.AsSlice()}
	if err := h.RouteReplace(defRoute); err != nil {
		return fmt.Errorf("default route via %s: %w", gw, err)
	}
	return nil
}

func (n *netlinkOps) SetHostUp(hostDev string, podIP netip.Addr, podMAC string) error {
	mac, err := net.ParseMAC(podMAC)
	if err != nil {
		return fmt.Errorf("pod mac %q: %w", podMAC, err)
	}
	lnk, err := netlink.LinkByName(hostDev)
	if err != nil {
		return fmt.Errorf("find %s: %w", hostDev, err)
	}
	neigh := &netlink.Neigh{
		LinkIndex:    lnk.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           podIP.AsSlice(),
		HardwareAddr: mac,
	}
	if err := netlink.NeighSet(neigh); err != nil {
		return fmt.Errorf("neighbor %s on %s: %w", podIP, hostDev, err)
	}
	if err := netlink.LinkSetUp(lnk); err != nil {
		return fmt.Errorf("bring %s up: %w", hostDev, err)
	}
	return nil
}

func (n *netlinkOps) InstallRoute(podIP netip.Addr, hostDev string, srcIP netip.Addr) error {
	lnk, err := netlink.LinkByName(hostDev)
	if err != nil {
		return fmt.Errorf("find %s: %w", hostDev, err)
	}
	route := &netlink.Route{
		LinkIndex: lnk.Attrs().Index,
		Dst:       ipNet32(podIP),
		Src:       srcIP.AsSlice(),
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route %s dev %s: %w", podIP, hostDev, err)
	}
	return nil
}

func (n *netlinkOps) DeleteVeth(hostDev string) error {
	lnk, err := netlink.LinkByName(hostDev)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil // absent is success
		}
		return fmt.Errorf("find %s: %w", hostDev, err)
	}
	if err := netlink.LinkDel(lnk); err != nil {
		return fmt.Errorf("delete %s: %w", hostDev, err)
	}
	return nil
}

func (n *netlinkOps) List() ([]Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	out := make([]Link, 0, len(links))
	for _, l := range links {
		attrs := l.Attrs()
		if !strings.HasPrefix(attrs.Name, devPrefix) {
			continue
		}
		out = append(out, Link{Name: attrs.Name, Alias: attrs.Alias})
	}
	return out, nil
}

func ipNet32(ip netip.Addr) *net.IPNet {
	return &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(32, 32)}
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	masked := p.Masked()
	return &net.IPNet{IP: masked.Addr().AsSlice(), Mask: net.CIDRMask(masked.Bits(), 32)}
}
