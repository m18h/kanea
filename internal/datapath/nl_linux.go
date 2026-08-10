//go:build linux

package datapath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"time"

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
	serviceCIDR netip.Prefix
	// serviceCIDR6 and clusterCIDR6 are the dual-stack halves (v1.41);
	// invalid prefixes mean v4-only. clusterCIDR6 is what the alloc's one v6
	// route covers — deliberately not a default route.
	serviceCIDR6  netip.Prefix
	clusterCIDR6  netip.Prefix
	toContainer   *ebpf.Program
	fromContainer *ebpf.Program
}

func (n *netlinkOps) EnsureHost(hostIP, hostIP6 netip.Addr) error {
	la := netlink.NewLinkAttrs()
	la.Name = HostInterface
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la}); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", HostInterface, err)
	}
	lnk, err := netlink.LinkByName(HostInterface)
	if err != nil {
		return fmt.Errorf("find %s: %w", HostInterface, err)
	}
	addr := &netlink.Addr{IPNet: hostNet(hostIP)}
	if err := netlink.AddrReplace(lnk, addr); err != nil {
		return fmt.Errorf("address %s on %s: %w", hostIP, HostInterface, err)
	}
	if hostIP6.IsValid() {
		// NODAD: the address is statically assigned on a link nothing else
		// shares, and duplicate address detection would only add a window.
		addr6 := &netlink.Addr{IPNet: hostNet(hostIP6), Flags: unix.IFA_F_NODAD}
		if err := netlink.AddrReplace(lnk, addr6); err != nil {
			return fmt.Errorf("address %s on %s: %w", hostIP6, HostInterface, err)
		}
		// Routing v6 between veths needs forwarding, which v4 gets from the
		// node's existing configuration; v6's is off by default everywhere.
		if err := writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
			return fmt.Errorf("enable v6 forwarding: %w", err)
		}
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
	if n.serviceCIDR6.IsValid() {
		route6 := &netlink.Route{Dst: prefixToIPNet(n.serviceCIDR6), Type: unix.RTN_BLACKHOLE}
		if err := netlink.RouteReplace(route6); err != nil {
			return fmt.Errorf("blackhole %s: %w", n.serviceCIDR6, err)
		}
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
	// Wait for udev to finish processing the new veth before its MAC is read.
	// systemd's default 99-default.link carries MACAddressPolicy=persistent,
	// which for a virtual device generates a MAC and applies it on the "add"
	// uevent — asynchronously, after LinkAdd returns. A MAC read before that
	// settles is the kernel's transient random one, stale by the time the
	// interface carries traffic; the static neighbors ConfigurePeer and
	// SetHostUp build from it would then point at an address nothing answers
	// to, and every packet across the veth would be dropped at L2 with no
	// counter to show for it. After settle the policy is applied and the MAC
	// is final (spike ⑤ check 4 / the MAC finding). "up" does not re-trigger
	// the policy, so the value read here holds through SetHostUp.
	settleUdev()
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

func (n *netlinkOps) ConfigurePeer(netnsPath string, ip, gw, ip6, gw6 netip.Addr, hostMAC string) error {
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

	// The kernel's own v6 machinery is configured before the link comes up:
	// with dual-stack, no RA and no autoconf (addressing is kanead's, not the
	// wire's) and no autogenerated link-local (static neighbors and NODAD
	// leave nothing that needs one); without, IPv6 is disabled outright so
	// the fe80 the tc drop would otherwise count never exists.
	if err := writePeerSysctls(netnsPath, ip6.IsValid()); err != nil {
		return err
	}

	eth0, err := h.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("find eth0 in %s: %w", netnsPath, err)
	}
	idx := eth0.Attrs().Index
	if err := h.AddrReplace(eth0, &netlink.Addr{IPNet: hostNet(ip)}); err != nil {
		return fmt.Errorf("address %s on eth0: %w", ip, err)
	}
	if ip6.IsValid() {
		if err := h.AddrReplace(eth0, &netlink.Addr{IPNet: hostNet(ip6), Flags: unix.IFA_F_NODAD}); err != nil {
			return fmt.Errorf("address %s on eth0: %w", ip6, err)
		}
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
	gwRoute := &netlink.Route{LinkIndex: idx, Dst: hostNet(gw), Scope: netlink.SCOPE_LINK}
	if err := h.RouteReplace(gwRoute); err != nil {
		return fmt.Errorf("gateway route %s: %w", gw, err)
	}
	defRoute := &netlink.Route{LinkIndex: idx, Gw: gw.AsSlice()}
	if err := h.RouteReplace(defRoute); err != nil {
		return fmt.Errorf("default route via %s: %w", gw, err)
	}

	if ip6.IsValid() {
		// The same trio for v6, except the last: a cluster-CIDR6 route
		// instead of a default route. Internal-only means external v6 is
		// ENETUNREACH immediately and Happy Eyeballs falls back to v4
		// (PRD v1.41) — which is also why there is no NAT66.
		neigh6 := &netlink.Neigh{
			LinkIndex:    idx,
			Family:       unix.AF_INET6,
			State:        netlink.NUD_PERMANENT,
			IP:           gw6.AsSlice(),
			HardwareAddr: mac,
		}
		if err := h.NeighSet(neigh6); err != nil {
			return fmt.Errorf("neighbor %s: %w", gw6, err)
		}
		gwRoute6 := &netlink.Route{LinkIndex: idx, Dst: hostNet(gw6), Scope: netlink.SCOPE_LINK}
		if err := h.RouteReplace(gwRoute6); err != nil {
			return fmt.Errorf("gateway route %s: %w", gw6, err)
		}
		clusterRoute := &netlink.Route{LinkIndex: idx, Dst: prefixToIPNet(n.clusterCIDR6), Gw: gw6.AsSlice()}
		if err := h.RouteReplace(clusterRoute); err != nil {
			return fmt.Errorf("cluster route %s via %s: %w", n.clusterCIDR6, gw6, err)
		}
	}
	return nil
}

func (n *netlinkOps) SetHostUp(hostDev string, podIP, podIP6 netip.Addr, podMAC string) error {
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
	if podIP6.IsValid() {
		neigh6 := &netlink.Neigh{
			LinkIndex:    lnk.Attrs().Index,
			Family:       unix.AF_INET6,
			State:        netlink.NUD_PERMANENT,
			IP:           podIP6.AsSlice(),
			HardwareAddr: mac,
		}
		if err := netlink.NeighSet(neigh6); err != nil {
			return fmt.Errorf("neighbor %s on %s: %w", podIP6, hostDev, err)
		}
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
		Dst:       hostNet(podIP),
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

// settleUdev blocks until udev's event queue drains, so its MACAddressPolicy
// has finished applying to a freshly created veth before the MAC is read
// (see CreateVeth). Best-effort and bounded: on a host without a running
// udevd it returns immediately, which is correct there — nothing will change
// the MAC. systemd (hence udevadm) is a hard platform requirement (§21).
func settleUdev() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "udevadm", "settle", "--timeout=5").Run() //nolint:errcheck // best-effort: a settle failure is not fatal, the MAC read below still proceeds
}

// hostNet renders one address as a host route/address: /32 or /128 by family.
func hostNet(ip netip.Addr) *net.IPNet {
	bits := ip.BitLen()
	return &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(bits, bits)}
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	masked := p.Masked()
	bits := masked.Addr().BitLen()
	return &net.IPNet{IP: masked.Addr().AsSlice(), Mask: net.CIDRMask(masked.Bits(), bits)}
}

// writeSysctl writes one /proc/sys value in the current netns.
func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o644) // #nosec G306 — /proc/sys modes are the kernel's
}

// writePeerSysctls configures the alloc netns's v6 posture before eth0 comes
// up. Entered via setns on a locked OS thread: sysctls are /proc/sys, which
// is per-netns, and a netlink handle cannot reach them.
func writePeerSysctls(netnsPath string, v6 bool) error {
	return inNetns(netnsPath, func() error {
		if !v6 {
			// Belt and braces beside the tc drop: with IPv6 off in the netns
			// the link-local never exists, so the drop counter stays quiet on
			// a v4-only node. A kernel built without IPv6 has nothing to
			// disable, which is the one tolerable absence.
			err := writeSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("disable ipv6 in %s: %w", netnsPath, err)
			}
			return nil
		}
		for _, s := range []struct{ key, value string }{
			// Addressing is kanead's: no router advertisements, no SLAAC.
			{"/proc/sys/net/ipv6/conf/eth0/accept_ra", "0"},
			{"/proc/sys/net/ipv6/conf/eth0/autoconf", "0"},
			// No autogenerated link-local (addr_gen_mode 1): static neighbors
			// and NODAD leave nothing that needs fe80, and an address nobody
			// planned is an address the egress guard has to drop.
			{"/proc/sys/net/ipv6/conf/eth0/addr_gen_mode", "1"},
		} {
			if err := writeSysctl(s.key, s.value); err != nil {
				return fmt.Errorf("sysctl %s in %s: %w", s.key, netnsPath, err)
			}
		}
		return nil
	})
}

// inNetns runs fn with the calling thread switched into the netns at path.
//
// The thread is locked for the duration; if the original namespace cannot be
// restored the thread is deliberately left locked, so the runtime destroys it
// with the goroutine instead of ever scheduling other code onto a thread in
// the wrong namespace.
func inNetns(netnsPath string, fn func() error) error {
	goruntime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		goruntime.UnlockOSThread()
		return fmt.Errorf("current netns: %w", err)
	}
	target, err := netns.GetFromPath(netnsPath)
	if err != nil {
		_ = orig.Close() //nolint:errcheck // read-only ns handle
		goruntime.UnlockOSThread()
		return fmt.Errorf("open netns %s: %w", netnsPath, err)
	}
	if err := netns.Set(target); err != nil {
		_ = target.Close() //nolint:errcheck // read-only ns handle
		_ = orig.Close()   //nolint:errcheck // read-only ns handle
		goruntime.UnlockOSThread()
		return fmt.Errorf("enter netns %s: %w", netnsPath, err)
	}
	fnErr := fn()
	restoreErr := netns.Set(orig)
	_ = target.Close() //nolint:errcheck // read-only ns handle
	_ = orig.Close()   //nolint:errcheck // read-only ns handle
	if restoreErr != nil {
		return errors.Join(fnErr, fmt.Errorf("restore netns: %w", restoreErr))
	}
	goruntime.UnlockOSThread()
	return fnErr
}
