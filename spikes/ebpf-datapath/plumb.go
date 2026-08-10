//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func ipnet32(ip net.IP) *net.IPNet {
	return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
}

// deterministicMAC builds a locally-administered unicast MAC from a lead byte
// and the four bytes of a v4 address: lead:00:a:b:c:d. Locally-administered
// (bit 1 of the first octet set — 0x02/0x06 both qualify) and unicast (bit 0
// clear), unique per pod, and distinct for the two ends via the lead byte.
// The point is that it is CHOSEN, not read: see createPod's MAC comment.
func deterministicMAC(lead byte, ip net.IP) net.HardwareAddr {
	v4 := ip.To4()
	return net.HardwareAddr{lead, 0x00, v4[0], v4[1], v4[2], v4[3]}
}

// settleUdev waits for udev's event queue to drain so its MACAddressPolicy has
// finished applying to a freshly created interface. Best-effort: on a host
// without a running udevd it returns quickly, which is the correct behaviour
// there (nothing will clobber the MAC).
func settleUdev() {
	_ = exec.Command("udevadm", "settle", "--timeout=5").Run()
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// createPod builds one alloc's plumbing in the exact order the design
// prescribes: netns -> veth (host side DOWN) -> ifalias -> clsact + tc
// filters referencing the PINNED programs -> peer into the netns as eth0
// with /32 + routes + PERMANENT neighbors -> and only THEN host side up +
// the /32 host route. The pod is reachable at the instant it is routable,
// with policy already in place.
func createPod(e *env, id string, ip net.IP, project, service uint32) (*pod, error) {
	t0 := time.Now()
	p := &pod{
		id:      id,
		ns:      nsPrefix + id,
		ip:      ip.To4(),
		veth:    vePrefix + id,
		project: project,
		service: service,
	}

	// The real code shells out to `ip netns` too: a named netns is a bind
	// mount under /var/run/netns, which plain netlink does not manage.
	if out, err := exec.Command("ip", "netns", "add", p.ns).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip netns add %s: %v: %s", p.ns, err, out)
	}
	nsh, err := netns.GetFromName(p.ns)
	if err != nil {
		return nil, fmt.Errorf("open netns %s: %w", p.ns, err)
	}
	defer nsh.Close()
	nl, err := netlink.NewHandleAt(nsh)
	if err != nil {
		return nil, fmt.Errorf("netlink handle in %s: %w", p.ns, err)
	}
	defer nl.Close()

	peerName := pePrefix + id
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: p.veth},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("veth add %s: %w", p.veth, err)
	}
	// Let udev finish processing the veth's "add" event before we touch its
	// MAC: MACAddressPolicy is applied asynchronously on add, so a MAC we set
	// (or read) before udev settles can be clobbered afterwards. After settle
	// the queue is empty and our explicit address below is final. (`up` does
	// not re-trigger the policy — only "add" does.)
	settleUdev()
	host, err := netlink.LinkByName(p.veth)
	if err != nil {
		return nil, err
	}
	// Deterministic, explicitly-set MACs — NOT the kernel's creation-time
	// random ones. On a systemd host, 99-default.link's MACAddressPolicy
	// generates and applies a fresh MAC to a virtual device *asynchronously*
	// after it appears, so a MAC read at creation is stale by the time traffic
	// flows and the PERMANENT neighbors built from it point at an address
	// nothing answers to — every packet dropped silently at L2. Because we
	// CHOOSE the addresses (deterministically from the pod IP) the neighbor
	// entries can be programmed up front; the interfaces are made to carry
	// them at the last moment (the host side right before it comes up, the
	// peer inside its fresh netns) so udev's async policy cannot clobber the
	// value between assignment and use. This is the datapath's bug too, not
	// just the spike's — see REPORT.md check 4 / the MAC finding.
	hostMAC := deterministicMAC(0x02, p.ip)
	peerMAC := deterministicMAC(0x06, p.ip)
	// Host side stays DOWN until the very end; the alias is the marker the
	// real datapath uses to find its interfaces again after a restart.
	if err := netlink.LinkSetAlias(host, fmt.Sprintf("kanea/%s/%s", id, p.ip)); err != nil {
		return nil, fmt.Errorf("set alias: %w", err)
	}

	// tc before the interface ever carries a packet.
	if err := attachTC(host.Attrs().Index, e.toContainer, e.fromContainer); err != nil {
		return nil, fmt.Errorf("attach tc on %s: %w", p.veth, err)
	}

	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetNsFd(peer, int(nsh)); err != nil {
		return nil, fmt.Errorf("move %s into %s: %w", peerName, p.ns, err)
	}

	inner, err := nl.LinkByName(peerName)
	if err != nil {
		return nil, err
	}
	if err := nl.LinkSetName(inner, "eth0"); err != nil {
		return nil, fmt.Errorf("rename to eth0: %w", err)
	}
	eth0, err := nl.LinkByName("eth0")
	if err != nil {
		return nil, err
	}
	// The peer's MAC is set inside the fresh netns, where no MACAddressPolicy
	// runs — so the value we chose is the value it keeps.
	if err := nl.LinkSetHardwareAddr(eth0, peerMAC); err != nil {
		return nil, fmt.Errorf("set peer mac: %w", err)
	}
	lo, err := nl.LinkByName("lo")
	if err == nil {
		_ = nl.LinkSetUp(lo)
	}
	if err := nl.AddrAdd(eth0, &netlink.Addr{IPNet: ipnet32(p.ip)}); err != nil {
		return nil, fmt.Errorf("addr add %s: %w", p.ip, err)
	}
	if err := nl.LinkSetUp(eth0); err != nil {
		return nil, err
	}

	gw := net.ParseIP(gwIPStr).To4()
	// The point-to-point trick: the gateway is not on any subnet the pod
	// has; a scope-link /32 route makes it reachable, then default via it.
	if err := nl.RouteAdd(&netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Dst:       ipnet32(gw),
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return nil, fmt.Errorf("gw route: %w", err)
	}
	if err := nl.RouteAdd(&netlink.Route{
		LinkIndex: eth0.Attrs().Index,
		Gw:        gw,
	}); err != nil {
		return nil, fmt.Errorf("default route: %w", err)
	}

	// The in-ns gateway neighbor (eth0 is already up), from the host MAC we
	// chose above — no ARP on this pair, ever.
	if err := nl.NeighAdd(&netlink.Neigh{
		LinkIndex:    eth0.Attrs().Index,
		IP:           gw,
		HardwareAddr: hostMAC,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return nil, fmt.Errorf("in-ns neigh: %w", err)
	}

	// Set the host side's chosen MAC and bring it up in immediate succession —
	// the narrowest possible window for udev's async policy to clobber it.
	if err := netlink.LinkSetHardwareAddr(host, hostMAC); err != nil {
		return nil, fmt.Errorf("set host mac: %w", err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return nil, err
	}

	// The host->pod PERMANENT neighbor goes in AFTER the host veth is up: a
	// neighbor added to a down device does not reliably stay NUD_PERMANENT —
	// the kernel re-resolves it via ARP once the link carries traffic, which
	// defeats the point of a static entry (check 7c).
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    host.Attrs().Index,
		IP:           p.ip,
		HardwareAddr: peerMAC,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return nil, fmt.Errorf("host neigh: %w", err)
	}

	// LAST: the /32 host route with the gateway address as preferred source
	// (host->pod traffic must carry a HOST identity).
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: host.Attrs().Index,
		Dst:       ipnet32(p.ip),
		Scope:     netlink.SCOPE_LINK,
		Src:       gw,
	}); err != nil {
		return nil, fmt.Errorf("host /32 route: %w", err)
	}

	if err := setIdentity(e, p.ip, project, service, 0); err != nil {
		return nil, err
	}

	e.pods[id] = p
	e.podAttach[id] = time.Since(t0)
	return p, nil
}

func deletePod(e *env, id string) {
	p, ok := e.pods[id]
	if !ok {
		return
	}
	if link, err := netlink.LinkByName(p.veth); err == nil {
		_ = netlink.LinkDel(link) // takes the peer and the tc filters with it
	}
	_ = exec.Command("ip", "netns", "delete", p.ns).Run()
	delete(e.pods, id)
}

// attachTC adds a clsact qdisc and the two SCHED_CLS filters. Egress on the
// host-side veth is traffic INTO the container (P2), ingress is traffic
// LEAVING it (P3).
func attachTC(ifindex int, toContainer, fromContainer *ebpf.Program) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("clsact: %w", err)
	}
	if err := netlink.FilterReplace(bpfFilter(ifindex, netlink.HANDLE_MIN_EGRESS, toContainer, progToContainer)); err != nil {
		return fmt.Errorf("egress filter: %w", err)
	}
	if err := netlink.FilterReplace(bpfFilter(ifindex, netlink.HANDLE_MIN_INGRESS, fromContainer, progFromContainer)); err != nil {
		return fmt.Errorf("ingress filter: %w", err)
	}
	return nil
}

func bpfFilter(ifindex int, parent uint32, prog *ebpf.Program, name string) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
}

// hostAnchor creates the dummy device carrying the gateway address and the
// blackhole route for the service CIDR (a VIP must never leave the node as
// a raw destination).
func hostAnchor(e *env) error {
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}}
	if err := netlink.LinkAdd(dummy); err != nil && !os.IsExist(err) {
		return fmt.Errorf("dummy add: %w", err)
	}
	link, err := netlink.LinkByName(dummyName)
	if err != nil {
		return err
	}
	gw := net.ParseIP(gwIPStr).To4()
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet32(gw)}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("dummy addr: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst:  mustCIDR(svcCIDRStr),
		Type: unix.RTN_BLACKHOLE,
	}); err != nil && !os.IsExist(err) {
		return fmt.Errorf("blackhole %s: %w", svcCIDRStr, err)
	}
	return nil
}

func removeHostAnchor() {
	_ = netlink.RouteDel(&netlink.Route{Dst: mustCIDR(svcCIDRStr), Type: unix.RTN_BLACKHOLE})
	if link, err := netlink.LinkByName(dummyName); err == nil {
		_ = netlink.LinkDel(link)
	}
}

func findUplink(e *env) error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Gw == nil {
			continue
		}
		// A default route's Dst is nil on older netlink versions and the
		// explicit 0.0.0.0/0 on newer ones; both spell "default".
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil || len(addrs) == 0 {
			continue
		}
		e.uplinkName = link.Attrs().Name
		e.uplinkIP = addrs[0].IP.To4()
		return nil
	}
	return fmt.Errorf("no IPv4 default route found (the masquerade checks need an uplink)")
}

// ---- sysctl save/restore ----

func sysctlPath(key string) string {
	return filepath.Join("/proc/sys", key)
}

func saveAndSetSysctl(e *env, key, val string) error {
	old, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return err
	}
	if _, saved := e.sysctls[key]; !saved {
		e.sysctls[key] = strings.TrimSpace(string(old))
	}
	return os.WriteFile(sysctlPath(key), []byte(val), 0o644)
}

func restoreSysctls(e *env) {
	for key, val := range e.sysctls {
		_ = os.WriteFile(sysctlPath(key), []byte(val), 0o644)
	}
	e.sysctls = map[string]string{}
}

// purge removes leftovers of a crashed run: netns, veths, dummy, nftables
// tables, the pin directory. Unpinning the cgroup link detaches it once the
// last reference is gone. Sysctls are NOT restored (a fresh process cannot
// know the pre-crash values); README documents the two that matter.
func purge() {
	_ = exec.Command("pkill", "-f", "__serve").Run()
	entries, _ := os.ReadDir("/var/run/netns")
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), nsPrefix) {
			_ = exec.Command("ip", "netns", "delete", ent.Name()).Run()
		}
	}
	links, _ := netlink.LinkList()
	for _, l := range links {
		if strings.HasPrefix(l.Attrs().Name, vePrefix) || l.Attrs().Name == dummyName {
			_ = netlink.LinkDel(l)
		}
	}
	_ = netlink.RouteDel(&netlink.Route{Dst: mustCIDR(svcCIDRStr), Type: unix.RTN_BLACKHOLE})
	nftPurge()
	_ = os.RemoveAll(pinRoot)
	fmt.Println("purged: netns, veths, dummy, nftables tables, pin dir")
}
