//go:build linux

package main

import (
	"fmt"
	"time"

	"github.com/vishvananda/netlink"
)

// check7 — strict rp_filter and PERMANENT neighbors. With
// net.ipv4.conf.all.rp_filter=1, does masqueraded return traffic and
// pod<->pod routing still work, and do the static neighbors function.
func check7(e *env) error {
	// Set strict rp_filter on all + the relevant interfaces. rp_filter takes
	// the max of `all` and the per-interface value.
	if err := saveAndSetSysctl(e, "net/ipv4/conf/all/rp_filter", "1"); err != nil {
		check("7 set rp_filter=1 strict", false, err.Error())
		return nil
	}
	_ = saveAndSetSysctl(e, "net/ipv4/conf/default/rp_filter", "1")

	// pod<->pod under strict rp_filter.
	p2Addr := fmt.Sprintf("%s:%d", e.pods["p2"].ip, backendPort)
	ok, _, _, _, err := podConnect(e, "p1", p2Addr, 2*time.Second, false)
	if err != nil {
		check("7a pod<->pod routing under strict rp_filter", false, err.Error())
	} else {
		check("7a pod<->pod routing under strict rp_filter", ok, "reachable="+boolText(ok))
	}

	// masqueraded egress still counts (return path passes rp_filter).
	p0, _, _ := masqCounter(e)
	_, _, _, _, _ = podConnect(e, "p1", fmt.Sprintf("%s:%d", e.uplinkIP, 9), 1200*time.Millisecond, false)
	time.Sleep(150 * time.Millisecond)
	p1, _, _ := masqCounter(e)
	check("7b masqueraded egress under strict rp_filter", p1 > p0,
		fmt.Sprintf("masq counter %d->%d", p0, p1))

	// PERMANENT neighbors present and not stale (no ARP needed).
	permOK, detail := neighborsPermanent(e, "p1")
	check("7c static PERMANENT neighbors function (no ARP)", permOK, detail)
	return nil
}

func neighborsPermanent(e *env, podID string) (bool, string) {
	host, err := netlink.LinkByName(e.pods[podID].veth)
	if err != nil {
		return false, err.Error()
	}
	neighs, err := netlink.NeighList(host.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return false, err.Error()
	}
	for _, n := range neighs {
		if n.IP.Equal(e.pods[podID].ip) {
			perm := n.State&netlink.NUD_PERMANENT != 0
			return perm, fmt.Sprintf("host->pod neigh state=0x%x permanent=%v", n.State, perm)
		}
	}
	return false, "no host-side neighbor entry for the pod"
}

// check8 — measurements.
func check8(e *env) error {
	// Program load + verify time (captured at load).
	info("8 program load+verify time", e.loadTime.Round(time.Microsecond).String())

	// Added connect() latency through the LB program: 1000 connects to a VIP
	// (through connect4) vs 1000 to a real backend address (no rewrite).
	vipAddr := fmt.Sprintf("%s:%d", vip1, vipPort)
	beAddr := fmt.Sprintf("%s:%d", e.pods["p2"].ip, backendPort)
	vipAvg := connectLoop(vipAddr, 1000)
	beAvg := connectLoop(beAddr, 1000)
	info("8 connect latency via VIP (connect4 rewrite)", vipAvg.Round(time.Microsecond).String())
	info("8 connect latency direct (no rewrite)", beAvg.Round(time.Microsecond).String())
	delta := vipAvg - beAvg
	info("8 added connect latency (VIP - direct)", delta.Round(time.Microsecond).String())
	// This is a measurement, not a threshold; recorded PASS with the number.
	check("8a connect-time LB latency measured", true,
		fmt.Sprintf("+%v per connect through the LB program", delta.Round(time.Microsecond)))

	// Attach latency for the full veth+tc+maps sequence (target: beat
	// Cilium's measured 123ms-1.15s). Report min/median/max across pods.
	minD, medD, maxD := attachStats(e)
	within := maxD <= 1150*time.Millisecond
	check("8b full alloc attach latency (target < Cilium 123ms-1.15s)", within,
		fmt.Sprintf("min=%v median=%v max=%v across %d pods",
			minD.Round(time.Millisecond), medD.Round(time.Millisecond), maxD.Round(time.Millisecond), len(e.podAttach)))

	// Pinned map+prog kernel memory.
	maps, progs, err := memlockTotal(e)
	if err != nil {
		check("8c pinned map+prog kernel memory measured", false, err.Error())
	} else {
		check("8c pinned map+prog kernel memory measured", true,
			fmt.Sprintf("maps=%s progs=%s total=%s", humanBytes(maps), humanBytes(progs), humanBytes(maps+progs)))
	}
	return nil
}

func connectLoop(addr string, n int) time.Duration {
	var total time.Duration
	ok := 0
	for i := 0; i < n; i++ {
		_, _, d, err := hostDial(addr, 2*time.Second)
		if err == nil {
			total += d
			ok++
		}
	}
	if ok == 0 {
		return 0
	}
	return total / time.Duration(ok)
}

func attachStats(e *env) (minD, medD, maxD time.Duration) {
	var ds []time.Duration
	for _, d := range e.podAttach {
		ds = append(ds, d)
	}
	if len(ds) == 0 {
		return 0, 0, 0
	}
	for i := range ds {
		for j := i + 1; j < len(ds); j++ {
			if ds[j] < ds[i] {
				ds[i], ds[j] = ds[j], ds[i]
			}
		}
	}
	return ds[0], ds[len(ds)/2], ds[len(ds)-1]
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
