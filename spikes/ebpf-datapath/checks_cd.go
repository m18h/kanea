//go:build linux

package main

import (
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/vishvananda/netlink"
)

// check3 — tc clsact filters referencing pinned programs survive loader
// exit; NLM_F_REPLACE is atomic under traffic; deleting the veth removes
// the filters cleanly.
func check3(e *env) error {
	// A dedicated pod so a destructive veth-delete cannot touch the fleet.
	p, err := createPod(e, "p5", net.ParseIP("10.244.0.15"), projB, svcTempB)
	if err != nil {
		check("3 setup: temp pod for tc tests", false, err.Error())
		return nil
	}

	// 3a: a child attaches the pinned tc programs to a fresh interface and
	// exits; the filters must remain.
	pair := "kspv-tc0"
	if err := makeHostVeth(pair); err != nil {
		check("3a tc filters survive loader exit", false, "veth: "+err.Error())
	} else {
		out, cerr := exec.Command(self(), "__childtc", pair).CombinedOutput()
		if cerr != nil {
			check("3a tc filters survive loader exit", false, fmt.Sprintf("%v: %s", cerr, out))
		} else {
			n, ferr := countBpfFilters(pair)
			check("3a tc filters survive loader exit", ferr == nil && n == 2,
				fmt.Sprintf("%d bpf filters present after child exit", n))
		}
		_ = delLink(pair)
	}

	// 3b: FilterReplace (NLM_F_REPLACE) is atomic under traffic. Hammer the
	// hairpin VIP while replacing p2's egress filter repeatedly.
	done := make(chan hammerResult, 1)
	go func() {
		counts, errCount, firstErr, herr := podHammer(e, "p1", fmt.Sprintf("%s:%d", vip3, vipPort), 1200*time.Millisecond, 8)
		done <- hammerResult{counts, errCount, firstErr, herr}
	}()
	time.Sleep(200 * time.Millisecond)
	host, _ := netlink.LinkByName(e.pods["p1"].veth)
	replErr := ""
	for i := 0; i < 8 && host != nil; i++ {
		if err := netlink.FilterReplace(bpfFilter(host.Attrs().Index, netlink.HANDLE_MIN_EGRESS, e.toContainer, progToContainer)); err != nil {
			replErr = err.Error()
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	res := <-done
	switch {
	case res.err != nil:
		check("3b NLM_F_REPLACE atomic under traffic", false, res.err.Error())
	case replErr != "":
		check("3b NLM_F_REPLACE atomic under traffic", false, "replace: "+replErr)
	default:
		total := 0
		for _, n := range res.counts {
			total += n
		}
		check("3b NLM_F_REPLACE atomic under traffic", res.errCount == 0 && total > 0,
			fmt.Sprintf("%d connects during %d replaces, %d errors", total, 8, res.errCount))
	}

	// 3c: deleting the veth removes the filters cleanly (no leaked qdisc,
	// interface gone).
	veth := p.veth
	deletePod(e, "p5")
	_, ferr := netlink.LinkByName(veth)
	check("3c veth deletion removes filters cleanly", ferr != nil,
		"host-side veth absent after delete: "+boolText(ferr != nil))
	return nil
}

func makeHostVeth(name string) error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  name + "p",
	}
	return netlink.LinkAdd(veth)
}

func delLink(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}

func countBpfFilters(ifname string) (int, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, parent := range []uint32{netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_MIN_INGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return 0, err
		}
		for _, f := range filters {
			if _, ok := f.(*netlink.BpfFilter); ok {
				n++
			}
		}
	}
	return n, nil
}

// check4 — the end-to-end matrix.
func check4(e *env) error {
	vip1Addr := fmt.Sprintf("%s:%d", vip1, vipPort)

	// pod -> VIP -> other pod, spread across both backends.
	counts, errCount, _, err := podHammer(e, "p1", vip1Addr, 1200*time.Millisecond, 6)
	if err != nil {
		check("4a pod -> VIP -> pod (load spread)", false, err.Error())
	} else {
		check("4a pod -> VIP -> pod (load spread)", len(counts) == 2 && errCount == 0,
			fmt.Sprintf("backends hit: %v, errors=%d", counts, errCount))
	}

	// host -> VIP -> pod (kanea-edge path).
	banner, _, _, herr := hostDial(vip1Addr, 3*time.Second)
	check("4b host -> VIP -> pod", herr == nil && backendPortMatches(banner), resultText(banner, herr))

	// hairpin: p1 -> vip3 -> p1 itself.
	ok, banner, _, errText, err := podConnect(e, "p1", fmt.Sprintf("%s:%d", vip3, vipPort), 3*time.Second, false)
	if err != nil {
		check("4c hairpin pod -> VIP -> itself", false, err.Error())
	} else {
		check("4c hairpin pod -> VIP -> itself", ok && backendPortMatches(banner),
			"landed on "+bannerAddr(banner)+" errText="+errText)
	}

	// VIP with zero backends: immediate EPERM, not a timeout.
	ok, _, elapsed, errText, err := podConnect(e, "p1", fmt.Sprintf("%s:%d", vip2, vipPort), 5*time.Second, false)
	if err != nil {
		check("4d zero-backend VIP fails fast (EPERM)", false, err.Error())
	} else {
		fast := !ok && elapsed < 500*time.Millisecond
		check("4d zero-backend VIP fails fast (EPERM)", fast && isEPERM(errText),
			fmt.Sprintf("refused in %v, err=%q, eperm=%v", elapsed.Round(time.Millisecond), errText, isEPERM(errText)))
	}

	// pod -> uplink via masquerade. Reachability to the internet is not
	// assumed; the masquerade counter incrementing is the assertion.
	p0, _, _ := masqCounter(e)
	_, _, _, _, _ = podConnect(e, "p1", fmt.Sprintf("%s:%d", e.uplinkIP, 9), 1500*time.Millisecond, false)
	// discard:9 will refuse/timeout; the SNAT still counts the SYN.
	time.Sleep(200 * time.Millisecond)
	p1, _, cerr := masqCounter(e)
	if cerr != nil {
		check("4e pod -> uplink is masqueraded", false, cerr.Error())
	} else {
		check("4e pod -> uplink is masqueraded", p1 > p0,
			fmt.Sprintf("masquerade counter %d -> %d packets", p0, p1))
	}
	return nil
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
