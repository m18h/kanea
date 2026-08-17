//go:build linux

package main

import (
	"fmt"
	"time"
)

// check5: SYN-gated stateless policy.
//
// p1 (projA, svcClientA) and p4 (projB, svcOtherB) are the actors. p4 runs a
// server on backendPort (started for the fleet); p1 dials it directly (no
// VIP) so the tc policy on p4's veth is what decides.
func check5(e *env) error {
	// Ensure p4 has a listener to connect to; startServer for p4 was not in
	// the default set (it is a client-role pod), so add one now.
	if err := startServer(e, "p4", backendPort); err != nil {
		check("5 setup: p4 listener", false, err.Error())
		return nil
	}
	p4Addr := fmt.Sprintf("%s:%d", e.pods["p4"].ip, backendPort)
	p2Addr := fmt.Sprintf("%s:%d", e.pods["p2"].ip, backendPort)

	// 5a: same project (p1 -> p2, both projA) is allowed.
	ok, _, _, errText, err := podConnect(e, "p1", p2Addr, 2*time.Second, false)
	if err != nil {
		check("5a same-project connect allowed", false, err.Error())
	} else {
		check("5a same-project connect allowed", ok, "connect ok="+boolText(ok)+" err="+errText)
	}

	// 5b: cross project (p1 projA -> p4 projB) is denied; the SYN is dropped.
	before, _ := readDrops(e, dropPolicy)
	ok, _, elapsed, errText, err := podConnect(e, "p1", p4Addr, 2*time.Second, false)
	after, _ := readDrops(e, dropPolicy)
	if err != nil {
		check("5b cross-project connect denied (SYN dropped)", false, err.Error())
	} else {
		denied := !ok && after > before
		check("5b cross-project connect denied (SYN dropped)", denied,
			fmt.Sprintf("connect ok=%v in %v, policy drops %d->%d, err=%q", ok, elapsed.Round(time.Millisecond), before, after, errText))
	}

	// 5c: allow_v4 edge permits the cross-project connect and the reply flows
	// (the server responds; a full request/response, not just a SYN).
	if err := allowEdge(e, svcOtherB, svcClientA); err != nil {
		check("5c allow edge permits cross-project + reply flows", false, "allow: "+err.Error())
	} else {
		ok, banner, _, errText, err := podConnect(e, "p1", p4Addr, 2*time.Second, false)
		if err != nil {
			check("5c allow edge permits cross-project + reply flows", false, err.Error())
		} else {
			check("5c allow edge permits cross-project + reply flows", ok && banner != "",
				fmt.Sprintf("ok=%v banner=%q err=%q", ok, banner, errText))
		}
		_ = denyEdge(e, svcOtherB, svcClientA)
	}

	// 5d: ICMP within and across projects; recorded, not gated. The policy
	// is SYN-gated, so ICMP (no TCP flags) is passed by P2 for a programmed
	// destination regardless of project. We record what actually happens.
	okSame, _ := podPing(e, "p1", e.pods["p2"].ip.String())
	okCross, _ := podPing(e, "p1", e.pods["p4"].ip.String())
	info("5d ICMP same-project (p1->p2)", "reachable="+boolText(okSame))
	info("5d ICMP cross-project (p1->p4)", "reachable="+boolText(okCross))
	// This is a genuine finding for the report, not a pass/fail: it documents
	// that the stateless SYN gate does not police ICMP, which the design must
	// account for (a separate ICMP decision, or accept it).
	check("5d ICMP behavior recorded (see INFO lines)", true,
		fmt.Sprintf("same=%v cross=%v: SYN gate does not police ICMP", okSame, okCross))
	return nil
}

// check6: netfilter interplay. Install a FORWARD-drop table (docker/ufw
// stand-in), see whether routed pod<->pod and pod->uplink break, whether our
// own accept chain rescues them, and restore state.
func check6(e *env) error {
	p2Addr := fmt.Sprintf("%s:%d", e.pods["p2"].ip, backendPort)

	// Baseline: p1 -> p2 works (same project).
	ok, _, _, _, err := podConnect(e, "p1", p2Addr, 2*time.Second, false)
	if err != nil || !ok {
		check("6 baseline pod<->pod before FORWARD drop", false, fmt.Sprintf("ok=%v err=%v", ok, err))
		return nil
	}

	tbl, chain, err := simDropInstall(e)
	if err != nil {
		check("6a FORWARD policy drop installed", false, err.Error())
		return nil
	}
	check("6a FORWARD policy drop installed (docker/ufw sim)", true, "table "+nftSimTable+" policy drop")

	// pod<->pod is routed through FORWARD, so a drop policy there should bite
	// unless our own accept chain (higher priority) already rescued it.
	okAfter, _, _, _, _ := podConnect(e, "p1", p2Addr, 1500*time.Millisecond, false)
	info("6b pod<->pod under FORWARD drop", "reachable="+boolText(okAfter)+
		" (our accept chain runs at priority filter, the sim at filter+10)")
	check("6b behavior under FORWARD drop recorded", true,
		fmt.Sprintf("pod<->pod reachable=%v with our accept chain present", okAfter))

	// Explicit rescue inside the sim chain (the DOCKER-USER move) must restore
	// reachability if it was broken.
	if err := simDropRescue(e, tbl, chain); err != nil {
		check("6c accept-rule rescue in the foreign chain", false, err.Error())
	} else {
		okResc, _, _, _, _ := podConnect(e, "p1", p2Addr, 1500*time.Millisecond, false)
		check("6c accept-rule rescue restores pod<->pod", okResc,
			"reachable after rescue="+boolText(okResc))
	}

	if err := simDropRemove(e); err != nil {
		check("6d foreign FORWARD table removed (state restored)", false, err.Error())
	} else {
		okRestored, _, _, _, _ := podConnect(e, "p1", p2Addr, 1500*time.Millisecond, false)
		check("6d foreign FORWARD table removed (state restored)", okRestored,
			"reachable after cleanup="+boolText(okRestored))
	}
	return nil
}
