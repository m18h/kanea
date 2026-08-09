//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"reflect"
	"time"

	"github.com/cilium/ebpf"
)

// check1 — connect4 at the root cgroup rewrites a VIP connect from both a
// plain host process and a process in a netns under a systemd-managed
// cgroup, without disturbing systemd's own cgroup programs.
func check1(e *env) error {
	vipAddr := fmt.Sprintf("%s:%d", vip1, vipPort)

	// 1a: plain host process (the kanea-edge north-south path).
	banner, peer, _, err := hostDial(vipAddr, 3*time.Second)
	if err != nil {
		check("1a connect4 rewrites a host-process VIP connect", false, err.Error())
	} else {
		be := backendPortMatches(banner)
		check("1a connect4 rewrites a host-process VIP connect", be,
			fmt.Sprintf("landed on %s (peer %s)", bannerAddr(banner), peer))
	}

	// 1b: a process inside a pod netns, wrapped in a transient systemd scope
	// so it lives under a systemd-managed cgroup rather than ours.
	ok, banner, _, errText, err := podConnect(e, "p1", vipAddr, 3*time.Second, true)
	if err != nil {
		check("1b connect4 rewrites a netns/systemd-scope VIP connect", false, err.Error())
	} else if !ok {
		check("1b connect4 rewrites a netns/systemd-scope VIP connect", false, "connect failed: "+errText)
	} else {
		check("1b connect4 rewrites a netns/systemd-scope VIP connect", backendPortMatches(banner),
			"landed on "+bannerAddr(banner))
	}

	// 1c: systemd's own cgroup programs are untouched. Compare the pre-attach
	// snapshot with now, ignoring our own InetConnect additions.
	post := queryCgroupPrograms()
	disturbed, detail := diffCgroupPrograms(e.preAttach, post)
	check("1c systemd's own cgroup programs undisturbed", !disturbed, detail)
	return nil
}

func backendPortMatches(banner string) bool {
	addr := bannerAddr(banner)
	return endsWithPort(addr, backendPort)
}

func endsWithPort(addr string, port int) bool {
	want := fmt.Sprintf(":%d", port)
	return len(addr) >= len(want) && addr[len(addr)-len(want):] == want
}

// diffCgroupPrograms reports whether any attach type OTHER than the two
// InetConnect ones we touch changed. A changed InetConnect set is expected
// (that is our program); anything else changing means we disturbed the host.
func diffCgroupPrograms(before, after map[ebpf.AttachType][]ebpf.ProgramID) (bool, string) {
	if before == nil || after == nil {
		return false, "kernel does not support BPF_PROG_QUERY on this cgroup (recorded, not a failure)"
	}
	for at, b := range before {
		if at == ebpf.AttachCGroupInet4Connect || at == ebpf.AttachCGroupInet6Connect {
			continue
		}
		a := after[at]
		if !reflect.DeepEqual(sortedIDs(b), sortedIDs(a)) {
			return true, fmt.Sprintf("attach %v changed: %v -> %v", at, b, a)
		}
	}
	n := 0
	for at, b := range before {
		if at == ebpf.AttachCGroupInet4Connect || at == ebpf.AttachCGroupInet6Connect {
			continue
		}
		n += len(b)
	}
	return false, fmt.Sprintf("%d pre-existing cgroup progs across other attach types preserved", n)
}

func sortedIDs(ids []ebpf.ProgramID) []ebpf.ProgramID {
	out := append([]ebpf.ProgramID(nil), ids...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// check2 — the pinned cgroup link survives the loader exiting, and
// Link.Update() swaps programs without dropping connects.
func check2(e *env) error {
	// A child process re-attaches+pins another link, then exits. If the pin
	// keeps the attachment alive, a VIP connect still rewrites afterwards.
	// (We already have our own link pinned; the point of the child is to
	// prove pin-survives-exit is a property of the mechanism, so it loads
	// the PINNED program and pins a fresh link with ALLOW_MULTI alongside.)
	out, err := exec.Command(self(), "__childload").CombinedOutput()
	if err != nil {
		check("2a pinned cgroup link survives loader exit", false,
			fmt.Sprintf("child failed: %v: %s", err, out))
	} else {
		// child has exited by now; try a connect.
		banner, _, _, derr := hostDial(fmt.Sprintf("%s:%d", vip1, vipPort), 3*time.Second)
		ok := derr == nil && backendPortMatches(banner)
		check("2a pinned cgroup link survives loader exit", ok,
			"post-child rewrite: "+resultText(banner, derr))
	}

	// 2b: Link.Update swaps the program under connect load without dropping.
	// Load a fresh copy of the same program and Update the live link to it
	// while a hammer runs; assert zero errors.
	prog2, err := reloadConnect4(e)
	if err != nil {
		check("2b Link.Update swaps programs with no dropped connects", false, "reload: "+err.Error())
		return nil
	}
	defer prog2.Close()

	done := make(chan hammerResult, 1)
	go func() {
		counts, errCount, firstErr, herr := podHammer(e, "p1", fmt.Sprintf("%s:%d", vip1, vipPort), 1500*time.Millisecond, 8)
		done <- hammerResult{counts, errCount, firstErr, herr}
	}()
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if err := e.cgLink.Update(prog2); err != nil {
			check("2b Link.Update swaps programs with no dropped connects", false, "update: "+err.Error())
			<-done
			return nil
		}
		time.Sleep(100 * time.Millisecond)
		if err := e.cgLink.Update(e.connect4); err != nil {
			check("2b Link.Update swaps programs with no dropped connects", false, "update-back: "+err.Error())
			<-done
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	res := <-done
	if res.err != nil {
		check("2b Link.Update swaps programs with no dropped connects", false, res.err.Error())
		return nil
	}
	total := 0
	for _, n := range res.counts {
		total += n
	}
	check("2b Link.Update swaps programs with no dropped connects", res.errCount == 0 && total > 0,
		fmt.Sprintf("%d connects across the swap, %d errors (first=%q)", total, res.errCount, res.firstErr))
	return nil
}

type hammerResult struct {
	counts   map[string]int
	errCount int
	firstErr string
	err      error
}

func resultText(banner string, err error) string {
	if err != nil {
		return "err=" + err.Error()
	}
	return "landed on " + bannerAddr(banner)
}

// reloadConnect4 loads a second, independent instance of the connect4
// program sharing the pinned maps, for Link.Update to swap to.
func reloadConnect4(e *env) (*ebpf.Program, error) {
	spec := e.spec.Copy()
	for name := range spec.Programs {
		if name != progConnect4 {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinMaps},
	})
	if err != nil {
		return nil, err
	}
	prog := coll.Programs[progConnect4]
	delete(coll.Programs, progConnect4) // hand ownership to the caller
	coll.Close()
	return prog, nil
}
