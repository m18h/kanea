package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// runClean resets everything the spike created: containers, CNI state, hogs, slices.
func runClean(ctx context.Context) error {
	client, ctx, err := dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	cs, err := client.Containers(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		fmt.Println("removing container", c.ID())
		removeAlloc(ctx, client, c.ID())
	}

	// leftover hogs
	_ = exec.Command("pkill", "-9", "-f", "spike-linux memhog").Run()
	for _, f := range []string{"/tmp/kanea-spike-pagecache.bin"} {
		os.Remove(f)
	}
	matches, _ := filepath_GlobTmp()
	for _, m := range matches {
		os.Remove(m)
	}

	// CNI state + config
	_ = cniDel("lc-1", 0) // best-effort IP release (netns already gone)
	_ = cniDel("lc-2", 0)
	_ = cniDel("m-1", 0)
	_ = cniDel("m-2", 0)
	_ = cniDel("m-3", 0)
	_ = cniDel("cg-t2", 0)
	os.RemoveAll("/var/lib/cni/networks/kanea-spike")
	os.Remove(cniConfPath)

	// GC stale CNI iptables chains: bridge DEL against a dead netns skips
	// ipMasq teardown (finding #2 for the report; M1 uses persistent netns
	// + DEL-before-kill to avoid this entirely).
	// Delete jump rules by number (full-spec -D chokes on quoted comments).
	if out, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "--line-numbers").Output(); err == nil {
		var nums []int
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && strings.HasPrefix(f[1], "CNI-") {
				if n, err := strconv.Atoi(f[0]); err == nil {
					nums = append(nums, n)
				}
			}
		}
		sort.Sort(sort.Reverse(sort.IntSlice(nums)))
		for _, n := range nums {
			_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", strconv.Itoa(n)).Run()
		}
	}
	if out, err := exec.Command("iptables", "-t", "nat", "-S").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && f[0] == "-N" && strings.HasPrefix(f[1], "CNI-") {
				_ = exec.Command("iptables", "-t", "nat", "-F", f[1]).Run()
				_ = exec.Command("iptables", "-t", "nat", "-X", f[1]).Run()
			}
		}
	}

	// slices: move stray procs back to root, then rmdir
	for _, slice := range []string{sliceCP, sliceWL} {
		if b, err := os.ReadFile(slice + "/cgroup.procs"); err == nil {
			for _, s := range strings.Fields(string(b)) {
				if pid, err := strconv.Atoi(s); err == nil {
					if p, err := os.FindProcess(pid); err == nil {
						_ = p.Kill()
					}
				}
			}
		}
	}
	// child cgroups (alloc-*) should be gone with their tasks; rmdir what remains
	entries, _ := os.ReadDir(sliceWL)
	for _, e := range entries {
		if e.IsDir() {
			_ = os.Remove(sliceWL + "/" + e.Name())
		}
	}
	if err := os.Remove(sliceCP); err != nil {
		fmt.Println("note:", err)
	}
	if err := os.Remove(sliceWL); err != nil {
		fmt.Println("note:", err)
	}
	fmt.Println("clean done")
	return nil
}

func filepath_GlobTmp() ([]string, error) {
	ents, err := os.ReadDir("/tmp")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "kanea-spike-") {
			out = append(out, "/tmp/"+e.Name())
		}
	}
	return out, nil
}
