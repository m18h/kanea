package main

import goruntime "runtime"

// Network modes. Which one a node runs is not a setting (PRD v1.115): it
// follows the platform kanead runs on, so no file and no flag can put a Linux
// node into the mode that enforces nothing.
const (
	// networkEBPF is the product: Kanea's own eBPF datapath; connect-time
	// service LB, per-project policy, per-CPU counters (PRD §5.2.5). It needs
	// a Linux kernel.
	networkEBPF = "ebpf"
	// networkNetns gives each alloc a bare namespace and nothing else: no
	// address, no policy, no service load balancing, no internal DNS. It is
	// what kanead runs anywhere but Linux, so it still starts on a
	// development machine. It is not a deployment.
	networkNetns = "netns"
)

// networkModeFor is the mode a node on goos runs.
func networkModeFor(goos string) string {
	if goos == "linux" {
		return networkEBPF
	}
	return networkNetns
}

// nodeNetworkMode is the mode this process runs.
func nodeNetworkMode() string { return networkModeFor(goruntime.GOOS) }
