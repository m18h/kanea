// Command kanea-spike-ebpf-datapath is throwaway M0-style validation code
// (see spikes/README.md) for Kanea's planned internal eBPF datapath; the
// standalone-Cilium replacement: connect-time service load balancing
// (cgroup/connect4), SYN-gated stateless policy and endpoint accounting on
// the veth tc hooks, static-neighbor point-to-point plumbing, and nftables
// masquerade.
//
// It is Linux-only and must run as root on a real node; see README.md for
// the build and run instructions and REPORT.md for the 11 go/no-go
// questions it answers. Nothing here ships.
package main
