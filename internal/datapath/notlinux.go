//go:build !linux

package datapath

import "fmt"

// New exists on every platform so the wiring in cmd/kanea stays portable, but
// an eBPF datapath needs a Linux kernel to exist on.
func New(_ Config) (*Datapath, error) {
	return nil, fmt.Errorf("datapath: the ebpf network mode requires linux")
}
