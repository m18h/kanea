//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/m18h/kanea/internal/datapath/bpf"
	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// cgroupRoot is where the connect4 program attaches: the root cgroup, so
// connect-time LB covers the host and every alloc alike.
const cgroupRoot = "/sys/fs/cgroup"

// New builds the real datapath: the BPF objects loaded (or re-opened from
// their pins) under cfg.BPFDir, the cgroup connect4 link attached and pinned,
// and the netlink/nftables/netns seams wired in. Call Init afterwards to bring
// the node-level state up.
func New(cfg Config) (*Datapath, error) {
	if cfg.BPFDir == "" {
		cfg.BPFDir = dpmap.PinRoot
	}
	coll, err := openObjects(cfg.BPFDir, cfg.ServiceCIDR6.IsValid())
	if err != nil {
		return nil, err
	}
	km := &kernelMaps{coll: coll}
	nl := &netlinkOps{
		serviceCIDR:   cfg.ServiceCIDR.Masked(),
		toContainer:   coll.Programs[bpf.ProgToContainer],
		fromContainer: coll.Programs[bpf.ProgFromContainer],
	}
	if cfg.ServiceCIDR6.IsValid() {
		nl.serviceCIDR6 = cfg.ServiceCIDR6.Masked()
		nl.clusterCIDR6 = cfg.ClusterCIDR6.Masked()
	}
	d, err := newDatapath(cfg, seams{nl: nl, maps: km, fw: nftFirewall{}, netns: hostNetns{}, counters: km})
	if err != nil {
		coll.Close()
		return nil, err
	}
	return d, nil
}

// openObjects loads the embedded collection with every map pinned by name
// under dir, re-opening pins that already exist. A pinned map whose shape no
// longer matches the compiled object is a schema mismatch: the pin directory
// is deleted and recreated; safe because established flows bypass the maps
// (PRD v1.36), and the first reconcile pass repopulates everything (the state
// is derived; nothing under the pin root is ever backed up).
func openObjects(dir string, v6 bool) (*ebpf.Collection, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("datapath: pin dir %s: %w", dir, err)
	}
	coll, err := loadPinned(dir)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// bpffs holds only pinned objects, so the map ABI recorded in each pin
		// (type, key size, value size, entries, flags) is the schema stamp.
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			return nil, fmt.Errorf("datapath: recreate pin dir %s: %w", dir, rmErr)
		}
		if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
			return nil, fmt.Errorf("datapath: pin dir %s: %w", dir, mkErr)
		}
		coll, err = loadPinned(dir)
	}
	if err != nil {
		return nil, fmt.Errorf("datapath: load bpf objects: %w", err)
	}

	progs := []string{bpf.ProgConnect4, bpf.ProgConnect6, bpf.ProgToContainer, bpf.ProgFromContainer}
	for _, name := range progs {
		prog := coll.Programs[name]
		if prog == nil {
			coll.Close()
			return nil, fmt.Errorf("datapath: program %q missing from the object", name)
		}
		pin := filepath.Join(dir, "prog_"+name)
		// Re-pin unconditionally: a surviving pin from the previous process
		// holds the previous binary's program.
		if err := os.Remove(pin); err != nil && !errors.Is(err, os.ErrNotExist) {
			coll.Close()
			return nil, fmt.Errorf("datapath: replace pin %s: %w", pin, err)
		}
		if err := prog.Pin(pin); err != nil {
			coll.Close()
			return nil, fmt.Errorf("datapath: pin %s: %w", pin, err)
		}
	}

	if err := ensureConnectLink(dir, "link_connect4", ebpf.AttachCGroupInet4Connect,
		coll.Programs[bpf.ProgConnect4]); err != nil {
		coll.Close()
		return nil, err
	}
	if v6 {
		if err := ensureConnectLink(dir, "link_connect6", ebpf.AttachCGroupInet6Connect,
			coll.Programs[bpf.ProgConnect6]); err != nil {
			coll.Close()
			return nil, err
		}
	} else if err := removeStaleLink(filepath.Join(dir, "link_connect6")); err != nil {
		// A node whose v6 was turned off must not keep rewriting AF_INET6
		// dials against maps nothing repopulates.
		coll.Close()
		return nil, err
	}
	return coll, nil
}

// removeStaleLink detaches a pinned link left behind by a configuration this
// process no longer runs. Absent is success.
func removeStaleLink(pin string) error {
	l, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("datapath: open stale pin %s: %w", pin, err)
	}
	if err := l.Unpin(); err != nil {
		return fmt.Errorf("datapath: unpin %s: %w", pin, err)
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("datapath: close stale link %s: %w", pin, err)
	}
	return nil
}

// loadPinned loads the collection with PinByName under dir.
func loadPinned(dir string) (*ebpf.Collection, error) {
	// The memlock limit is the kernel floor's problem, not a tuning knob
	// (§21: ≥ 5.10). Kernel 5.11 moved BPF memory accounting to the cgroup
	// memory controller; *below* it, every map and program is charged against
	// RLIMIT_MEMLOCK instead, and kanead.service deliberately sets no
	// LimitMEMLOCK, so it inherits systemd's 8 MiB default. Five of the
	// datapath's maps are PERCPU_HASH (the stats twins), costing ~360 KiB per
	// CPU, so a node with enough cores exceeds that default and map creation
	// fails with EPERM: the datapath would not come up at all on the very
	// kernel the floor names, and the error would point nowhere near the cause.
	//
	// Measured on 6.x/7.x: the collection loads with RLIMIT_MEMLOCK squeezed to
	// 64 KiB, confirming the limit is not consulted there and that this call
	// costs nothing above the floor. The failure below it is reasoned from the
	// accounting change, not yet observed: confirming it is a checkpoint of
	// the 5.10 floor run (spikes/ebpf-datapath).
	//
	// It belongs here rather than in the unit because every load path goes
	// through this function (systemd, a dev run, the spike harness) and a
	// unit directive would cover only the first.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("datapath: raise RLIMIT_MEMLOCK: %w", err)
	}
	spec, err := bpf.LoadSpec()
	if err != nil {
		return nil, err
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}
	return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: dir},
	})
}

// ensureConnectLink holds a connect program at the root cgroup through a
// pinned bpf_link: a surviving pin is updated in place (the attachment never
// lapses across a kanead restart), a missing one is attached fresh and
// pinned. Serves connect4 always and connect6 when dual-stack is configured.
func ensureConnectLink(dir, pinName string, attach ebpf.AttachType, prog *ebpf.Program) error {
	pin := filepath.Join(dir, pinName)
	if l, err := link.LoadPinnedLink(pin, nil); err == nil {
		if err := l.Update(prog); err != nil {
			return fmt.Errorf("datapath: update %s: %w", pinName, err)
		}
		return nil
	}
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupRoot,
		Attach:  attach,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("datapath: attach %s at %s: %w", pinName, cgroupRoot, err)
	}
	if err := l.Pin(pin); err != nil {
		wrapped := fmt.Errorf("datapath: pin %s: %w", pinName, err)
		if closeErr := l.Close(); closeErr != nil {
			return errors.Join(wrapped, closeErr)
		}
		return wrapped
	}
	return nil
}
