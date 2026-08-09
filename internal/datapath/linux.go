//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

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
	coll, err := openObjects(cfg.BPFDir)
	if err != nil {
		return nil, err
	}
	km := &kernelMaps{coll: coll}
	nl := &netlinkOps{
		serviceCIDR:   cfg.ServiceCIDR.Masked(),
		toContainer:   coll.Programs[bpf.ProgToContainer],
		fromContainer: coll.Programs[bpf.ProgFromContainer],
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
// is deleted and recreated — safe because established flows bypass the maps
// (PRD v1.36), and the first reconcile pass repopulates everything (the state
// is derived; nothing under the pin root is ever backed up).
func openObjects(dir string) (*ebpf.Collection, error) {
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

	for _, name := range []string{bpf.ProgConnect4, bpf.ProgToContainer, bpf.ProgFromContainer} {
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

	if err := ensureConnectLink(dir, coll.Programs[bpf.ProgConnect4]); err != nil {
		coll.Close()
		return nil, err
	}
	return coll, nil
}

// loadPinned loads the collection with PinByName under dir.
func loadPinned(dir string) (*ebpf.Collection, error) {
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

// ensureConnectLink holds kanea_connect4 at the root cgroup through a pinned
// bpf_link: a surviving pin is updated in place (the attachment never lapses
// across a kanead restart), a missing one is attached fresh and pinned.
func ensureConnectLink(dir string, prog *ebpf.Program) error {
	pin := filepath.Join(dir, "link_connect4")
	if l, err := link.LoadPinnedLink(pin, nil); err == nil {
		if err := l.Update(prog); err != nil {
			return fmt.Errorf("datapath: update connect4 link: %w", err)
		}
		return nil
	}
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupRoot,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("datapath: attach connect4 at %s: %w", cgroupRoot, err)
	}
	if err := l.Pin(pin); err != nil {
		wrapped := fmt.Errorf("datapath: pin connect4 link: %w", err)
		if closeErr := l.Close(); closeErr != nil {
			return errors.Join(wrapped, closeErr)
		}
		return wrapped
	}
	return nil
}
