//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func checkBpffs() error {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil {
		return fmt.Errorf("statfs /sys/fs/bpf: %w", err)
	}
	if st.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("/sys/fs/bpf is not bpffs (mount -t bpf bpf /sys/fs/bpf)")
	}
	return nil
}

// loadAndPin loads bpf/spike.o (minus the protocol-field probe, which may
// legitimately fail to verify on the 5.10 floor and must not take the whole
// collection down with it), pins the maps by name and the programs by path.
func loadAndPin(e *env) error {
	spec, err := ebpf.LoadCollectionSpec(e.objPath)
	if err != nil {
		return fmt.Errorf("load %s (did you run ./build.sh?): %w", e.objPath, err)
	}
	e.spec = spec

	for _, dir := range []string{pinMaps, pinProgs, pinLinks} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	mainSpec := spec.Copy()
	delete(mainSpec.Programs, progConnect4Proto)

	t0 := time.Now()
	coll, err := ebpf.NewCollectionWithOptions(mainSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinMaps},
	})
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	e.loadTime = time.Since(t0)
	e.coll = coll

	e.svcMap = coll.Maps["svc_v4"]
	e.backendMap = coll.Maps["svc_backends"]
	e.identityMap = coll.Maps["identity_v4"]
	e.allowMap = coll.Maps["allow_v4"]
	e.statsSvc = coll.Maps["stats_svc"]
	e.statsDrops = coll.Maps["stats_drops"]
	e.statsEp = coll.Maps["stats_ep"]

	e.connect4 = coll.Programs[progConnect4]
	e.toContainer = coll.Programs[progToContainer]
	e.fromContainer = coll.Programs[progFromContainer]

	for name, p := range coll.Programs {
		path := filepath.Join(pinProgs, name)
		_ = os.Remove(path)
		if err := p.Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return nil
}

// attachConnect4 attaches the LB program at the root cgroup and pins the
// resulting link. On >= 5.7 this is a bpf_link (which is inherently
// multi-program, the BPF_F_ALLOW_MULTI semantics); on older kernels
// cilium/ebpf falls back to PROG_ATTACH with ALLOW_MULTI but the fallback
// cannot be pinned, which the harness would surface as a failure here.
func attachConnect4(prog *ebpf.Program) (link.Link, error) {
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupRoot,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		return nil, err
	}
	_ = os.Remove(pinConnect4Link)
	if err := l.Pin(pinConnect4Link); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("pin cgroup link (kernel without cgroup bpf_link?): %w", err)
	}
	return l, nil
}

// queryCgroupPrograms enumerates programs attached at the root cgroup for a
// fixed set of attach types (check 1c: we must not disturb systemd's own).
// Attach types the kernel cannot query are simply absent from the result.
func queryCgroupPrograms() map[ebpf.AttachType][]ebpf.ProgramID {
	f, err := os.Open(cgroupRoot)
	if err != nil {
		return nil
	}
	defer f.Close()

	types := []ebpf.AttachType{
		ebpf.AttachCGroupInetIngress,
		ebpf.AttachCGroupInetEgress,
		ebpf.AttachCGroupInetSockCreate,
		ebpf.AttachCGroupSockOps,
		ebpf.AttachCGroupDevice,
		ebpf.AttachCGroupInet4Bind,
		ebpf.AttachCGroupInet6Bind,
		ebpf.AttachCGroupInet4Connect,
		ebpf.AttachCGroupInet6Connect,
		ebpf.AttachCGroupGetsockopt,
		ebpf.AttachCGroupSetsockopt,
	}
	out := map[ebpf.AttachType][]ebpf.ProgramID{}
	for _, at := range types {
		res, err := link.QueryPrograms(link.QueryOptions{Target: int(f.Fd()), Attach: at})
		if err != nil {
			continue
		}
		ids := []ebpf.ProgramID{}
		for _, ap := range res.Programs {
			ids = append(ids, ap.ID)
		}
		out[at] = ids
	}
	return out
}

// loadProtoProbe attempts to load the kanea_connect4_proto variant (which
// reads ctx->protocol) against the already-pinned maps. Its error is the
// answer to half of check 11.
func loadProtoProbe(e *env) error {
	probe := e.spec.Copy()
	for name := range probe.Programs {
		if name != progConnect4Proto {
			delete(probe.Programs, name)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(probe, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinMaps},
	})
	if err != nil {
		return err
	}
	coll.Close()
	return nil
}

// memlockTotal sums the kernel-reported memlock of every pinned map and
// program (bpftool reads the same fdinfo field).
func memlockTotal(e *env) (maps, progs uint64, err error) {
	for name, m := range e.coll.Maps {
		mi, err := m.Info()
		if err != nil {
			return 0, 0, fmt.Errorf("map %s info: %w", name, err)
		}
		ml, ok := mi.Memlock()
		if !ok {
			return 0, 0, fmt.Errorf("map %s: kernel does not report memlock", name)
		}
		maps += ml
	}
	for name, p := range e.coll.Programs {
		pi, err := p.Info()
		if err != nil {
			return 0, 0, fmt.Errorf("prog %s info: %w", name, err)
		}
		ml, ok := pi.Memlock()
		if !ok {
			return 0, 0, fmt.Errorf("prog %s: kernel does not report memlock", name)
		}
		progs += ml
	}
	return maps, progs, nil
}
