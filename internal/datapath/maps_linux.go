//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// kernelMaps implements Maps and Counters over the pinned kernel maps. kanead
// is the sole writer; keys and values travel through dpmap's byte layouts, so
// endianness is decided in exactly one place.
type kernelMaps struct {
	coll *ebpf.Collection
}

func (k *kernelMaps) mp(name string) (*ebpf.Map, error) {
	m := k.coll.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("datapath: map %q missing from the collection", name)
	}
	return m, nil
}

func (k *kernelMaps) PutIdentity(ip netip.Addr, id dpmap.Identity) error {
	m, err := k.mp(dpmap.MapIdentityV4)
	if err != nil {
		return err
	}
	return m.Update(dpmap.IPKey(ip.As4()), id.Marshal(), ebpf.UpdateAny)
}

func (k *kernelMaps) DeleteIdentity(ip netip.Addr) error {
	m, err := k.mp(dpmap.MapIdentityV4)
	if err != nil {
		return err
	}
	if err := m.Delete(dpmap.IPKey(ip.As4())); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (k *kernelMaps) ApplyFlip(key dpmap.SvcKey, ops []dpmap.Op) error {
	svc, err := k.mp(dpmap.MapSvcV4)
	if err != nil {
		return err
	}
	backends, err := k.mp(dpmap.MapSvcBackends)
	if err != nil {
		return err
	}
	for _, op := range ops {
		switch op.Kind {
		case dpmap.OpPutBackend:
			if err := backends.Update(op.Key.Marshal(), op.Val.Marshal(), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("put backend %d/%d gen %d: %w", op.Key.SvcID, op.Key.Index, op.Key.Gen, err)
			}
		case dpmap.OpCommitService:
			if err := svc.Update(key.Marshal(), op.Svc.Marshal(), ebpf.UpdateAny); err != nil {
				return fmt.Errorf("commit service %d gen %d: %w", op.Svc.SvcID, op.Svc.Gen, err)
			}
		case dpmap.OpDeleteBackend:
			if err := backends.Delete(op.Key.Marshal()); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("delete backend %d/%d gen %d: %w", op.Key.SvcID, op.Key.Index, op.Key.Gen, err)
			}
		default:
			return fmt.Errorf("datapath: unknown flip op %d", op.Kind)
		}
	}
	return nil
}

func (k *kernelMaps) DeleteService(key dpmap.SvcKey) error {
	m, err := k.mp(dpmap.MapSvcV4)
	if err != nil {
		return err
	}
	if err := m.Delete(key.Marshal()); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (k *kernelMaps) PutAllow(dst, src uint32) error {
	m, err := k.mp(dpmap.MapAllowV4)
	if err != nil {
		return err
	}
	one := uint8(1)
	return m.Update(dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src}.Marshal(), one, ebpf.UpdateAny)
}

func (k *kernelMaps) DeleteAllow(dst, src uint32) error {
	m, err := k.mp(dpmap.MapAllowV4)
	if err != nil {
		return err
	}
	err = m.Delete(dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src}.Marshal())
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (k *kernelMaps) Allows() (map[dpmap.AllowKey]struct{}, error) {
	m, err := k.mp(dpmap.MapAllowV4)
	if err != nil {
		return nil, err
	}
	out := map[dpmap.AllowKey]struct{}{}
	var kb [dpmap.AllowKeySize]byte
	var v uint8
	it := m.Iterate()
	for it.Next(&kb, &v) {
		var key dpmap.AllowKey
		if err := key.Unmarshal(kb[:]); err != nil {
			return nil, err
		}
		out[key] = struct{}{}
	}
	return out, it.Err()
}

func (k *kernelMaps) Identities() (map[netip.Addr]dpmap.Identity, error) {
	m, err := k.mp(dpmap.MapIdentityV4)
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]dpmap.Identity{}
	var kb [4]byte
	var vb [dpmap.IdentitySize]byte
	it := m.Iterate()
	for it.Next(&kb, &vb) {
		var id dpmap.Identity
		if err := id.Unmarshal(vb[:]); err != nil {
			return nil, err
		}
		out[netip.AddrFrom4(kb)] = id
	}
	return out, it.Err()
}

func (k *kernelMaps) Services() (map[dpmap.SvcKey]dpmap.SvcVal, error) {
	m, err := k.mp(dpmap.MapSvcV4)
	if err != nil {
		return nil, err
	}
	out := map[dpmap.SvcKey]dpmap.SvcVal{}
	var kb [dpmap.SvcKeySize]byte
	var vb [dpmap.SvcValSize]byte
	it := m.Iterate()
	for it.Next(&kb, &vb) {
		var key dpmap.SvcKey
		var val dpmap.SvcVal
		if err := key.Unmarshal(kb[:]); err != nil {
			return nil, err
		}
		if err := val.Unmarshal(vb[:]); err != nil {
			return nil, err
		}
		out[key] = val
	}
	return out, it.Err()
}

func (k *kernelMaps) SetConfig(cfg dpmap.Config) error {
	m, err := k.mp(dpmap.MapConfig)
	if err != nil {
		return err
	}
	return m.Update(uint32(0), cfg.Marshal(), ebpf.UpdateAny)
}

// --- Counters: per-CPU maps, summed across CPUs ---

func (k *kernelMaps) ServiceConnects() (map[uint16]uint64, error) {
	m, err := k.mp(dpmap.MapStatsSvc)
	if err != nil {
		return nil, err
	}
	out := map[uint16]uint64{}
	var key uint16
	var perCPU []uint64
	it := m.Iterate()
	for it.Next(&key, &perCPU) {
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[key] = sum
	}
	return out, it.Err()
}

func (k *kernelMaps) Drops() (map[dpmap.DropKey]uint64, error) {
	m, err := k.mp(dpmap.MapStatsDrops)
	if err != nil {
		return nil, err
	}
	out := map[dpmap.DropKey]uint64{}
	var kb [dpmap.DropKeySize]byte
	var perCPU []uint64
	it := m.Iterate()
	for it.Next(&kb, &perCPU) {
		var key dpmap.DropKey
		if err := key.Unmarshal(kb[:]); err != nil {
			return nil, err
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[key] = sum
	}
	return out, it.Err()
}

func (k *kernelMaps) EndpointStats() (map[netip.Addr]dpmap.EpStats, error) {
	m, err := k.mp(dpmap.MapStatsEp)
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]dpmap.EpStats{}
	var kb [4]byte
	var perCPU []dpmap.EpStats
	it := m.Iterate()
	for it.Next(&kb, &perCPU) {
		var sum dpmap.EpStats
		for _, v := range perCPU {
			sum.RxBytes += v.RxBytes
			sum.RxPkts += v.RxPkts
			sum.TxBytes += v.TxBytes
			sum.TxPkts += v.TxPkts
		}
		out[netip.AddrFrom4(kb)] = sum
	}
	return out, it.Err()
}
