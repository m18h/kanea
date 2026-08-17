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

// identityMapFor picks the identity map by the address's family: the one
// place the PutIdentity/DeleteIdentity dispatch lives.
func (k *kernelMaps) identityMapFor(ip netip.Addr) (*ebpf.Map, []byte, error) {
	if ip.Is4() {
		m, err := k.mp(dpmap.MapIdentityV4)
		return m, dpmap.IPKey(ip.As4()), err
	}
	m, err := k.mp(dpmap.MapIdentityV6)
	return m, dpmap.IP6Key(ip.As16()), err
}

func (k *kernelMaps) PutIdentity(ip netip.Addr, id dpmap.Identity) error {
	m, key, err := k.identityMapFor(ip)
	if err != nil {
		return err
	}
	return m.Update(key, id.Marshal(), ebpf.UpdateAny)
}

func (k *kernelMaps) DeleteIdentity(ip netip.Addr) error {
	m, key, err := k.identityMapFor(ip)
	if err != nil {
		return err
	}
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// svcMapsFor picks the service and backend maps by the key's family, and
// renders the key bytes once.
func (k *kernelMaps) svcMapsFor(key dpmap.SvcAddr) (svc, backends *ebpf.Map, keyBytes []byte, v6 bool, err error) {
	if key.IP.Is4() {
		if svc, err = k.mp(dpmap.MapSvcV4); err != nil {
			return nil, nil, nil, false, err
		}
		if backends, err = k.mp(dpmap.MapSvcBackends); err != nil {
			return nil, nil, nil, false, err
		}
		return svc, backends, key.Key4().Marshal(), false, nil
	}
	if svc, err = k.mp(dpmap.MapSvcV6); err != nil {
		return nil, nil, nil, false, err
	}
	if backends, err = k.mp(dpmap.MapSvcBackends6); err != nil {
		return nil, nil, nil, false, err
	}
	return svc, backends, key.Key6().Marshal(), true, nil
}

func (k *kernelMaps) ApplyFlip(key dpmap.SvcAddr, ops []dpmap.Op) error {
	svc, backends, keyBytes, v6, err := k.svcMapsFor(key)
	if err != nil {
		return err
	}
	// The value's family follows the key's: a v6 frontend's backends are v6
	// addresses, marshalled for svc_backends6, and mixing families in one
	// flip is a bug worth failing loudly on.
	marshalVal := func(b dpmap.Backend) ([]byte, error) {
		if b.IP.Is4() != !v6 {
			return nil, fmt.Errorf("backend %s does not match the frontend's family", b.IP)
		}
		if v6 {
			return dpmap.BackendVal6{IP: b.IP.As16(), Port: b.Port}.Marshal(), nil
		}
		return dpmap.BackendVal{IP: b.IP.As4(), Port: b.Port}.Marshal(), nil
	}
	for _, op := range ops {
		switch op.Kind {
		case dpmap.OpPutBackend:
			val, err := marshalVal(op.Val)
			if err != nil {
				return err
			}
			if err := backends.Update(op.Key.Marshal(), val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("put backend %d/%d gen %d: %w", op.Key.SvcID, op.Key.Index, op.Key.Gen, err)
			}
		case dpmap.OpCommitService:
			if err := svc.Update(keyBytes, op.Svc.Marshal(), ebpf.UpdateAny); err != nil {
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

func (k *kernelMaps) DeleteService(key dpmap.SvcAddr) error {
	m, _, keyBytes, _, err := k.svcMapsFor(key)
	if err != nil {
		return err
	}
	if err := m.Delete(keyBytes); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
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
	out := map[netip.Addr]dpmap.Identity{}

	m4, err := k.mp(dpmap.MapIdentityV4)
	if err != nil {
		return nil, err
	}
	var kb [4]byte
	var vb [dpmap.IdentitySize]byte
	it := m4.Iterate()
	for it.Next(&kb, &vb) {
		var id dpmap.Identity
		if err := id.Unmarshal(vb[:]); err != nil {
			return nil, err
		}
		out[netip.AddrFrom4(kb)] = id
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	m6, err := k.mp(dpmap.MapIdentityV6)
	if err != nil {
		return nil, err
	}
	var kb6 [16]byte
	it = m6.Iterate()
	for it.Next(&kb6, &vb) {
		var id dpmap.Identity
		if err := id.Unmarshal(vb[:]); err != nil {
			return nil, err
		}
		out[netip.AddrFrom16(kb6)] = id
	}
	return out, it.Err()
}

func (k *kernelMaps) Services() (map[dpmap.SvcAddr]dpmap.SvcVal, error) {
	out := map[dpmap.SvcAddr]dpmap.SvcVal{}

	m4, err := k.mp(dpmap.MapSvcV4)
	if err != nil {
		return nil, err
	}
	var kb [dpmap.SvcKeySize]byte
	var vb [dpmap.SvcValSize]byte
	it := m4.Iterate()
	for it.Next(&kb, &vb) {
		var key dpmap.SvcKey
		var val dpmap.SvcVal
		if err := key.Unmarshal(kb[:]); err != nil {
			return nil, err
		}
		if err := val.Unmarshal(vb[:]); err != nil {
			return nil, err
		}
		out[dpmap.SvcAddr{IP: netip.AddrFrom4(key.VIP), Port: key.Port, Proto: key.Proto}] = val
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	m6, err := k.mp(dpmap.MapSvcV6)
	if err != nil {
		return nil, err
	}
	var kb6 [dpmap.SvcKey6Size]byte
	it = m6.Iterate()
	for it.Next(&kb6, &vb) {
		var key dpmap.SvcKey6
		var val dpmap.SvcVal
		if err := key.Unmarshal(kb6[:]); err != nil {
			return nil, err
		}
		if err := val.Unmarshal(vb[:]); err != nil {
			return nil, err
		}
		out[dpmap.SvcAddr{IP: netip.AddrFrom16(key.VIP), Port: key.Port, Proto: key.Proto}] = val
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

func (k *kernelMaps) SetConfig6(cfg dpmap.Config6) error {
	m, err := k.mp(dpmap.MapConfig6)
	if err != nil {
		return err
	}
	return m.Update(uint32(0), cfg.Marshal(), ebpf.UpdateAny)
}

func (k *kernelMaps) SetClusterCIDR(cfg dpmap.CIDR) error {
	m, err := k.mp(dpmap.MapClusterV4)
	if err != nil {
		return err
	}
	return m.Update(uint32(0), cfg.Marshal(), ebpf.UpdateAny)
}

func (k *kernelMaps) SetClusterCIDR6(cfg dpmap.CIDR6) error {
	m, err := k.mp(dpmap.MapClusterV6)
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

func (k *kernelMaps) Drops() (map[dpmap.DropEntry]uint64, error) {
	out := map[dpmap.DropEntry]uint64{}

	m4, err := k.mp(dpmap.MapStatsDrops)
	if err != nil {
		return nil, err
	}
	var kb [dpmap.DropKeySize]byte
	var perCPU []uint64
	it := m4.Iterate()
	for it.Next(&kb, &perCPU) {
		var key dpmap.DropKey
		if err := key.Unmarshal(kb[:]); err != nil {
			return nil, err
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[dpmap.DropEntry{Addr: netip.AddrFrom4(key.DstIP), Reason: key.Reason}] = sum
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	m6, err := k.mp(dpmap.MapStatsDrops6)
	if err != nil {
		return nil, err
	}
	var kb6 [dpmap.DropKey6Size]byte
	it = m6.Iterate()
	for it.Next(&kb6, &perCPU) {
		var key dpmap.DropKey6
		if err := key.Unmarshal(kb6[:]); err != nil {
			return nil, err
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[dpmap.DropEntry{Addr: netip.AddrFrom16(key.DstIP), Reason: key.Reason}] = sum
	}
	return out, it.Err()
}

func (k *kernelMaps) EndpointStats() (map[netip.Addr]dpmap.EpStats, error) {
	out := map[netip.Addr]dpmap.EpStats{}

	sum := func(perCPU []dpmap.EpStats) dpmap.EpStats {
		var s dpmap.EpStats
		for _, v := range perCPU {
			s.RxBytes += v.RxBytes
			s.RxPkts += v.RxPkts
			s.TxBytes += v.TxBytes
			s.TxPkts += v.TxPkts
		}
		return s
	}

	m4, err := k.mp(dpmap.MapStatsEp)
	if err != nil {
		return nil, err
	}
	var kb [4]byte
	var perCPU []dpmap.EpStats
	it := m4.Iterate()
	for it.Next(&kb, &perCPU) {
		out[netip.AddrFrom4(kb)] = sum(perCPU)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	m6, err := k.mp(dpmap.MapStatsEp6)
	if err != nil {
		return nil, err
	}
	var kb6 [16]byte
	it = m6.Iterate()
	for it.Next(&kb6, &perCPU) {
		out[netip.AddrFrom16(kb6)] = sum(perCPU)
	}
	return out, it.Err()
}
