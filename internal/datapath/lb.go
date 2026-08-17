package datapath

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

// protoTCP is IPPROTO_TCP. Service ports are TCP-only in the datapath
// (PRD v1.36): connect-time rewrite has no hook for UDP.
const protoTCP uint8 = 6

// desiredSvc is one frontend's desired programming.
type desiredSvc struct {
	applied appliedService
	name    string // "project/service", for errors
}

// SyncServices makes the datapath's load balancing match the given set: new
// and changed frontends are flipped in (dpmap.FlipPlan puts them under the
// next generation, commits with one atomic write, then deletes the old), unchanged ones cost
// no map writes, and frontends for services that no longer exist are removed.
// The DNS zone follows from the same call, so a frontend and the name that
// resolves to it never disagree.
func (d *Datapath) SyncServices(ctx context.Context, services []network.Service) error {
	desired, err := d.desiredFrontends(ctx, services)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	current, err := d.maps.Services()
	if err != nil {
		return fmt.Errorf("datapath: read services: %w", err)
	}

	// Withdraw first, like the VIP allocator: an address moving between
	// services in one pass must not meet its own stale entry.
	for _, key := range sortedSvcKeys(current) {
		if _, keep := desired[key]; keep {
			continue
		}
		val := current[key]
		if err := d.maps.DeleteService(key); err != nil {
			return fmt.Errorf("datapath: delete service %s:%d: %w", key.IP, key.Port, err)
		}
		if err := d.maps.ApplyFlip(key, backendDeletes(val)); err != nil {
			return fmt.Errorf("datapath: delete backends for %s:%d: %w", key.IP, key.Port, err)
		}
		delete(d.applied, key)
	}

	for _, key := range sortedDesiredKeys(desired) {
		want := desired[key]
		cur, exists := current[key]
		if exists {
			if cached, ok := d.applied[key]; ok && cached.equal(want.applied) {
				continue // no drift, no writes
			}
		}
		var oldGen uint32
		var oldCount uint16
		if exists {
			oldGen, oldCount = cur.Gen, cur.Count
		}
		plan := dpmap.FlipPlan(want.applied.id, make([]dpmap.Backend, oldCount), want.applied.backends, oldGen)
		if err := d.maps.ApplyFlip(key, plan); err != nil {
			return fmt.Errorf("datapath: program %s: %w", want.name, err)
		}
		d.applied[key] = want.applied
	}

	// DNS follows the same set of services, so it is published from the same
	// call: a frontend and the name that resolves to it never disagree.
	if d.dns != nil {
		d.dns.SetZone(services)
	}
	return nil
}

// desiredFrontends validates and converts the reconciler's view into per-key
// desired programming, minting frontend ids as needed. A service with a v6
// VIP twin gets a second frontend per port under the same frontend id: the
// v6 set built from the backends' v6 addresses, omitting allocs that have
// none (a pre-v1.41 attachment adopted across the upgrade).
func (d *Datapath) desiredFrontends(ctx context.Context, services []network.Service) (map[dpmap.SvcAddr]desiredSvc, error) {
	desired := make(map[dpmap.SvcAddr]desiredSvc)
	for _, svc := range services {
		if err := svc.Validate(); err != nil {
			return nil, err
		}
		if len(svc.Ports) == 0 {
			continue // nothing to load balance
		}
		vip, err := netip.ParseAddr(svc.VIP)
		if err != nil || !vip.Is4() {
			return nil, fmt.Errorf("datapath: service %s/%s frontend %q is not an IPv4 address",
				svc.Project, svc.Service, svc.VIP)
		}
		var vip6 netip.Addr
		if svc.VIP6 != "" {
			vip6, err = netip.ParseAddr(svc.VIP6)
			if err != nil || !vip6.Is6() || vip6.Is4In6() {
				return nil, fmt.Errorf("datapath: service %s/%s v6 frontend %q is not an IPv6 address",
					svc.Project, svc.Service, svc.VIP6)
			}
		}

		backends := make([]network.Backend, len(svc.Backends))
		copy(backends, svc.Backends)
		sort.Slice(backends, func(i, j int) bool { return backends[i].AllocID < backends[j].AllocID })

		for _, p := range svc.Ports {
			if p.Protocol != "" && p.Protocol != "TCP" {
				// Refused at plan too; this is the second check, for a record
				// that reached the Store another way. A silently dropped port
				// is worse than a refused one.
				return nil, fmt.Errorf("datapath: service %s/%s port %q is %s; service ports are TCP-only",
					svc.Project, svc.Service, p.Name, p.Protocol)
			}
			target := p.TargetPort
			if target == 0 {
				target = p.Port
			}
			id, err := d.ids.FrontendID(ctx, svc.Project, svc.Service, p.Name)
			if err != nil {
				return nil, err
			}

			set := make([]dpmap.Backend, 0, len(backends))
			set6 := make([]dpmap.Backend, 0, len(backends))
			for _, b := range backends {
				addr, err := netip.ParseAddr(b.IPv4)
				if err != nil || !addr.Is4() {
					return nil, fmt.Errorf("datapath: service %s/%s backend %q is not an IPv4 address",
						svc.Project, svc.Service, b.IPv4)
				}
				// #nosec G115; validate bounds ports to 1..65535.
				set = append(set, dpmap.Backend{IP: addr, Port: uint16(target)})
				if !vip6.IsValid() || b.IPv6 == "" {
					// A backend with no v6 half is a pre-v1.41 attachment
					// adopted across the upgrade: the v6 set omits it rather
					// than failing the service (PRD v1.41).
					continue
				}
				addr6, err := netip.ParseAddr(b.IPv6)
				if err != nil || !addr6.Is6() || addr6.Is4In6() {
					return nil, fmt.Errorf("datapath: service %s/%s v6 backend %q is not an IPv6 address",
						svc.Project, svc.Service, b.IPv6)
				}
				set6 = append(set6, dpmap.Backend{IP: addr6, Port: uint16(target)}) // #nosec G115; bounded as above
			}

			// #nosec G115: validate bounds ports to 1..65535.
			key := dpmap.SvcAddr{IP: vip, Port: uint16(p.Port), Proto: protoTCP}
			desired[key] = desiredSvc{
				applied: appliedService{id: id, backends: set},
				name:    svc.Project + "/" + svc.Service,
			}
			if vip6.IsValid() {
				// The v6 twin: same frontend id (stats_svc folds both families
				// into one invocation counter), its own key and backend set.
				// #nosec G115: validate bounds ports to 1..65535.
				key6 := dpmap.SvcAddr{IP: vip6, Port: uint16(p.Port), Proto: protoTCP}
				desired[key6] = desiredSvc{
					applied: appliedService{id: id, backends: set6},
					name:    svc.Project + "/" + svc.Service,
				}
			}
		}
	}
	return desired, nil
}

// backendDeletes emits the delete ops for a withdrawn service's backend set.
func backendDeletes(val dpmap.SvcVal) []dpmap.Op {
	ops := make([]dpmap.Op, 0, val.Count)
	for i := uint16(0); i < val.Count; i++ {
		ops = append(ops, dpmap.Op{
			Kind: dpmap.OpDeleteBackend,
			Key:  dpmap.BackendKey{SvcID: val.SvcID, Index: i, Gen: val.Gen},
		})
	}
	return ops
}

// svcKeyLess orders map keys so every pass walks frontends the same way: a
// test, and a log, should be reproducible. netip.Addr.Compare orders v4
// before v6, so the families interleave deterministically too.
func svcKeyLess(a, b dpmap.SvcAddr) bool {
	if c := a.IP.Compare(b.IP); c != 0 {
		return c < 0
	}
	return a.Port < b.Port
}

func sortedSvcKeys(m map[dpmap.SvcAddr]dpmap.SvcVal) []dpmap.SvcAddr {
	keys := make([]dpmap.SvcAddr, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return svcKeyLess(keys[i], keys[j]) })
	return keys
}

func sortedDesiredKeys(m map[dpmap.SvcAddr]desiredSvc) []dpmap.SvcAddr {
	keys := make([]dpmap.SvcAddr, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return svcKeyLess(keys[i], keys[j]) })
	return keys
}
