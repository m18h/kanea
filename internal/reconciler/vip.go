package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/store"
)

// DefaultServiceCIDR is the pool service frontends are allocated from
// (PRD §15.1 `service_cidr`). It is deliberately outside the endpoint CIDR:
// a VIP is not an address any alloc owns.
const DefaultServiceCIDR = "10.201.0.0/16"

// vipKeyPrefix namespaces VIP assignments in the KV bucket.
const vipKeyPrefix = "lb/vip/"

// vip6KeyPrefix namespaces the v6 twins (v1.41). A separate key space, so
// the lb/vip/ records stay byte-identical — a rollback, or a replicated
// Store read by a v4-only node, parses unchanged.
const vip6KeyPrefix = "lb/vip6/"

// VIPKey is where one service's frontend address is remembered.
func VIPKey(project, service string) string { return vipKeyPrefix + project + "/" + service }

// VIP6Key is where one service's v6 frontend twin is remembered (v1.41).
func VIP6Key(project, service string) string { return vip6KeyPrefix + project + "/" + service }

// vipAllocator hands out service frontend addresses and remembers them.
//
// The assignment is durable, and that is not an optimisation. A VIP is the
// address DNS answers with and clients cache, so it has to outlive the thing
// that programs it — the agent's LB state is rebuilt from scratch after a
// restart, and a service whose frontend moved would have every existing client
// pointing at nothing. Constraint #9 says datapath state must be rebuildable
// from the Store; that only works if the Store is where the assignment lives.
type vipAllocator struct {
	store  Store
	prefix netip.Prefix
	// prefix6 is the v6 twin pool (v1.41); invalid means v4-only. With v6
	// off, the lb/vip6/ key space is left exactly as it is — stale twins
	// from a formerly-enabled node are released only when v6 is enabled
	// again, never silently deleted.
	prefix6 netip.Prefix
}

func newVIPAllocator(st Store, cidr, cidr6 string) (*vipAllocator, error) {
	if cidr == "" {
		cidr = DefaultServiceCIDR
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("service CIDR %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("service CIDR %q: v4 frontends come from a v4 pool; --service-cidr6 is the v6 half", cidr)
	}
	a := &vipAllocator{store: st, prefix: prefix.Masked()}
	if cidr6 != "" {
		prefix6, err := netip.ParsePrefix(cidr6)
		if err != nil {
			return nil, fmt.Errorf("service CIDR6 %q: %w", cidr6, err)
		}
		if !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() {
			return nil, fmt.Errorf("service CIDR6 %q is not an IPv6 prefix", cidr6)
		}
		a.prefix6 = prefix6.Masked()
	}
	return a, nil
}

// Sync makes the set of VIP assignments match the given services: every service
// gets one (a v4 address always, plus a v6 twin when the allocator has a v6
// pool), and assignments for services that no longer exist are released.
//
// It returns the full mappings, keyed by "project/service"; the second map is
// nil when v6 is off. Both families move in one Apply batch.
func (a *vipAllocator) Sync(ctx context.Context, services []serviceRef) (map[string]string, map[string]string, error) {
	assigned, err := a.load(ctx, vipKeyPrefix)
	if err != nil {
		return nil, nil, err
	}
	var assigned6 map[string]string
	if a.prefix6.IsValid() {
		if assigned6, err = a.load(ctx, vip6KeyPrefix); err != nil {
			return nil, nil, err
		}
	}

	wanted := make(map[string]struct{}, len(services))
	for _, svc := range services {
		wanted[svc.key()] = struct{}{}
	}

	var muts []store.Mutation

	// Release first, so a rename (delete one service, add another) can reuse
	// the freed address in the same pass instead of leaking it until the next.
	inUse := make(map[string]struct{}, len(assigned))
	for key, ip := range assigned {
		if _, keep := wanted[key]; !keep {
			muts = append(muts, store.DeleteMutation(store.KindKV, vipKeyPrefix+key))
			delete(assigned, key)
			continue
		}
		inUse[ip] = struct{}{}
	}
	inUse6 := make(map[string]struct{}, len(assigned6))
	for key, ip := range assigned6 {
		if _, keep := wanted[key]; !keep {
			muts = append(muts, store.DeleteMutation(store.KindKV, vip6KeyPrefix+key))
			delete(assigned6, key)
			continue
		}
		inUse6[ip] = struct{}{}
	}

	// Allocate in a stable order so the same set of new services always lands
	// on the same addresses — a test, and a rebuild, should be reproducible.
	for _, svc := range sortedRefs(services) {
		key := svc.key()
		if _, ok := assigned[key]; !ok {
			ip, err := nextFree(a.prefix, inUse)
			if err != nil {
				return nil, nil, fmt.Errorf("allocate frontend for %s: %w", key, err)
			}
			assigned[key] = ip
			inUse[ip] = struct{}{}

			mut, err := store.PutMutation(store.KindKV, vipKeyPrefix+key, ip)
			if err != nil {
				return nil, nil, err
			}
			muts = append(muts, mut)
		}
		if !a.prefix6.IsValid() {
			continue
		}
		if _, ok := assigned6[key]; !ok {
			ip6, err := nextFree(a.prefix6, inUse6)
			if err != nil {
				return nil, nil, fmt.Errorf("allocate v6 frontend for %s: %w", key, err)
			}
			assigned6[key] = ip6
			inUse6[ip6] = struct{}{}

			mut, err := store.PutMutation(store.KindKV, vip6KeyPrefix+key, ip6)
			if err != nil {
				return nil, nil, err
			}
			muts = append(muts, mut)
		}
	}

	if len(muts) > 0 {
		if _, err := a.store.Apply(ctx, muts...); err != nil {
			return nil, nil, fmt.Errorf("persist frontend addresses: %w", err)
		}
	}
	return assigned, assigned6, nil
}

// nextFree returns the lowest unused address in the pool.
//
// Lowest-free rather than random or sequential-from-a-cursor: it is
// deterministic, it reuses released addresses, and it keeps assignments dense
// enough that an operator reading `kanea status` sees something comprehensible.
func nextFree(prefix netip.Prefix, inUse map[string]struct{}) (string, error) {
	// Skip the network address itself; the first usable frontend is .1.
	addr := prefix.Addr().Next()
	for prefix.Contains(addr) {
		s := addr.String()
		if _, taken := inUse[s]; !taken {
			return s, nil
		}
		addr = addr.Next()
	}
	return "", fmt.Errorf("service CIDR %s is exhausted (%d assigned)", prefix, len(inUse))
}

// load reads every existing assignment under one key prefix.
func (a *vipAllocator) load(ctx context.Context, prefix string) (map[string]string, error) {
	out := map[string]string{}
	opts := store.ListOptions{Prefix: prefix}
	for {
		page, err := a.store.List(ctx, store.KindKV, opts)
		if err != nil {
			return nil, fmt.Errorf("load frontend addresses: %w", err)
		}
		for _, rec := range page.Records {
			// Decoded here rather than through store.ListValues because the key
			// is half the record: it says which service the address belongs to.
			var ip string
			if err := json.Unmarshal(rec.Value, &ip); err != nil {
				return nil, fmt.Errorf("decode frontend address %s: %w", rec.Key, err)
			}
			out[strings.TrimPrefix(rec.Key, prefix)] = ip
		}
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// serviceRef names one service.
type serviceRef struct {
	Project string
	Service string
}

func (r serviceRef) key() string { return r.Project + "/" + r.Service }

func sortedRefs(refs []serviceRef) []serviceRef {
	out := make([]serviceRef, len(refs))
	copy(out, refs)
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}
