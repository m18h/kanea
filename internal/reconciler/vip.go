package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"github.com/kanea-dev/kanea/internal/store"
)

// DefaultServiceCIDR is the pool service frontends are allocated from
// (PRD §15.1 `service_cidr`). It is deliberately outside the endpoint CIDR:
// a VIP is not an address any alloc owns.
const DefaultServiceCIDR = "10.201.0.0/16"

// vipKeyPrefix namespaces VIP assignments in the KV bucket.
const vipKeyPrefix = "lb/vip/"

// VIPKey is where one service's frontend address is remembered.
func VIPKey(project, service string) string { return vipKeyPrefix + project + "/" + service }

// vipAllocator hands out service frontend addresses and remembers them.
//
// The assignment is durable, and that is not an optimisation. A VIP is the
// address DNS answers with and clients cache, so it has to outlive the thing
// that programs it — the agent's LB state is rebuilt from scratch after a
// restart, and a service whose frontend moved would have every existing client
// pointing at nothing. Constraint #9 says Cilium state must be rebuildable from
// the Store; that only works if the Store is where the assignment lives.
type vipAllocator struct {
	store  Store
	prefix netip.Prefix
}

func newVIPAllocator(st Store, cidr string) (*vipAllocator, error) {
	if cidr == "" {
		cidr = DefaultServiceCIDR
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("service CIDR %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("service CIDR %q: only IPv4 is supported in v1", cidr)
	}
	return &vipAllocator{store: st, prefix: prefix.Masked()}, nil
}

// Sync makes the set of VIP assignments match the given services: every service
// gets one, and assignments for services that no longer exist are released.
//
// It returns the full mapping, keyed by "project/service".
func (a *vipAllocator) Sync(ctx context.Context, services []serviceRef) (map[string]string, error) {
	assigned, err := a.load(ctx)
	if err != nil {
		return nil, err
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

	// Allocate in a stable order so the same set of new services always lands
	// on the same addresses — a test, and a rebuild, should be reproducible.
	for _, svc := range sortedRefs(services) {
		key := svc.key()
		if _, ok := assigned[key]; ok {
			continue
		}
		ip, err := a.nextFree(inUse)
		if err != nil {
			return nil, fmt.Errorf("allocate frontend for %s: %w", key, err)
		}
		assigned[key] = ip
		inUse[ip] = struct{}{}

		mut, err := store.PutMutation(store.KindKV, vipKeyPrefix+key, ip)
		if err != nil {
			return nil, err
		}
		muts = append(muts, mut)
	}

	if len(muts) > 0 {
		if _, err := a.store.Apply(ctx, muts...); err != nil {
			return nil, fmt.Errorf("persist frontend addresses: %w", err)
		}
	}
	return assigned, nil
}

// nextFree returns the lowest unused address in the pool.
//
// Lowest-free rather than random or sequential-from-a-cursor: it is
// deterministic, it reuses released addresses, and it keeps assignments dense
// enough that an operator reading `kanea status` sees something comprehensible.
func (a *vipAllocator) nextFree(inUse map[string]struct{}) (string, error) {
	// Skip the network address itself; the first usable frontend is .1.
	addr := a.prefix.Addr().Next()
	for a.prefix.Contains(addr) {
		s := addr.String()
		if _, taken := inUse[s]; !taken {
			return s, nil
		}
		addr = addr.Next()
	}
	return "", fmt.Errorf("service CIDR %s is exhausted (%d assigned)", a.prefix, len(inUse))
}

// load reads every existing assignment.
func (a *vipAllocator) load(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	opts := store.ListOptions{Prefix: vipKeyPrefix}
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
			out[trimVIPKey(rec.Key)] = ip
		}
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

func trimVIPKey(key string) string {
	if len(key) > len(vipKeyPrefix) && key[:len(vipKeyPrefix)] == vipKeyPrefix {
		return key[len(vipKeyPrefix):]
	}
	return key
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
