package datapath

import (
	"fmt"
	"net/netip"
	"strings"
)

// devPrefix marks every interface the datapath owns. Together with the alias
// it is the ownership mark that makes enumeration — and therefore the reaper —
// safe.
const devPrefix = "kn"

// aliasPrefix opens every ownership alias: "kanea/<allocID>/<ip>".
const aliasPrefix = "kanea/"

// aliasFor renders the ownership alias for an attachment.
func aliasFor(allocID string, ip netip.Addr) string {
	return aliasPrefix + allocID + "/" + ip.String()
}

// parseAlias reads an ownership alias back. Anything that does not parse is
// not ours, whatever the interface is called.
func parseAlias(alias string) (allocID string, ip netip.Addr, ok bool) {
	rest, found := strings.CutPrefix(alias, aliasPrefix)
	if !found {
		return "", netip.Addr{}, false
	}
	id, ipStr, found := strings.Cut(rest, "/")
	if !found || id == "" {
		return "", netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return "", netip.Addr{}, false
	}
	return id, addr, true
}

// ipam hands out alloc addresses from the node CIDR. It is deliberately not
// stored: the state is derived, rebuilt from the marked veths at startup, so a
// leaked reservation cannot outlive the interface that holds it.
//
// It is not safe for concurrent use; the Datapath's mutex serialises access.
type ipam struct {
	prefix    netip.Prefix
	host      netip.Addr // the .1 anchor, never allocated
	broadcast netip.Addr
	byIP      map[netip.Addr]string
	byAlloc   map[string]netip.Addr
}

func newIPAM(nodeCIDR netip.Prefix) *ipam {
	masked := nodeCIDR.Masked()
	return &ipam{
		prefix:    masked,
		host:      masked.Addr().Next(),
		broadcast: broadcastOf(masked),
		byIP:      map[netip.Addr]string{},
		byAlloc:   map[string]netip.Addr{},
	}
}

// Reserve returns the alloc's address, allocating the lowest free one if it
// has none. Lowest-free rather than sequential-from-a-cursor: deterministic,
// reuses released addresses, and keeps the pool dense enough to read.
func (p *ipam) Reserve(allocID string) (netip.Addr, error) {
	if ip, ok := p.byAlloc[allocID]; ok {
		return ip, nil
	}
	// Skip the network address; .1 and the broadcast are skipped below.
	addr := p.prefix.Addr().Next()
	for p.prefix.Contains(addr) {
		if addr != p.host && addr != p.broadcast {
			if _, taken := p.byIP[addr]; !taken {
				p.byIP[addr] = allocID
				p.byAlloc[allocID] = addr
				return addr, nil
			}
		}
		addr = addr.Next()
	}
	return netip.Addr{}, fmt.Errorf("datapath: node CIDR %s is exhausted (%d allocated)", p.prefix, len(p.byIP))
}

// Adopt records an existing attachment's address, e.g. one found on an
// already-attached link during an idempotent re-attach.
func (p *ipam) Adopt(allocID string, ip netip.Addr) {
	if prev, ok := p.byAlloc[allocID]; ok && prev != ip {
		delete(p.byIP, prev)
	}
	p.byAlloc[allocID] = ip
	p.byIP[ip] = allocID
}

// Lookup returns the alloc's reservation, if it has one.
func (p *ipam) Lookup(allocID string) (netip.Addr, bool) {
	ip, ok := p.byAlloc[allocID]
	return ip, ok
}

// Release frees the alloc's reservation. Missing is a no-op.
func (p *ipam) Release(allocID string) {
	if ip, ok := p.byAlloc[allocID]; ok {
		delete(p.byIP, ip)
		delete(p.byAlloc, allocID)
	}
}

// Len reports how many addresses are reserved.
func (p *ipam) Len() int { return len(p.byAlloc) }

// Rebuild replaces the reservation state with what the marked veths say.
// Aliases that do not parse, or addresses outside the pool, are ignored: they
// are not ours to account for.
func (p *ipam) Rebuild(links []Link) {
	p.byIP = map[netip.Addr]string{}
	p.byAlloc = map[string]netip.Addr{}
	for _, l := range links {
		if !strings.HasPrefix(l.Name, devPrefix) {
			continue
		}
		allocID, ip, ok := parseAlias(l.Alias)
		if !ok || !p.prefix.Contains(ip) {
			continue
		}
		p.byIP[ip] = allocID
		p.byAlloc[allocID] = ip
	}
}

// broadcastOf computes the highest address of a v4 prefix.
func broadcastOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	mask := maskFor(p)
	for i := range a {
		a[i] |= ^mask[i]
	}
	return netip.AddrFrom4(a)
}
