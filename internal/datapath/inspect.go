package datapath

import (
	"context"
	"fmt"
	"strings"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

// Attachments lists every attachment the datapath owns, keyed by alloc id.
//
// This is the authoritative source of alloc IPs — a live query, never
// something the Store remembers (constraint #9). It is also what the reaper
// deletes from, so the filter is the safety property: an interface is reported
// only when it carries both ownership marks, the "kn" name prefix AND an alias
// that parses as kanea/<alloc>/<ip>. A dummy, a bridge, or another tool's veth
// must never appear in a set the caller is about to tear down.
//
// An attachment whose identity is missing reports Ready=false: it exists but
// its traffic is dropped (the tc program fails closed on an identity miss), so
// it is not fit to receive traffic and the reaper is free to detach it.
func (d *Datapath) Attachments(ctx context.Context) (map[string]network.Attachment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	links, err := d.nl.List()
	if err != nil {
		return nil, fmt.Errorf("datapath: list links: %w", err)
	}
	idents, err := d.maps.Identities()
	if err != nil {
		return nil, fmt.Errorf("datapath: read identities: %w", err)
	}

	out := make(map[string]network.Attachment, len(links))
	for _, l := range links {
		if !strings.HasPrefix(l.Name, devPrefix) {
			continue // not ours, whatever the alias claims
		}
		allocID, ip, ip6, ok := parseAlias(l.Alias)
		if !ok {
			continue // marked name without our alias: not provably ours
		}
		att := network.Attachment{AllocID: allocID, IPv4: ip.String()}
		if ip6.IsValid() {
			att.IPv6 = ip6.String()
		}
		// Ready gates on the v4 identity alone: v4 is the required family,
		// and a v4-only attachment adopted across the dual-stack upgrade is
		// complete as it stands (PRD v1.41).
		if id, present := idents[ip]; present && id.Flags&dpmap.IdentityFlagHost == 0 {
			att.Ready = true
			if ref, found, err := d.ids.ServiceName(ctx, id.ServiceID); err != nil {
				return nil, err
			} else if found {
				att.Service = ref
			}
		}
		out[allocID] = att
	}
	return out, nil
}
