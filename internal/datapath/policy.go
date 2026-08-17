package datapath

import (
	"context"
	"fmt"
	"sort"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

// SyncPolicies makes allow_v4 match the declared cross-project allowlists
// (PRD §6.2 R14): one {dst_service_id, src_service_id} edge per allow_from
// entry, missing edges added, stale edges removed.
//
// Only these edges live in the map. Project isolation, the host pass and the
// SYN gate are the BPF program's own logic over identity_v4: there is no
// "default deny" entry to manage, so an empty desired set empties the map.
func (d *Datapath) SyncPolicies(ctx context.Context, projects []network.ProjectPolicy) error {
	desired := make(map[dpmap.AllowKey]struct{})
	for _, p := range projects {
		if err := validateName("project", p.Project); err != nil {
			return err
		}
		for _, sp := range p.Services {
			dst, err := d.ids.ServiceID(ctx, p.Project, sp.Service)
			if err != nil {
				return err
			}
			for _, ref := range sp.AllowFrom {
				src, err := d.ids.ServiceID(ctx, ref.Project, ref.Service)
				if err != nil {
					return err
				}
				desired[dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src}] = struct{}{}
			}
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	current, err := d.maps.Allows()
	if err != nil {
		return fmt.Errorf("datapath: read allows: %w", err)
	}

	// Add before delete: a rule moving between representations must never
	// have a window with neither present.
	for _, key := range sortedAllowKeys(desired) {
		if _, ok := current[key]; ok {
			continue
		}
		if err := d.maps.PutAllow(key.DstServiceID, key.SrcServiceID); err != nil {
			return fmt.Errorf("datapath: allow %d<-%d: %w", key.DstServiceID, key.SrcServiceID, err)
		}
	}
	for _, key := range sortedAllowKeys(current) {
		if _, keep := desired[key]; keep {
			continue
		}
		if err := d.maps.DeleteAllow(key.DstServiceID, key.SrcServiceID); err != nil {
			return fmt.Errorf("datapath: withdraw allow %d<-%d: %w", key.DstServiceID, key.SrcServiceID, err)
		}
	}
	return nil
}

func sortedAllowKeys(m map[dpmap.AllowKey]struct{}) []dpmap.AllowKey {
	keys := make([]dpmap.AllowKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].DstServiceID != keys[j].DstServiceID {
			return keys[i].DstServiceID < keys[j].DstServiceID
		}
		return keys[i].SrcServiceID < keys[j].SrcServiceID
	})
	return keys
}
