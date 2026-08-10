package datapath

import (
	"context"
	"net/netip"

	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// Counters is the raw view of the datapath's per-CPU counters. The linux
// implementation sums across CPUs; tests substitute fixed maps. East-west
// metrics come from here, on by default (PRD v1.36) — they never touch the
// Store (constraint #2).
type Counters interface {
	// ServiceConnects returns cumulative connect counts per frontend id.
	// stats_svc is id-keyed and family-neutral, so a connect to a v6 VIP
	// counts against the same frontend as its v4 twin — which is what keeps
	// function invocation metrics whole under dual-stack (v1.41).
	ServiceConnects() (map[uint16]uint64, error)
	// Drops returns cumulative drop counts per destination and reason,
	// merged across stats_drops and stats_drops6 — the address carries the
	// family.
	Drops() (map[dpmap.DropEntry]uint64, error)
	// EndpointStats returns cumulative per-alloc byte/packet counters,
	// merged across stats_ep and stats_ep6.
	EndpointStats() (map[netip.Addr]dpmap.EpStats, error)
}

// CounterSource joins the numeric ids in the counters back to names, which is
// the shape internal/scaling consumes: per-service connects keyed by
// "project/service", feeding flows_per_second with its meaning unchanged.
type CounterSource struct {
	counters Counters
	ids      *idAllocator
}

// ServiceConnects returns cumulative connects per "project/service". Multiple
// port frontends of one service fold into one number. Ids the Store no longer
// explains — counters surviving from before a pin-dir rebuild — are skipped
// rather than invented a name for.
func (s *CounterSource) ServiceConnects(ctx context.Context) (map[string]uint64, error) {
	raw, err := s.counters.ServiceConnects()
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(raw))
	for id, n := range raw {
		ref, ok, err := s.ids.FrontendService(ctx, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out[ref.String()] += n
	}
	return out, nil
}

// Drops returns cumulative drops per destination address and reason, exactly
// as the datapath counted them.
func (s *CounterSource) Drops() (map[dpmap.DropEntry]uint64, error) {
	return s.counters.Drops()
}

// EndpointStats returns cumulative per-alloc traffic counters keyed by the
// alloc's address; Attachments is where an address becomes an alloc.
func (s *CounterSource) EndpointStats() (map[netip.Addr]dpmap.EpStats, error) {
	return s.counters.EndpointStats()
}
