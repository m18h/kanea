package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// The history seed: one range read of the in-memory time series, served both by
// GET /v1/stats/history and on the first frame of a stats or node websocket
// subscription (PRD v1.79, §9.1, §12.1).
//
// One builder, two surfaces, for the reason serviceViews has one: the two would
// otherwise drift about what a window means, which tier answers it, and which
// series a view carries, and the drift would only be visible as a chart drawn
// at the wrong scale.

// HistoryBlock is a set of sparse series over one window at one resolution.
//
// A gap is an absent point, never a zero (§9.2): the ring's unwritten slots are
// simply not serialised, so this surface cannot get the rule wrong. The interval
// is what lets a client rebuild fixed slots and put the gaps back.
//
// A series present with a null value means "asked for, nothing recorded"; a
// series absent from the map means "not asked for". Those are different facts,
// which is why the nil slice is left as it comes rather than replaced with an
// empty one.
type HistoryBlock struct {
	From            time.Time                  `json:"from"`
	To              time.Time                  `json:"to"`
	IntervalSeconds int                        `json:"interval_seconds"`
	Series          map[string][]scaling.Point `json:"series"`
}

// StatsHistorySeed is a history block riding a websocket frame, with the
// per-alloc breakdown an allocs table needs.
type StatsHistorySeed struct {
	HistoryBlock
	// Allocs is keyed by alloc id, over its own shorter window: an allocs table
	// draws sparklines, not charts.
	Allocs map[string]HistoryBlock `json:"allocs,omitempty"`
	// AllocsOmitted says the alloc half did not fit the point budget and was
	// dropped whole. Stated rather than silent, so a table of empty sparklines
	// has a cause a client can name.
	AllocsOmitted bool `json:"allocs_omitted,omitempty"`
}

// Window bounds for a seed request.
const (
	// allocSeedWindow is the alloc half's own window. A sparkline is sixty
	// pixels wide, so seeding it with the service chart's window is twelve
	// times the points for a drawing that cannot show them.
	allocSeedWindow = 5 * time.Minute
	// maxSeedPoints bounds the points in one seed across every series in it.
	// Stats is not a lossy topic, so an oversized frame is not dropped: it is
	// written under the write timeout to a client that may be slow, and it is
	// allocated per subscriber. The figure is the same order as maxBatchBytes
	// and chosen the same way.
	maxSeedPoints = 3000
)

// seedRequest is what a caller wants seeded.
type seedRequest struct {
	// window is the range, already clamped by clampWindow.
	window time.Duration
	// series names the series to serve. Empty means the view's default set,
	// which is deliberately what v1.38 and v1.42 shipped: a request that names
	// nothing must produce exactly the bytes it always did.
	series []string
	// allocs adds the per-alloc breakdown, for a service view only.
	allocs bool
}

// clampWindow bounds a requested window to what the rings can answer.
//
// The ceiling is the rollup tier's retention: asking for more would read an
// empty ring and look like a quiet week.
func clampWindow(window time.Duration) time.Duration {
	return min(max(window, minHistoryWindow), scaling.RollupWindow)
}

// The series each view may serve, keyed by the name on the wire.
//
// Fixed lists rather than the store's open key space, the same rule `exported`
// follows in metrics.go: a new internal metric must not become a new public one
// by accident. The default sets are what v1.38 and v1.42 shipped and must stay
// that way; everything else is reachable through the selector, which is what
// makes the rest seedable without making the common frame bigger.
var (
	serviceSeries = map[string]string{
		"cpu":              scaling.MetricCPU,
		"memory":           scaling.MetricMemory,
		"rps":              scaling.MetricRPS,
		"p50_latency_ms":   scaling.MetricP50,
		"p95_latency_ms":   scaling.MetricP95,
		"p99_latency_ms":   scaling.MetricP99,
		"error_rate":       scaling.MetricErrorRate,
		"flows_per_second": scaling.MetricFlows,
		"drops_per_second": scaling.MetricDrops,
	}
	defaultServiceSeries = []string{"cpu", "memory", "rps", "p95_latency_ms"}

	allocSeries = map[string]string{
		"cpu":          scaling.MetricCPU,
		"memory":       scaling.MetricMemory,
		"memory_bytes": scaling.MetricMemoryBytes,
		"pids":         scaling.MetricPIDs,
	}
	// Exactly what AllocStats carries on the live frame, so a sparkline's seed
	// and its live samples are the same three numbers.
	defaultAllocSeries = []string{"cpu", "memory", "memory_bytes"}

	// gpu_util (v1.94) is deliberately absent: this set is what a client that
	// names nothing receives, so adding to it changes the bytes an existing
	// caller already gets. It is available by name, which is how the dashboard
	// asks for it. TestThePreV179RequestIsUnchanged is the guard.
	defaultNodeSeries = []string{"cpu", "memory", "gpu_vram", "rps", "p95_latency_ms"}
)

// nodeSeriesDef says how one node series is produced: read directly off the
// node subject, or aggregated across services at read time.
type nodeSeriesDef struct {
	// metric is the series to read (direct) or to aggregate (sum, weighted).
	metric string
	// kind is "direct", "sum" or "weighted".
	kind string
	// weightBy is the weighting series, for kind "weighted".
	weightBy string
	// withNode adds the node subject's own recording to a sum. The datapath
	// records unattributable east-west traffic under "node", and a total that
	// left it out would be missing exactly the traffic nobody could attribute.
	withNode bool
}

var nodeSeries = map[string]nodeSeriesDef{
	"cpu":            {metric: scaling.MetricNodeCPU, kind: "direct"},
	"memory":         {metric: scaling.MetricNodeMemory, kind: "direct"},
	"gpu_util":       {metric: scaling.MetricNodeGPUUtil, kind: "direct"},
	"gpu_vram":       {metric: scaling.MetricNodeGPU, kind: "direct"},
	"load1":          {metric: scaling.MetricNodeLoad1, kind: "direct"},
	"allocs_running": {metric: scaling.MetricNodeAllocsRunning, kind: "direct"},
	"rps":            {metric: scaling.MetricRPS, kind: "sum"},
	// An rps-weighted mean of per-service p95s, which is an approximation:
	// percentiles do not aggregate. Stated here and in the PRD rather than
	// silently presented as a measurement.
	"p95_latency_ms":   {metric: scaling.MetricP95, kind: "weighted", weightBy: scaling.MetricRPS},
	"flows_per_second": {metric: scaling.MetricFlows, kind: "sum", withNode: true},
	"drops_per_second": {metric: scaling.MetricDrops, kind: "sum", withNode: true},
}

// resolveSeries turns requested names into the names to serve, refusing an
// unknown one by name.
//
// Refused rather than dropped: a chart seeded with nothing looks exactly like a
// service that has served nothing, and a typo that reads as an outage is the
// kind of silence §9.2 exists to prevent.
func resolveSeries(requested, fallback []string, known func(string) bool, view string) ([]string, error) {
	if len(requested) == 0 {
		return fallback, nil
	}
	out := make([]string, 0, len(requested))
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !known(name) {
			return nil, fmt.Errorf("api: %q is not a %s series", name, view)
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return fallback, nil
	}
	return out, nil
}

// parseSeriesList splits a comma-separated selector.
func parseSeriesList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// rangeFor is the slot-aligned range a window covers, with the resolution the
// store will actually answer at.
//
// Truncated to a raw slot rather than taken as "now": the ring's own slots are
// on that grid, so an untruncated range asks for a fraction of a slot at each
// end and no two answers are comparable; the aggregate memo can only key on a
// slot if the range is one; and it removes the epsilon that used to tip an
// exactly-one-hour window into the rollup while the response advertised the raw
// interval (v1.79).
func (s *Server) rangeFor(window time.Duration) (from, to time.Time, interval time.Duration) {
	to = s.now().Truncate(scaling.RawInterval)
	from = to.Add(-window)
	return from, to, s.metrics.RangeInterval(from, to)
}

// buildServiceHistory reads one service's series.
func (s *Server) buildServiceHistory(subject string, req seedRequest) (HistoryBlock, error) {
	names, err := resolveSeries(req.series, defaultServiceSeries,
		func(n string) bool { _, ok := serviceSeries[n]; return ok }, "service")
	if err != nil {
		return HistoryBlock{}, err
	}

	from, to, interval := s.rangeFor(req.window)
	block := HistoryBlock{
		From: from, To: to,
		IntervalSeconds: int(interval / time.Second),
		Series:          make(map[string][]scaling.Point, len(names)),
	}
	for _, name := range names {
		block.Series[name] = s.metrics.Range(
			scaling.Key{Subject: subject, Metric: serviceSeries[name]}, from, to)
	}
	return block, nil
}

// buildNodeHistory reads the node's own series and the read-time aggregates.
func (s *Server) buildNodeHistory(req seedRequest) (HistoryBlock, error) {
	names, err := resolveSeries(req.series, defaultNodeSeries,
		func(n string) bool { _, ok := nodeSeries[n]; return ok }, "node")
	if err != nil {
		return HistoryBlock{}, err
	}

	from, to, interval := s.rangeFor(req.window)
	block := HistoryBlock{
		From: from, To: to,
		IntervalSeconds: int(interval / time.Second),
		Series:          make(map[string][]scaling.Point, len(names)),
	}
	for _, name := range names {
		def := nodeSeries[name]
		switch def.kind {
		case "sum":
			block.Series[name] = s.sumSeries(def.metric, from, to, def.withNode)
		case "weighted":
			block.Series[name] = s.weightedSeries(def.metric, def.weightBy, from, to)
		default:
			block.Series[name] = s.metrics.Range(
				scaling.Key{Subject: scaling.NodeSubject, Metric: def.metric}, from, to)
		}
	}
	return block, nil
}

// buildAllocHistory reads the per-alloc breakdown for one service.
//
// The alloc set comes from the Store rather than from the ring's key space, for
// the reason statsFor's own comment gives: an alloc that started a second ago
// has a record and no samples, and leaving it out would make it look like it
// does not exist. It also means the seed's alloc set is *identical* to the live
// sample's, so nothing seeds a row the live frames will never feed.
//
// The whole map is dropped when it does not fit rather than truncated to a
// shorter window: two windows in one frame is a client rebuilding slots against
// the wrong interval, which draws a wrong chart rather than no chart.
func (s *Server) buildAllocHistory(ctx context.Context, subject string, spent int) (map[string]HistoryBlock, bool) {
	allocs, err := s.allocsAtCurrentIndex(ctx)
	if err != nil {
		s.log.Debug("history seed: cannot list allocs", "error", err)
		return nil, false
	}

	var ids []string
	for _, alloc := range allocs {
		if alloc.Project+"/"+alloc.Service == subject {
			ids = append(ids, alloc.ID)
		}
	}
	if len(ids) == 0 {
		return nil, false
	}
	sort.Strings(ids)

	from, to, interval := s.rangeFor(allocSeedWindow)
	slots := int(to.Sub(from)/interval) + 1
	if spent+len(ids)*len(defaultAllocSeries)*slots > maxSeedPoints {
		return nil, true
	}

	out := make(map[string]HistoryBlock, len(ids))
	for _, id := range ids {
		block := HistoryBlock{
			From: from, To: to,
			IntervalSeconds: int(interval / time.Second),
			Series:          make(map[string][]scaling.Point, len(defaultAllocSeries)),
		}
		for _, name := range defaultAllocSeries {
			block.Series[name] = s.metrics.Range(
				scaling.Key{Subject: subject + "/" + id, Metric: allocSeries[name]}, from, to)
		}
		out[id] = block
	}
	return out, false
}

// buildSeed assembles the seed a websocket subscription carries.
//
// subject is scaling.NodeSubject for the node view and "project/service"
// otherwise; the alloc half applies only to the latter.
func (s *Server) buildSeed(ctx context.Context, subject string, req seedRequest) (*StatsHistorySeed, error) {
	var block HistoryBlock
	var err error
	if subject == scaling.NodeSubject {
		block, err = s.buildNodeHistory(req)
	} else {
		block, err = s.buildServiceHistory(subject, req)
	}
	if err != nil {
		return nil, err
	}

	seed := &StatsHistorySeed{HistoryBlock: block}
	if req.allocs && subject != scaling.NodeSubject {
		seed.Allocs, seed.AllocsOmitted = s.buildAllocHistory(ctx, subject, countPoints(block))
	}
	return seed, nil
}

// countPoints is how much of the budget a block has already spent.
func countPoints(block HistoryBlock) int {
	total := 0
	for _, points := range block.Series {
		total += len(points)
	}
	return total
}
