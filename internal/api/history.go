package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// PathStatsHistory serves ranged reads of the in-memory time series (v1.38).
//
// It exists so a freshly opened page can seed its sparklines instead of
// accumulating from zero: the rings already hold the history, and until this
// route they had no reader outside the process.
const PathStatsHistory = "/v1/stats/history"

// Window bounds. The default answers what a sparkline shows; the ceiling is
// the rollup tier's retention: asking for more would read an empty ring and
// look like a quiet week.
const (
	defaultHistoryWindow = 15 * time.Minute
	minHistoryWindow     = time.Minute
)

// HistoryResponse is a set of sparse series over one window.
//
// A gap is an absent point, never a zero (§9.2): the ring's unwritten slots
// are simply not serialised, so this surface cannot get the rule wrong. The
// interval lets a client rebuild fixed slots and place the gaps.
// The embedded block keeps the pre-v1.79 wire shape exactly: an embedded
// struct's fields are flattened in place, so this still marshals as subject,
// from, to, interval_seconds, series, in that order, plus two omitempty
// additions that a request naming no allocs never produces.
type HistoryResponse struct {
	Subject string `json:"subject"`
	HistoryBlock
	// Allocs is the per-alloc breakdown (v1.79), served only when asked for.
	Allocs        map[string]HistoryBlock `json:"allocs,omitempty"`
	AllocsOmitted bool                    `json:"allocs_omitted,omitempty"`
}

// handleStatsHistory serves a service's history, or the node's when no
// service is named.
func (s *Server) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		writeError(w, http.StatusServiceUnavailable, errNoMetrics)
		return
	}

	q := r.URL.Query()
	project, service := q.Get("project"), q.Get("service")
	if (project == "") != (service == "") {
		writeError(w, http.StatusBadRequest,
			errors.New("api: a service history needs both project and service"))
		return
	}

	window := defaultHistoryWindow
	if raw := q.Get("window"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("api: window is not a duration"))
			return
		}
		window = parsed
	}

	subject := scaling.NodeSubject
	if project != "" {
		subject = project + "/" + service
	}
	req := seedRequest{
		window: clampWindow(window),
		series: parseSeriesList(q.Get("series")),
		allocs: q.Get("allocs") == "true",
	}

	// The same builder the websocket seed uses (v1.79): one implementation of
	// what a window means, which tier answers it and which series a view
	// carries, so the two surfaces cannot drift.
	seed, err := s.buildSeed(r.Context(), subject, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	out := HistoryResponse{
		Subject:       subject,
		HistoryBlock:  seed.HistoryBlock,
		Allocs:        seed.Allocs,
		AllocsOmitted: seed.AllocsOmitted,
	}

	writeJSON(w, http.StatusOK, out)
}

// aggKey identifies one memoized aggregate: which computation, over which
// metrics, at which window, ending at which slot.
type aggKey struct {
	kind     string
	metric   string
	weightBy string
	window   time.Duration
	slot     int64
	withNode bool
}

// maxAggCacheEntries bounds the memo. The working set is one or two windows, so
// this is a guard rather than a policy: `window` is client-chosen, so the map
// needs *some* bound, and clearing it wholesale past the bound is cheaper to
// reason about than an LRU for a case that does not arise.
const maxAggCacheEntries = 64

// cachedAggregate answers from the memo, or computes and stores.
//
// Computing under the same lock is deliberate: it collapses concurrent
// identical requests into one ring walk instead of letting each do its own. The
// cost is that a second window briefly waits behind the first, which is the
// right trade when the alternative is N subscribers each walking every series.
func (s *Server) cachedAggregate(key aggKey, compute func() []scaling.Point) []scaling.Point {
	s.aggCache.mu.Lock()
	defer s.aggCache.mu.Unlock()

	if points, ok := s.aggCache.entries[key]; ok {
		return points
	}
	points := compute()
	if s.aggCache.entries == nil || len(s.aggCache.entries) >= maxAggCacheEntries {
		s.aggCache.entries = map[aggKey][]scaling.Point{}
	}
	s.aggCache.entries[key] = points
	return points
}

// serviceSubjects lists the service-level subjects ("project/service") that
// carry a metric, excluding per-alloc ones.
//
// Cached against the series epoch: the underlying scan walks the whole key
// space and sorts it, and the answer cannot change while that space is
// unchanged.
func (s *Server) serviceSubjects(metric string) []string {
	epoch := s.metrics.Epoch()

	s.subjectCache.mu.Lock()
	defer s.subjectCache.mu.Unlock()

	if !s.subjectCache.valid || s.subjectCache.epoch != epoch {
		s.subjectCache.epoch = epoch
		s.subjectCache.valid = true
		s.subjectCache.byMetric = map[string][]string{}
	}
	if subjects, ok := s.subjectCache.byMetric[metric]; ok {
		return subjects
	}

	var out []string
	for _, subject := range s.metrics.Subjects(metric) {
		if strings.Count(subject, "/") == 1 {
			out = append(out, subject)
		}
	}
	s.subjectCache.byMetric[metric] = out
	return out
}

// sumSeries adds a metric across every service, slot by slot.
//
// A slot where no service has a point is absent; a slot where some do is the
// sum of those that do. Points from one Metrics store share slot-aligned
// timestamps, which is what makes merging by instant exact.
// withNode adds the node subject's own recording, which the datapath uses for
// traffic it cannot attribute to a service. A node total that left it out would
// be missing exactly the traffic nobody could account for.
func (s *Server) sumSeries(metric string, from, to time.Time, withNode bool) []scaling.Point {
	key := aggKey{kind: "sum", metric: metric, window: to.Sub(from), slot: to.Unix(), withNode: withNode}
	return s.cachedAggregate(key, func() []scaling.Point {
		sums := map[time.Time]float64{}
		for _, subject := range s.serviceSubjects(metric) {
			for _, p := range s.metrics.Range(scaling.Key{Subject: subject, Metric: metric}, from, to) {
				sums[p.At] += p.Value
			}
		}
		if withNode {
			for _, p := range s.metrics.Range(
				scaling.Key{Subject: scaling.NodeSubject, Metric: metric}, from, to) {
				sums[p.At] += p.Value
			}
		}
		return sortPoints(sums)
	})
}

// weightedSeries averages a metric across services, weighting each by a
// second metric at the same slot (missing weight = 1, so a service the edge
// has latency but no rate for still counts once rather than vanishing).
func (s *Server) weightedSeries(metric, weightBy string, from, to time.Time) []scaling.Point {
	key := aggKey{kind: "weighted", metric: metric, weightBy: weightBy, window: to.Sub(from), slot: to.Unix()}
	return s.cachedAggregate(key, func() []scaling.Point {
		return s.computeWeightedSeries(metric, weightBy, from, to)
	})
}

func (s *Server) computeWeightedSeries(metric, weightBy string, from, to time.Time) []scaling.Point {
	type acc struct{ weighted, weight float64 }
	slots := map[time.Time]*acc{}

	for _, subject := range s.serviceSubjects(metric) {
		weights := map[time.Time]float64{}
		for _, p := range s.metrics.Range(scaling.Key{Subject: subject, Metric: weightBy}, from, to) {
			weights[p.At] = p.Value
		}
		for _, p := range s.metrics.Range(scaling.Key{Subject: subject, Metric: metric}, from, to) {
			weight, ok := weights[p.At]
			if !ok || weight <= 0 {
				weight = 1
			}
			slot := slots[p.At]
			if slot == nil {
				slot = &acc{}
				slots[p.At] = slot
			}
			slot.weighted += p.Value * weight
			slot.weight += weight
		}
	}

	out := map[time.Time]float64{}
	for at, a := range slots {
		if a.weight > 0 {
			out[at] = a.weighted / a.weight
		}
	}
	return sortPoints(out)
}

func sortPoints(byAt map[time.Time]float64) []scaling.Point {
	if len(byAt) == 0 {
		return nil
	}
	out := make([]scaling.Point, 0, len(byAt))
	for at, value := range byAt {
		out = append(out, scaling.Point{At: at, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}
