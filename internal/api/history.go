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
type HistoryResponse struct {
	Subject         string                     `json:"subject"`
	From            time.Time                  `json:"from"`
	To              time.Time                  `json:"to"`
	IntervalSeconds int                        `json:"interval_seconds"`
	Series          map[string][]scaling.Point `json:"series"`
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
	window = min(max(window, minHistoryWindow), scaling.RollupWindow)

	// Truncated to a raw slot rather than taken as "now" (v1.79). Two things
	// depend on it. The ring's own slots are on this grid, so an untruncated
	// range asks for a fraction of a slot at each end and no two responses are
	// comparable; and the aggregate cache below can only key on a slot if the
	// range is one. It is also half of the tier fix: the old code decided the
	// interval from the window while Range decided from how long ago `from`
	// was, and a window of exactly RawWindow missed the raw tier by however
	// long the handler had taken.
	to := s.now().Truncate(scaling.RawInterval)
	from := to.Add(-window)

	// Which tier Range will serve decides the slot width the client rebuilds
	// gaps against, so it is asked rather than re-derived: one function, two
	// callers, and they cannot disagree.
	interval := s.metrics.RangeInterval(from, to)

	out := HistoryResponse{
		From: from, To: to,
		IntervalSeconds: int(interval / time.Second),
		Series:          map[string][]scaling.Point{},
	}

	if project == "" {
		out.Subject = scaling.NodeSubject
		// The node's own recorded series, plus read-time aggregates for what
		// is only recorded per service.
		out.Series["cpu"] = s.metrics.Range(
			scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeCPU}, from, to)
		out.Series["memory"] = s.metrics.Range(
			scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeMemory}, from, to)
		out.Series["gpu_vram"] = s.metrics.Range(
			scaling.Key{Subject: scaling.NodeSubject, Metric: scaling.MetricNodeGPU}, from, to)
		out.Series["rps"] = s.sumSeries(scaling.MetricRPS, from, to)
		// An rps-weighted mean of per-service p95s, which is an approximation:
		// percentiles do not aggregate. Stated here and in the PRD rather than
		// silently presented as a measurement.
		out.Series["p95_latency_ms"] = s.weightedSeries(scaling.MetricP95, scaling.MetricRPS, from, to)
	} else {
		subject := project + "/" + service
		out.Subject = subject
		for name, metric := range map[string]string{
			"cpu":            scaling.MetricCPU,
			"memory":         scaling.MetricMemory,
			"rps":            scaling.MetricRPS,
			"p95_latency_ms": scaling.MetricP95,
		} {
			out.Series[name] = s.metrics.Range(scaling.Key{Subject: subject, Metric: metric}, from, to)
		}
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
func (s *Server) sumSeries(metric string, from, to time.Time) []scaling.Point {
	key := aggKey{kind: "sum", metric: metric, window: to.Sub(from), slot: to.Unix()}
	return s.cachedAggregate(key, func() []scaling.Point {
		sums := map[time.Time]float64{}
		for _, subject := range s.serviceSubjects(metric) {
			for _, p := range s.metrics.Range(scaling.Key{Subject: subject, Metric: metric}, from, to) {
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
