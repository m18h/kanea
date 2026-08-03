package scaling

import (
	"math"
	"sort"
	"sync"
	"time"
)

// The metrics pipeline (PRD §9.1).
//
// Metrics never touch the Store (AGENTS.md #2): they are high-frequency,
// worthless after a few hours, and putting them through a single-writer bbolt
// would spend the write budget of the whole control plane on data nobody reads
// twice. This is an in-memory ring per series, and it is sized deliberately.
//
// **The arithmetic that chose the shape.** The §21 target is 2 000 allocs on a
// node, each contributing CPU and memory, plus rps and three latency
// percentiles for up to 500 exposed services — call it 6 000 series. At 5 s for
// an hour that is 720 raw points each, plus 360 at one minute for six hours:
//
//	6 000 series × 1 080 points × 4 bytes = ~26 MiB
//
// Four bytes because a point is a `float32` and *nothing else*. Timestamps are
// not stored: the sources are timers, so a point's time is its slot index times
// the interval, and a slot nobody wrote is NaN. Storing an int64 timestamp
// beside each value would triple the footprint to buy back precision that a
// scrape on a ticker does not have anyway.
//
// Gorilla-style delta-of-delta and XOR packing would roughly halve the 26 MiB
// again. It is not here because 26 MiB fits the §21 budget with room to spare,
// and bit-packing is a decode path to get wrong in exchange for memory nobody
// is short of. If the budget tightens, this is where it goes.
const (
	// RawInterval and RawWindow are the high-resolution tier: what the
	// autoscaler evaluates and the dashboard draws.
	RawInterval = 5 * time.Second
	RawWindow   = time.Hour
	// RollupInterval and RollupWindow are the downsampled tier, for the longer
	// view a service page shows without holding an hour of five-second points
	// for every alloc that ever ran.
	RollupInterval = time.Minute
	RollupWindow   = 6 * time.Hour
)

// MaxSeries caps how many series are tracked.
//
// The subjects are allocs and services, so the set is bounded by what the node
// runs — until something churns. A crash-looping service that changed alloc ids
// every restart would otherwise grow this map without limit, and the one
// process that must not die of memory pressure is the one that would restart
// everything else (AGENTS.md #11). Past the cap new series are refused and
// counted rather than evicting an existing one: losing the series a scaling
// decision reads is worse than not adding one.
const MaxSeries = 20_000

// Key identifies one series: what is measured, and of what.
type Key struct {
	// Subject is "project/service" for a service-level metric, or
	// "project/service/alloc-id" for a per-alloc one.
	Subject string
	// Metric is the measurement: "cpu", "memory", "rps", "p95_latency_ms".
	Metric string
}

// Point is one sample.
type Point struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// Metrics is the in-memory time series store.
type Metrics struct {
	mu     sync.RWMutex
	series map[Key]*seriesPair
	now    func() time.Time

	// dropped counts series refused at the cap, so the condition is visible.
	dropped int64
}

// MetricsConfig configures the store.
type MetricsConfig struct {
	// Now is injectable for tests.
	Now func() time.Time
}

// NewMetrics builds an empty store.
func NewMetrics(cfg MetricsConfig) *Metrics {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Metrics{series: map[Key]*seriesPair{}, now: cfg.Now}
}

// seriesPair is one metric at both resolutions.
type seriesPair struct {
	raw    *ring
	rollup *ring
	// pending accumulates the raw points inside the current rollup slot, so the
	// downsample is a mean rather than a sample of whichever point landed last.
	pendingSlot  int64
	pendingSum   float64
	pendingCount int
	// last is when this series was last written, for sweeping.
	last time.Time
}

// Record adds a sample.
//
// Out-of-order samples are dropped rather than reordered: the sources are
// tickers, a late point means a scrape overran its interval, and the honest
// answer to "which value belongs in that slot" is the one already there.
func (m *Metrics) Record(key Key, at time.Time, value float64) {
	if key.Subject == "" || key.Metric == "" || math.IsNaN(value) {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pair, ok := m.series[key]
	if !ok {
		if len(m.series) >= MaxSeries {
			m.dropped++
			return
		}
		pair = &seriesPair{
			raw:         newRing(RawInterval, RawWindow),
			rollup:      newRing(RollupInterval, RollupWindow),
			pendingSlot: slotOf(at, RollupInterval),
		}
		m.series[key] = pair
	}

	pair.raw.set(at, value)
	pair.last = at

	// Roll the minute over when the slot changes, so the rollup holds the mean
	// of the twelve raw points that made it up.
	slot := slotOf(at, RollupInterval)
	if slot != pair.pendingSlot {
		if pair.pendingCount > 0 {
			pair.rollup.setSlot(pair.pendingSlot, pair.pendingSum/float64(pair.pendingCount))
		}
		pair.pendingSlot, pair.pendingSum, pair.pendingCount = slot, 0, 0
	}
	pair.pendingSum += value
	pair.pendingCount++
}

// Latest returns the most recent sample, if there is one inside the raw window.
//
// The window bound is the point: a ring that nobody has written to for two
// hours still *holds* its last value, and returning that as "latest" would let
// a caller publish a stale number as current. "Latest" has to mean latest
// within the retention this tier promises, or every caller has to remember to
// check a timestamp — and one of them will not.
func (m *Metrics) Latest(key Key) (Point, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pair, ok := m.series[key]
	if !ok {
		return Point{}, false
	}
	point, found := pair.raw.latest()
	if !found || m.now().Sub(point.At) > RawWindow {
		return Point{}, false
	}
	return point, true
}

// Average is the mean over a trailing window, and how many points it covered.
//
// The count matters to the caller: an average of one sample is not evidence,
// and the autoscaler refuses to act on a window it has barely any data for.
func (m *Metrics) Average(key Key, window time.Duration) (mean float64, points int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pair, ok := m.series[key]
	if !ok {
		return 0, 0
	}
	return pair.raw.average(m.now().Add(-window), m.now())
}

// Range returns the points between two instants, oldest first.
//
// It reads the raw tier when the range fits inside it and the rollup otherwise,
// because a six-hour chart drawn from five-second points is 4 320 values nobody
// can see and a websocket frame nobody needs.
func (m *Metrics) Range(key Key, from, to time.Time) []Point {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pair, ok := m.series[key]
	if !ok {
		return nil
	}
	if m.now().Sub(from) <= RawWindow {
		return pair.raw.rangePoints(from, to)
	}
	return pair.rollup.rangePoints(from, to)
}

// Subjects lists the subjects that have a given metric, sorted.
func (m *Metrics) Subjects(metric string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []string
	for key := range m.series {
		if key.Metric == metric {
			out = append(out, key.Subject)
		}
	}
	sort.Strings(out)
	return out
}

// Forget drops every series for a subject and its allocs.
//
// Called when a service or alloc goes away. Without it the map holds the shape
// of everything that ever ran, which is the leak the cap exists to survive
// rather than the one it exists to hide.
func (m *Metrics) Forget(subject string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	dropped := 0
	for key := range m.series {
		if key.Subject == subject || isChildSubject(key.Subject, subject) {
			delete(m.series, key)
			dropped++
		}
	}
	return dropped
}

// Sweep drops series with nothing recent in them.
//
// The safety net under Forget: an alloc that vanished without anyone noticing
// still stops costing memory an hour later.
func (m *Metrics) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := m.now().Add(-RollupWindow)
	dropped := 0
	for key, pair := range m.series {
		if pair.last.Before(cutoff) {
			delete(m.series, key)
			dropped++
		}
	}
	return dropped
}

// Len reports how many series are held. Read by the exporter, so the ceiling
// is observable before it is a problem.
func (m *Metrics) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.series)
}

// Dropped reports how many series were refused at MaxSeries. A non-zero value
// means the node is measuring less than it thinks it is.
func (m *Metrics) Dropped() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dropped
}

// isChildSubject reports whether sub is an alloc under a service subject.
func isChildSubject(sub, service string) bool {
	return len(sub) > len(service)+1 && sub[:len(service)] == service && sub[len(service)] == '/'
}

// ---- ring ----

// ring is a fixed-interval circular buffer of float32.
//
// A slot is `unix / interval`, so a point's timestamp is implied by where it
// sits and never stored. An unwritten slot holds NaN, which is what makes a gap
// distinguishable from a zero — the difference between "no traffic" and "no
// data", which an autoscaler must not confuse.
type ring struct {
	interval time.Duration
	values   []float32
	// head is the newest slot written; slots below head-len(values) are gone.
	head int64
	// filled reports whether anything has been written at all.
	filled bool
}

func newRing(interval, window time.Duration) *ring {
	size := int(window / interval)
	if size < 1 {
		size = 1
	}
	values := make([]float32, size)
	for i := range values {
		values[i] = float32(math.NaN())
	}
	return &ring{interval: interval, values: values}
}

func slotOf(at time.Time, interval time.Duration) int64 {
	return at.UnixNano() / int64(interval)
}

func (r *ring) timeOf(slot int64) time.Time {
	return time.Unix(0, slot*int64(r.interval)).UTC()
}

// set writes a value at the slot the timestamp falls in.
func (r *ring) set(at time.Time, value float64) {
	r.setSlot(slotOf(at, r.interval), value)
}

func (r *ring) setSlot(slot int64, value float64) {
	switch {
	case !r.filled:
		r.head, r.filled = slot, true
	case slot > r.head:
		// Clear the slots skipped over, so a gap reads as absent data rather
		// than as whatever occupied those positions a full window ago.
		gap := slot - r.head
		if gap >= int64(len(r.values)) {
			for i := range r.values {
				r.values[i] = float32(math.NaN())
			}
		} else {
			for s := r.head + 1; s <= slot; s++ {
				r.values[r.index(s)] = float32(math.NaN())
			}
		}
		r.head = slot
	case r.head-slot >= int64(len(r.values)):
		// Older than the window: there is nowhere to put it.
		return
	}
	r.values[r.index(slot)] = float32(value)
}

func (r *ring) index(slot int64) int {
	i := slot % int64(len(r.values))
	if i < 0 {
		i += int64(len(r.values))
	}
	return int(i)
}

func (r *ring) latest() (Point, bool) {
	if !r.filled {
		return Point{}, false
	}
	// Walk back over any trailing gap: the newest *value* is what a caller
	// means by "latest", not the newest slot.
	for slot := r.head; slot > r.head-int64(len(r.values)); slot-- {
		v := r.values[r.index(slot)]
		if !math.IsNaN(float64(v)) {
			return Point{At: r.timeOf(slot), Value: float64(v)}, true
		}
	}
	return Point{}, false
}

func (r *ring) average(from, to time.Time) (float64, int) {
	if !r.filled {
		return 0, 0
	}
	var sum float64
	var count int
	for slot := slotOf(from, r.interval); slot <= slotOf(to, r.interval); slot++ {
		if slot > r.head || r.head-slot >= int64(len(r.values)) {
			continue
		}
		v := float64(r.values[r.index(slot)])
		if math.IsNaN(v) {
			continue
		}
		sum += v
		count++
	}
	if count == 0 {
		return 0, 0
	}
	return sum / float64(count), count
}

func (r *ring) rangePoints(from, to time.Time) []Point {
	if !r.filled {
		return nil
	}
	var out []Point
	for slot := slotOf(from, r.interval); slot <= slotOf(to, r.interval); slot++ {
		if slot > r.head || r.head-slot >= int64(len(r.values)) {
			continue
		}
		v := float64(r.values[r.index(slot)])
		if math.IsNaN(v) {
			continue
		}
		out = append(out, Point{At: r.timeOf(slot), Value: v})
	}
	return out
}
