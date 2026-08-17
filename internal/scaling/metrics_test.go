package scaling_test

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// clock drives the store's notion of now. Every property here is about what
// happens as time passes, and none of it is testable against a real clock.
type clock struct{ at time.Time }

func (c *clock) now() time.Time          { return c.at }
func (c *clock) advance(d time.Duration) { c.at = c.at.Add(d) }
func (c *clock) set(at time.Time)        { c.at = at }
func newClock() *clock                   { return &clock{at: time.Unix(1_800_000_000, 0).UTC()} }
func key(subject, metric string) scaling.Key {
	return scaling.Key{Subject: subject, Metric: metric}
}

func newMetrics(t *testing.T) (*scaling.Metrics, *clock) {
	t.Helper()
	c := newClock()
	return scaling.NewMetrics(scaling.MetricsConfig{Now: c.now}), c
}

func TestRecordAndLatest(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	if _, ok := m.Latest(k); ok {
		t.Fatal("an empty store reported a latest point")
	}

	m.Record(k, c.at, 42)
	point, ok := m.Latest(k)
	if !ok {
		t.Fatal("no latest point after a record")
	}
	if point.Value != 42 {
		t.Errorf("value = %v, want 42", point.Value)
	}
}

func TestLatestSkipsATrailingGap(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	m.Record(k, c.at, 10)
	// The scraper stopped for a minute. "Latest" means the newest value, not
	// the newest slot: a caller asking what CPU is wants the last reading.
	c.advance(time.Minute)
	m.Record(k, c.at, 20)
	c.advance(time.Minute)

	point, ok := m.Latest(k)
	if !ok || point.Value != 20 {
		t.Fatalf("latest = %+v, %v; want the last value written", point, ok)
	}
}

func TestAverageOverAWindowCountsPoints(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	for i := range 12 {
		m.Record(k, c.at, float64(i))
		c.advance(scaling.RawInterval)
	}

	mean, points := m.Average(k, time.Minute)
	if points != 12 {
		t.Fatalf("points = %d, want 12", points)
	}
	// 0..11 averages 5.5.
	if mean < 5.4 || mean > 5.6 {
		t.Errorf("mean = %v, want ~5.5", mean)
	}
}

func TestAverageReportsNoPointsForAnUnknownSeries(t *testing.T) {
	m, _ := newMetrics(t)
	// The distinction the autoscaler depends on: no data is not zero load.
	if mean, points := m.Average(key("shop/web", "rps"), time.Minute); points != 0 || mean != 0 {
		t.Fatalf("mean, points = %v, %d; want 0, 0", mean, points)
	}
}

func TestAverageIgnoresGaps(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "rps")

	m.Record(k, c.at, 100)
	c.advance(30 * time.Second) // six missed scrapes
	m.Record(k, c.at, 200)

	mean, points := m.Average(k, time.Minute)
	if points != 2 {
		t.Fatalf("points = %d, want 2: a missed scrape is absent, not zero", points)
	}
	if mean != 150 {
		t.Errorf("mean = %v, want 150", mean)
	}
}

func TestSamplesFallOutOfTheRawWindow(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	m.Record(k, c.at, 99)
	c.advance(scaling.RawWindow + time.Minute)
	m.Record(k, c.at, 1)

	// The old point is past the window, so it cannot come back as a stale
	// reading from a slot that wrapped.
	if mean, points := m.Average(k, scaling.RawWindow); points != 1 || mean != 1 {
		t.Fatalf("mean, points = %v, %d; want just the recent sample", mean, points)
	}
}

func TestWrappingClearsTheSlotsItPassesOver(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	// Fill the whole ring, so every position holds a value.
	for range int(scaling.RawWindow / scaling.RawInterval) {
		m.Record(k, c.at, 500)
		c.advance(scaling.RawInterval)
	}

	// Then a five-minute gap and one sample. The sixty skipped slots map onto
	// positions still holding 500 from an hour ago; if the gap is not cleared,
	// an autoscaler reading the last five minutes sees a busy service that has
	// in fact been silent.
	c.advance(5 * time.Minute)
	m.Record(k, c.at, 1)

	points := m.Range(k, c.at.Add(-5*time.Minute), c.at)
	for _, p := range points {
		if p.Value == 500 {
			t.Fatalf("a value from a full window ago resurfaced at %v", p.At)
		}
	}
	if len(points) != 1 {
		t.Fatalf("points = %d, want just the one recent sample", len(points))
	}

	// And the same through the average, which is what actually drives scaling.
	if mean, count := m.Average(k, 5*time.Minute); count != 1 || mean != 1 {
		t.Fatalf("mean, points = %v, %d; want 1, 1", mean, count)
	}
}

func TestRangeIsOldestFirst(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	for i := range 5 {
		m.Record(k, c.at, float64(i))
		c.advance(scaling.RawInterval)
	}

	points := m.Range(k, c.at.Add(-time.Minute), c.at)
	if len(points) != 5 {
		t.Fatalf("points = %d, want 5", len(points))
	}
	for i, p := range points {
		if p.Value != float64(i) {
			t.Fatalf("point[%d] = %v, want %d: out of order", i, p.Value, i)
		}
	}
}

func TestRangeUsesTheRollupForLongWindows(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	// Two hours of samples at five seconds: past the raw window, so the long
	// view has to come from the downsampled tier or it would be empty.
	for range 2 * 60 * 12 {
		m.Record(k, c.at, 50)
		c.advance(scaling.RawInterval)
	}

	long := m.Range(k, c.at.Add(-2*time.Hour), c.at)
	if len(long) == 0 {
		t.Fatal("the long range is empty; the rollup tier is not being read")
	}
	// A rollup point per minute, not one per five seconds.
	if len(long) > 130 {
		t.Fatalf("long range returned %d points; that is raw resolution", len(long))
	}
	for _, p := range long {
		if p.Value < 49.9 || p.Value > 50.1 {
			t.Fatalf("rollup value = %v, want the mean of its minute (50)", p.Value)
		}
	}
}

func TestRollupIsTheMeanOfItsMinute(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "rps")

	// A minute of alternating 0 and 100 averages 50. A downsample that kept
	// the last sample instead would report 0 or 100, which is the difference
	// between a scaling decision and a coin flip.
	start := c.at
	for i := range 12 {
		m.Record(k, c.at, float64((i%2)*100))
		c.advance(scaling.RawInterval)
	}
	// Cross the minute boundary so the pending bucket flushes.
	m.Record(k, c.at, 0)
	c.set(start.Add(3 * time.Hour))

	points := m.Range(k, start.Add(-time.Hour), start.Add(2*time.Minute))
	if len(points) == 0 {
		t.Fatal("no rollup points")
	}
	if points[0].Value < 45 || points[0].Value > 55 {
		t.Fatalf("rollup = %v, want the mean (~50)", points[0].Value)
	}
}

func TestForgetDropsAServiceAndItsAllocs(t *testing.T) {
	m, c := newMetrics(t)
	m.Record(key("shop/web", "rps"), c.at, 1)
	m.Record(key("shop/web/alloc-0", "cpu"), c.at, 1)
	m.Record(key("shop/web/alloc-1", "cpu"), c.at, 1)
	// A different service whose name starts the same way must survive: prefix
	// matching on strings is how "web" takes "web-admin" down with it.
	m.Record(key("shop/web-admin", "rps"), c.at, 1)

	if dropped := m.Forget("shop/web"); dropped != 3 {
		t.Fatalf("dropped = %d, want 3", dropped)
	}
	if _, ok := m.Latest(key("shop/web-admin", "rps")); !ok {
		t.Fatal("a service with a shared prefix was dropped too")
	}
}

func TestSweepDropsStaleSeries(t *testing.T) {
	m, c := newMetrics(t)
	m.Record(key("shop/gone", "cpu"), c.at, 1)

	c.advance(scaling.RollupWindow + time.Minute)
	m.Record(key("shop/live", "cpu"), c.at, 1)

	if dropped := m.Sweep(); dropped != 1 {
		t.Fatalf("swept %d, want the one stale series", dropped)
	}
	if m.Len() != 1 {
		t.Fatalf("held %d series after the sweep, want 1", m.Len())
	}
}

func TestSeriesAreCapped(t *testing.T) {
	m, c := newMetrics(t)
	for i := range scaling.MaxSeries + 100 {
		m.Record(key(fmt.Sprintf("shop/svc%d", i), "cpu"), c.at, 1)
	}

	if m.Len() > scaling.MaxSeries {
		t.Fatalf("held %d series, past the cap of %d", m.Len(), scaling.MaxSeries)
	}
	// Refusals are counted, because a node silently measuring less than it
	// thinks it is will make scaling decisions on series that do not exist.
	if m.Dropped() == 0 {
		t.Fatal("series were refused without being counted")
	}
}

func TestRecordIgnoresNonsense(t *testing.T) {
	m, c := newMetrics(t)
	m.Record(scaling.Key{Metric: "cpu"}, c.at, 1)
	m.Record(scaling.Key{Subject: "shop/web"}, c.at, 1)
	if m.Len() != 0 {
		t.Fatalf("held %d series from keys with no subject or metric", m.Len())
	}
}

func TestConcurrentRecordAndRead(t *testing.T) {
	m, c := newMetrics(t)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := range 1000 {
			m.Record(key(fmt.Sprintf("shop/svc%d", i%50), "cpu"), c.at, float64(i))
		}
	}()
	for range 1000 {
		m.Average(key("shop/svc1", "cpu"), time.Minute)
		m.Latest(key("shop/svc2", "cpu"))
	}
	<-done
}

// The §21 footprint budget is 150 MiB idle RSS for the whole control plane, and
// the package comment claims ~26 MiB for the metrics at the 2 000-alloc target.
// A claim about memory that nobody measures is a claim that drifts.
func TestFootprintAtTargetScale(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~30 MiB")
	}

	m, c := newMetrics(t)
	// 6 000 series: 2 000 allocs × (cpu, memory) + 500 services × 4 L7 metrics.
	const series = 6000

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	for i := range series {
		k := key(fmt.Sprintf("shop/svc%d/alloc-%d", i/4, i), "cpu")
		// One point is enough: the rings are allocated at full size on first
		// write, so the footprint is there whether or not it is filled.
		m.Record(k, c.at, float64(i))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	// Without this the store is unreachable by the second reading and the GC
	// collects the very thing being measured, which reports a comfortable
	// zero and tests nothing.
	runtime.KeepAlive(m)

	grew := after.HeapAlloc - before.HeapAlloc
	const (
		floor  = 10 << 20 // the rings must actually exist
		budget = 40 << 20 // and must not exceed what §21 can afford
	)
	if grew < floor {
		t.Fatalf("%d series cost only %d MiB; the rings are not being allocated, "+
			"so this measures nothing", series, grew>>20)
	}
	if grew > budget {
		t.Fatalf("%d series cost %d MiB, past the %d MiB the design claims",
			series, grew>>20, budget>>20)
	}
	t.Logf("%d series cost %d MiB", series, grew>>20)
}

func TestRangeIntervalIsTheTierRangeServes(t *testing.T) {
	// The property that matters is agreement, not either answer alone: what
	// RangeInterval advertises has to be the spacing Range actually returns,
	// because the client rebuilds its gap slots against the advertised number.
	cases := []struct {
		name   string
		window time.Duration
		ago    time.Duration // how long before now the range ends
		want   time.Duration
	}{
		{"a short recent window is raw", 15 * time.Minute, 0, scaling.RawInterval},
		{"just inside the raw window is raw", scaling.RawWindow - time.Second, 0, scaling.RawInterval},
		{"exactly the raw window is raw", scaling.RawWindow, 0, scaling.RawInterval},
		{"past the raw window is the rollup", scaling.RawWindow + time.Second, 0, scaling.RollupInterval},
		{"a long window is the rollup", 6 * time.Hour, 0, scaling.RollupInterval},
		// The second condition: a short window that ended long ago is no longer
		// in the raw ring, so answering "raw" would promise points that were
		// swept out from under it.
		{"a short window from three hours ago is the rollup", 10 * time.Minute, 3 * time.Hour, scaling.RollupInterval},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, c := newMetrics(t)
			to := c.at.Add(-tc.ago)
			from := to.Add(-tc.window)

			if got := m.RangeInterval(from, to); got != tc.want {
				t.Fatalf("RangeInterval = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnHourWindowDoesNotAdvertiseFiveSecondPoints(t *testing.T) {
	// The regression (v1.79). The route decided the interval from the window it
	// was asked for while Range decided from how long ago `from` was, and since
	// `to` was captured first, an exactly-one-hour window missed the raw tier by
	// however long the handler took: the rollup answered at a minute while the
	// response promised five seconds, and every point landed in the wrong slot.
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	// Two hours of samples, so both tiers hold something.
	for range 2 * 60 * 12 {
		m.Record(k, c.at, 50)
		c.advance(scaling.RawInterval)
	}

	to := c.at
	from := to.Add(-scaling.RawWindow)
	advertised := m.RangeInterval(from, to)
	points := m.Range(k, from, to)

	if len(points) < 2 {
		t.Fatalf("points = %d; the range is too short to measure a spacing", len(points))
	}
	spacing := points[1].At.Sub(points[0].At)
	if spacing != advertised {
		t.Fatalf("advertised %v but the points are %v apart: a client rebuilding "+
			"slots against the advertised interval draws the chart at the wrong scale",
			advertised, spacing)
	}
}

func TestTheEpochMovesWithTheSeriesSetAndNotWithSamples(t *testing.T) {
	m, c := newMetrics(t)
	k := key("shop/web", "cpu")

	start := m.Epoch()
	m.Record(k, c.at, 1)
	created := m.Epoch()
	if created == start {
		t.Fatal("creating a series did not move the epoch; a cache keyed on it would serve a stale subject set")
	}

	// The common case by orders of magnitude, and it cannot change which
	// subjects carry which metric.
	for range 10 {
		c.advance(scaling.RawInterval)
		m.Record(k, c.at, 2)
	}
	if m.Epoch() != created {
		t.Fatal("an ordinary record moved the epoch; the cache it guards would rebuild every scrape")
	}

	if m.Forget("shop/web") == 0 {
		t.Fatal("nothing was forgotten; the rest of this test proves nothing")
	}
	if m.Epoch() == created {
		t.Fatal("forgetting a series did not move the epoch")
	}
}
