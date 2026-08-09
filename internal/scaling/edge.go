package scaling

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultEdgeMetricsURL is kanea-edge's loopback status listener.
const DefaultEdgeMetricsURL = "http://127.0.0.1:8601/metrics"

// L7 metric names. They are spelled the way a job spec spells them (§6.1), so
// `metric "p95_latency_ms" { target = 800 }` names a series that exists.
const (
	MetricRPS       = "rps"
	MetricP50       = "p50_latency_ms"
	MetricP95       = "p95_latency_ms"
	MetricP99       = "p99_latency_ms"
	MetricErrorRate = "error_rate"
)

// Edge metric names, as internal/edge publishes them.
const (
	edgeRequestsMetric = "kanea_edge_requests_total"
	edgeBucketMetric   = "kanea_edge_request_duration_ms_bucket"
	edgeErrorsMetric   = "kanea_edge_errors_total"
)

// EdgeConfig configures the L7 scraper.
type EdgeConfig struct {
	// URL is the edge's metrics endpoint. Empty means the default.
	URL     string
	Metrics *Metrics
	Client  *http.Client
	Logger  *slog.Logger
	Now     func() time.Time
	// Exposition retains the labelled families for the exporter (§9.1.1).
	// Optional: a node whose API server has no exporter configured still
	// autoscales.
	Exposition *EdgeExposition
}

// EdgeScraper turns the edge's cumulative counters into rates and percentiles.
//
// The differencing lives here rather than in the edge for a reason worth
// stating: the edge has no idea how often it is scraped or by how many readers,
// so a rate computed there would be a rate against an interval it invented. Two
// readings and the wall clock between them is a measurement; one reading and an
// assumption is not.
type EdgeScraper struct {
	url     string
	client  *http.Client
	metrics *Metrics
	log     *slog.Logger
	now     func() time.Time
	// exposition receives the labelled families verbatim. They are never
	// differenced and never enter the time series (§9.1.1).
	exposition *EdgeExposition

	mu       sync.Mutex
	previous map[string]edgeSample
}

// edgeSample is the last reading for one service.
type edgeSample struct {
	at       time.Time
	requests float64
	errors   float64
	// buckets is the cumulative histogram, keyed by upper bound. +Inf is
	// math.Inf(1), which sorts last and needs no special case.
	buckets map[float64]float64
}

// NewEdgeScraper builds the scraper.
func NewEdgeScraper(cfg EdgeConfig) (*EdgeScraper, error) {
	if cfg.Metrics == nil {
		return nil, errors.New("scaling: a metrics store is required")
	}
	if cfg.URL == "" {
		cfg.URL = DefaultEdgeMetricsURL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 4 * time.Second}
	}
	return &EdgeScraper{
		url: cfg.URL, client: cfg.Client, metrics: cfg.Metrics,
		log: cfg.Logger, now: cfg.Now, exposition: cfg.Exposition,
		previous: map[string]edgeSample{},
	}, nil
}

// Run scrapes on a ticker until the context ends.
//
// A missing edge is not an error worth shouting about on every tick: kanead
// does not supervise the edge and does not require it (§5.2.6), so a node with
// no exposed services has nothing listening here and that is a normal state.
func (s *EdgeScraper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = RawInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var consecutive int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := s.Scrape(ctx); err != nil {
			consecutive++
			// Log the first failure and then roughly once a minute, so an edge
			// that is down is visible without a line every five seconds.
			if consecutive == 1 || consecutive%12 == 0 {
				s.log.Warn("edge metrics scrape failed",
					"url", s.url, "consecutive", consecutive, "error", err)
			}
			continue
		}
		if consecutive > 0 {
			s.log.Info("edge metrics recovered", "url", s.url, "after", consecutive)
			consecutive = 0
		}
	}
}

// Scrape performs one pass and reports how many services it recorded for.
func (s *EdgeScraper) Scrape(ctx context.Context) (services int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("scaling: scrape %s: %w", s.url, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode != http.StatusOK {
		if _, derr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)); derr != nil {
			s.log.Debug("drain error body", "error", derr)
		}
		return 0, fmt.Errorf("scaling: scrape %s: %s", s.url, resp.Status)
	}
	return s.parse(resp.Body, s.now())
}

func (s *EdgeScraper) parse(body io.Reader, at time.Time) (int, error) {
	current := map[string]*edgeSample{}

	// The labelled families are collected in the same pass that differences the
	// aggregate one. Two passes would mean buffering the whole body twice, and
	// a second HTTP request would mean the exporter and the autoscaler reading
	// two different moments of the same counters.
	var retained strings.Builder
	byService := breakdowns{}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 32<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if s.exposition != nil && keepInPassthrough(string(line)) {
			retained.Write(line)
			retained.WriteByte('\n')
		}
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		name, labels, rawValue, ok := splitExpositionLine(line)
		if !ok {
			continue
		}
		value, err := strconv.ParseFloat(string(rawValue), 64)
		if err != nil {
			continue
		}
		service := labelValue(labels, "service")

		// The structured view is folded in the same pass, from the labelled
		// families. It feeds /v1/stats, which the dashboard and the CLI read —
		// neither should have to parse an exposition to show a code breakdown.
		if s.exposition != nil {
			byService.observe(string(name), service, labelValue(labels, "code"), value)
		}

		switch string(name) {
		case edgeRequestsMetric, edgeBucketMetric, edgeErrorsMetric:
		default:
			continue
		}
		if service == "" {
			continue
		}

		sample := current[service]
		if sample == nil {
			sample = &edgeSample{at: at, buckets: map[float64]float64{}}
			current[service] = sample
		}
		switch string(name) {
		case edgeRequestsMetric:
			sample.requests = value
		case edgeErrorsMetric:
			sample.errors = value
		case edgeBucketMetric:
			bound, ok := parseBound(labelValue(labels, "le"))
			if !ok {
				continue
			}
			sample.buckets[bound] = value
		}
	}
	if err := scanner.Err(); err != nil {
		// Nothing is retained from a truncated read. A partial exposition would
		// publish a subset of the families as though the rest had gone to zero,
		// which is worse than publishing the previous scrape unchanged.
		return 0, fmt.Errorf("scaling: read edge metrics: %w", err)
	}
	if s.exposition != nil {
		s.exposition.Set(retained.String(), at, byService)
	}

	recorded := 0
	for service, sample := range current {
		if s.record(service, sample, at) {
			recorded++
		}
	}

	// Services the edge no longer reports have stopped being exposed. Their
	// baselines go with them, or this map grows for the life of the process.
	s.mu.Lock()
	for service := range s.previous {
		if _, ok := current[service]; !ok {
			delete(s.previous, service)
		}
	}
	s.mu.Unlock()

	return recorded, nil
}

// record differences one service against its previous reading.
func (s *EdgeScraper) record(service string, sample *edgeSample, at time.Time) bool {
	s.mu.Lock()
	previous, seen := s.previous[service]
	s.previous[service] = *sample
	s.mu.Unlock()

	if !seen {
		// The first reading of a counter measures nothing but uptime.
		return false
	}
	elapsed := at.Sub(previous.at)
	if elapsed <= 0 {
		return false
	}
	requests := sample.requests - previous.requests
	if requests < 0 {
		// The edge restarted and its counters began again. There is no rate
		// across that, and reporting one would show a service that has been
		// idle as suddenly busy — or the reverse.
		return false
	}

	subject := Key{Subject: service}
	subject.Metric = MetricRPS
	s.metrics.Record(subject, at, requests/elapsed.Seconds())

	if requests > 0 {
		errors := sample.errors - previous.errors
		if errors >= 0 {
			subject.Metric = MetricErrorRate
			s.metrics.Record(subject, at, errors/requests*100)
		}
	}

	// Percentiles come from the *difference* of the histograms, so they
	// describe this interval rather than everything since the edge started.
	// A service that was slow an hour ago and is fast now should read as fast.
	deltas := bucketDeltas(sample.buckets, previous.buckets)
	for metric, quantile := range map[string]float64{
		MetricP50: 0.50, MetricP95: 0.95, MetricP99: 0.99,
	} {
		if value, ok := quantileOf(deltas, quantile); ok {
			subject.Metric = metric
			s.metrics.Record(subject, at, value)
		}
	}
	return true
}

// bound pairs a histogram's upper edge with a count.
type bound struct {
	upper float64
	count float64
}

// bucketDeltas subtracts two cumulative histograms, in ascending bound order.
func bucketDeltas(current, previous map[float64]float64) []bound {
	out := make([]bound, 0, len(current))
	for upper, count := range current {
		delta := count - previous[upper]
		if delta < 0 {
			// A counter reset mid-histogram: treat the bucket as empty rather
			// than as a negative count that would corrupt the interpolation.
			delta = 0
		}
		out = append(out, bound{upper: upper, count: delta})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].upper < out[j].upper })
	return out
}

// quantileOf interpolates a quantile out of cumulative bucket counts.
//
// Linear interpolation inside the bucket the quantile falls in, which is what
// makes "p95 = 800 ms" a usable number from thirteen buckets rather than a
// staircase that reports whichever bound it landed on. The result is bounded by
// the histogram's resolution and says so: a p99 inside the +Inf bucket cannot
// be interpolated at all and reports the last finite bound instead of pretending
// to a precision the data does not have.
func quantileOf(buckets []bound, quantile float64) (float64, bool) {
	if len(buckets) == 0 {
		return 0, false
	}
	total := buckets[len(buckets)-1].count
	if total <= 0 {
		// No requests in this interval. Not a latency of zero — no latency.
		return 0, false
	}

	rank := quantile * total
	previousCount, previousBound := 0.0, 0.0
	for _, b := range buckets {
		if b.count < rank {
			previousCount, previousBound = b.count, b.upper
			continue
		}
		if math.IsInf(b.upper, 1) {
			return previousBound, true
		}
		width := b.upper - previousBound
		inBucket := b.count - previousCount
		if inBucket <= 0 || width <= 0 {
			return b.upper, true
		}
		return previousBound + width*(rank-previousCount)/inBucket, true
	}
	return buckets[len(buckets)-1].upper, true
}

// parseBound reads a histogram's `le` label.
func parseBound(raw string) (float64, bool) {
	if raw == "" {
		return 0, false
	}
	if raw == "+Inf" {
		return math.Inf(1), true
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}
