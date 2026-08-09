package scaling

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Datapath east-west metrics (PRD v1.36, §9.1) — on by default.
//
// The edge is the primary signal for exposed services because it is already in
// the request path. What this adds is the traffic the edge never sees:
// service-to-service calls inside the node. A service that is busy only
// because another service is calling it has no north-south signal at all.
//
// The numbers come from the datapath's own per-CPU counters, read straight off
// the pinned maps — no agent, no scrape endpoint, no cost per request. That is
// what lets this be on by default where Hubble, which cost L7 parsing per
// request and 152.8 MiB of resident cilium-agent, had to be opt-in.
//
// The metric names are the ones Hubble's scraper published, kept deliberately:
// a scaling spec written against `flows_per_second` keeps its meaning. What
// the datapath counts under it is connection attempts rather than flows —
// the connect-time hook is where its counter lives — which is the same signal
// at a coarser grain.

// East-west metric names, distinct from the edge's north-south ones. A rule
// written against `rps` means requests from the internet; one written against
// `flows_per_second` means traffic between services, and conflating them would
// scale a backend on its frontend's traffic.
const (
	MetricFlows = "flows_per_second"
	MetricDrops = "drops_per_second"
)

// NodeSubject is where traffic that cannot be attributed to a service is
// recorded. It is a single-segment subject on purpose: everything else is
// "project/service", so a node total can never collide with one.
const NodeSubject = "node"

// FlowSource is the consumer-side slice of the datapath's counters this
// scraper differences. Both maps are cumulative and keyed by
// "project/service"; a source folds whatever it cannot attribute into
// NodeSubject rather than dropping it — a number nobody can break down is
// still a number worth having.
type FlowSource interface {
	// ServiceConnects returns cumulative connection attempts per service.
	ServiceConnects(ctx context.Context) (map[string]uint64, error)
	// Drops returns cumulative datapath drops per service.
	Drops(ctx context.Context) (map[string]uint64, error)
}

// DatapathConfig configures the east-west scraper.
type DatapathConfig struct {
	Source  FlowSource
	Metrics *Metrics
	Logger  *slog.Logger
	Now     func() time.Time
}

// DatapathScraper turns the datapath's cumulative counters into east-west
// rates.
//
// Like the edge scraper, the differencing lives here: two readings and the
// wall clock between them is a measurement, and the counters themselves never
// enter the time series — only rates do, one series per subject, which is the
// cardinality bound everything in this package respects (constraint #2).
type DatapathScraper struct {
	source  FlowSource
	metrics *Metrics
	log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	previous map[string]flowSample
}

// flowSample is one subject's last counter reading.
type flowSample struct {
	at    time.Time
	flows float64
	drops float64
}

// NewDatapathScraper builds the scraper.
func NewDatapathScraper(cfg DatapathConfig) (*DatapathScraper, error) {
	if cfg.Source == nil {
		return nil, errors.New("scaling: a flow source is required")
	}
	if cfg.Metrics == nil {
		return nil, errors.New("scaling: a metrics store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &DatapathScraper{
		source: cfg.Source, metrics: cfg.Metrics,
		log: cfg.Logger, now: cfg.Now, previous: map[string]flowSample{},
	}, nil
}

// Run scrapes on a ticker until the context ends.
func (s *DatapathScraper) Run(ctx context.Context, interval time.Duration) {
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
			// Log the first failure and then roughly once a minute: the source
			// is a set of pinned maps in this process's own mount namespace, so
			// a persistent failure is a bug worth seeing, not a peer being down.
			if consecutive == 1 || consecutive%12 == 0 {
				s.log.Warn("datapath metrics read failed",
					"consecutive", consecutive, "error", err)
			}
			continue
		}
		if consecutive > 0 {
			s.log.Info("datapath metrics recovered", "after", consecutive)
			consecutive = 0
		}
	}
}

// Scrape performs one pass and reports how many subjects it recorded for.
func (s *DatapathScraper) Scrape(ctx context.Context) (subjects int, err error) {
	connects, err := s.source.ServiceConnects(ctx)
	if err != nil {
		return 0, err
	}
	drops, err := s.source.Drops(ctx)
	if err != nil {
		return 0, err
	}
	at := s.now()

	// Totals per subject, plus the node itself. The node figure is what the
	// whole datapath did — attributed traffic included — not just the
	// leftovers, so it reads as a node total rather than a residue.
	current := map[string]*flowSample{NodeSubject: {at: at}}
	sampleFor := func(subject string) *flowSample {
		sample := current[subject]
		if sample == nil {
			sample = &flowSample{at: at}
			current[subject] = sample
		}
		return sample
	}
	node := current[NodeSubject]
	for subject, n := range connects {
		sampleFor(subject).flows += float64(n)
		if subject != NodeSubject {
			node.flows += float64(n)
		}
	}
	for subject, n := range drops {
		sampleFor(subject).drops += float64(n)
		if subject != NodeSubject {
			node.drops += float64(n)
		}
	}

	recorded := 0
	for subject, sample := range current {
		if s.record(subject, sample, at) {
			recorded++
		}
	}

	// Subjects the datapath no longer reports have left the node. Their
	// baselines go with them, or this map grows for the life of the process.
	s.mu.Lock()
	for subject := range s.previous {
		if _, ok := current[subject]; !ok {
			delete(s.previous, subject)
		}
	}
	s.mu.Unlock()

	return recorded, nil
}

// record differences one subject against its previous reading.
func (s *DatapathScraper) record(subject string, sample *flowSample, at time.Time) bool {
	s.mu.Lock()
	previous, seen := s.previous[subject]
	s.previous[subject] = *sample
	s.mu.Unlock()

	if !seen {
		// The first reading of a cumulative counter measures nothing but uptime.
		return false
	}
	elapsed := at.Sub(previous.at)
	if elapsed <= 0 {
		return false
	}

	// A counter that went backwards means the maps were recreated — a pin-dir
	// schema rebuild. There is no rate across that discontinuity, so this
	// reading becomes the new baseline.
	flows := sample.flows - previous.flows
	drops := sample.drops - previous.drops
	if flows < 0 || drops < 0 {
		return false
	}

	key := Key{Subject: subject, Metric: MetricFlows}
	s.metrics.Record(key, at, flows/elapsed.Seconds())
	key.Metric = MetricDrops
	s.metrics.Record(key, at, drops/elapsed.Seconds())
	return true
}
