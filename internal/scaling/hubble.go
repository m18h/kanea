package scaling

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hubble east-west metrics (PRD §9.1) — opt-in, and secondary by design.
//
// The edge is the primary signal for exposed services because it is already in
// the request path. Hubble's L7 parsing costs CPU per request and its ring
// buffer drops flows under load, so eBPF metrics lose fidelity at exactly the
// moment they would matter most. What Hubble adds is the traffic the edge never
// sees: service-to-service calls inside the node. A service that is busy only
// because another service is calling it has no north-south signal at all.
//
// It is off unless configured, and §21's footprint budget is the reason: M0
// spike ① measured cilium-agent at 152.8 MiB with Hubble on, the largest
// resident component on the node.

// DefaultHubbleMetricsURL is cilium-agent's Hubble metrics listener.
const DefaultHubbleMetricsURL = "http://127.0.0.1:9965/metrics"

// East-west metric names, distinct from the edge's north-south ones. A rule
// written against `rps` means requests from the internet; one written against
// `flows_per_second` means traffic between services, and conflating them would
// scale a backend on its frontend's traffic.
const (
	MetricFlows = "flows_per_second"
	MetricDrops = "drops_per_second"
)

// Hubble's metric names, as M0 spike ① measured them on a standalone agent.
const (
	hubbleFlowsMetric = "hubble_flows_processed_total"
	hubbleDropsMetric = "hubble_drop_total"
)

// nodeSubject is where flows that cannot be attributed to a service are
// recorded. It is a single-segment subject on purpose: everything else is
// "project/service", so a node total can never collide with one.
const nodeSubject = "node"

// ErrHubbleNoFlows means the endpoint answered but carried no flow data.
//
// This is the failure M0 spike ① went out of its way to document, because it
// looks like success from every angle: `--hubble-metrics` takes a
// **space-separated list inside one value**, and both a comma-separated list
// and a repeated flag are accepted silently — leaving an endpoint that serves
// 200 OK with nothing in it. A scraper that only checked the status code would
// report a healthy pipeline forever.
var ErrHubbleNoFlows = errors.New("scaling: hubble is serving metrics but no flow data")

// HubbleConfig configures the east-west scraper.
type HubbleConfig struct {
	// URL is the Hubble metrics endpoint. Empty means the default.
	URL     string
	Metrics *Metrics
	Client  *http.Client
	Logger  *slog.Logger
	Now     func() time.Time
}

// HubbleScraper turns Hubble's flow counters into east-west rates.
type HubbleScraper struct {
	url     string
	client  *http.Client
	metrics *Metrics
	log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	previous map[string]hubbleSample
	// configured records whether a scrape has ever seen flow data, so the
	// misconfiguration above is reported once rather than every five seconds.
	warned bool
}

// hubbleSample is one subject's last counter reading.
type hubbleSample struct {
	at    time.Time
	flows float64
	drops float64
}

// NewHubbleScraper builds the scraper.
func NewHubbleScraper(cfg HubbleConfig) (*HubbleScraper, error) {
	if cfg.Metrics == nil {
		return nil, errors.New("scaling: a metrics store is required")
	}
	if cfg.URL == "" {
		cfg.URL = DefaultHubbleMetricsURL
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
	return &HubbleScraper{
		url: cfg.URL, client: cfg.Client, metrics: cfg.Metrics,
		log: cfg.Logger, now: cfg.Now, previous: map[string]hubbleSample{},
	}, nil
}

// Run scrapes on a ticker until the context ends.
func (s *HubbleScraper) Run(ctx context.Context, interval time.Duration) {
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

		switch _, err := s.Scrape(ctx); {
		case errors.Is(err, ErrHubbleNoFlows):
			// Reported once, with the fix, because it is a configuration
			// mistake rather than a transient failure — it will not resolve on
			// its own and repeating it every tick buries everything else.
			s.warnOnce()
		case err != nil:
			consecutive++
			if consecutive == 1 || consecutive%12 == 0 {
				s.log.Warn("hubble metrics scrape failed",
					"url", s.url, "consecutive", consecutive, "error", err)
			}
		default:
			if consecutive > 0 {
				s.log.Info("hubble metrics recovered", "url", s.url, "after", consecutive)
				consecutive = 0
			}
		}
	}
}

// warnOnce reports the silent misconfiguration, once.
func (s *HubbleScraper) warnOnce() {
	s.mu.Lock()
	already := s.warned
	s.warned = true
	s.mu.Unlock()
	if already {
		return
	}
	s.log.Error("hubble is serving metrics but reporting no flows",
		"url", s.url,
		"detail", "cilium-agent's --hubble-metrics takes a space-separated list inside "+
			"one value, e.g. --hubble-metrics='flow drop'. A comma-separated list is read "+
			"as one unknown metric name and a repeated flag keeps only the last, both "+
			"silently — the endpoint answers 200 with nothing in it (M0 spike ①)")
}

// Scrape performs one pass and reports how many subjects it recorded for.
//
// It returns ErrHubbleNoFlows when the endpoint answers but carries no flow
// family at all, so a caller can tell "Hubble is off" from "Hubble is
// misconfigured" — which look identical in the metrics themselves.
func (s *HubbleScraper) Scrape(ctx context.Context) (subjects int, err error) {
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

func (s *HubbleScraper) parse(body io.Reader, at time.Time) (int, error) {
	// Totals per subject: one per service Hubble could attribute a flow to,
	// plus the node itself for everything it could not.
	current := map[string]*hubbleSample{nodeSubject: {at: at}}
	sawFlowFamily := false

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 32<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		name, labels, rawValue, ok := splitExpositionLine(line)
		if !ok {
			continue
		}
		metric := string(name)
		switch metric {
		case hubbleFlowsMetric:
			sawFlowFamily = true
		case hubbleDropsMetric:
		default:
			continue
		}
		value, err := strconv.ParseFloat(string(rawValue), 64)
		if err != nil {
			continue
		}

		// Hubble emits one series per label combination — verdict, protocol,
		// subtype and so on — so a subject's total is the sum across all of
		// them. Summing here rather than exporting the breakdown keeps the
		// cardinality of the time series bounded by the service count, which
		// is the same bound everything else in this package respects.
		subject := hubbleSubject(labels)
		sample := current[subject]
		if sample == nil {
			sample = &hubbleSample{at: at}
			current[subject] = sample
		}
		node := current[nodeSubject]
		if metric == hubbleFlowsMetric {
			sample.flows += value
			if subject != nodeSubject {
				node.flows += value
			}
		} else {
			sample.drops += value
			if subject != nodeSubject {
				node.drops += value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scaling: read hubble metrics: %w", err)
	}

	if !sawFlowFamily {
		return 0, ErrHubbleNoFlows
	}

	recorded := 0
	for subject, sample := range current {
		if s.record(subject, sample, at) {
			recorded++
		}
	}

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
func (s *HubbleScraper) record(subject string, sample *hubbleSample, at time.Time) bool {
	s.mu.Lock()
	previous, seen := s.previous[subject]
	s.previous[subject] = *sample
	s.mu.Unlock()

	if !seen {
		return false
	}
	elapsed := at.Sub(previous.at)
	if elapsed <= 0 {
		return false
	}

	// A counter that went backwards means the agent restarted. There is no rate
	// across that discontinuity, so this reading becomes the new baseline.
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

// hubbleSubject attributes a flow series to a service, or to the node.
//
// Hubble renders an identity's labels into the `destination` label as a
// comma-joined list, so a flow into one of Kanea's endpoints carries the
// `project=` and `service=` labels the network driver attaches (§7.1). The
// destination is what matters: a service is loaded by the traffic arriving at
// it, not by what it sends.
//
// Anything unattributable — traffic to the world, to the host, or an agent
// configured without a label context — lands on the node total rather than
// being dropped. A number nobody can break down is still a number worth having.
func hubbleSubject(labels []byte) string {
	destination := labelValue(labels, "destination")
	if destination == "" {
		return nodeSubject
	}
	project, service := "", ""
	for _, label := range strings.Split(destination, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(label), "=")
		if !found {
			continue
		}
		// Cilium prefixes source-specific labels ("k8s:", "any:"); the ones
		// Kanea sets are unprefixed, and a prefix on the way in should not stop
		// a match.
		if cut := strings.LastIndex(key, ":"); cut >= 0 {
			key = key[cut+1:]
		}
		switch key {
		case "project":
			project = value
		case "service":
			service = value
		}
	}
	if project == "" || service == "" {
		return nodeSubject
	}
	return project + "/" + service
}
