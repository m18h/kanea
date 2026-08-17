package scaling

import (
	"bufio"
	"bytes"
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

// DefaultContainerdMetricsURL is containerd's Prometheus listener, configured
// in containerd's config v4 as `[plugins.'io.containerd.server.v1.metrics']`
// (spike ②).
const DefaultContainerdMetricsURL = "http://127.0.0.1:1338/v1/metrics"

// Metric names recorded by the scraper.
const (
	// MetricCPU is percent of the alloc's declared CPU limit, which is what the
	// job spec's `metric "cpu" { target = 70 }` means (§6.1).
	MetricCPU = "cpu"
	// MetricMemory is percent of the declared memory limit.
	MetricMemory = "memory"
	// MetricMemoryBytes is the raw figure, for the dashboard's graphs: a
	// percentage is what you scale on, bytes are what you look at.
	MetricMemoryBytes = "memory_bytes"
	// MetricPIDs is the current process count.
	MetricPIDs = "pids"
)

// containerd's metric names, as measured in spike ②. Only these are parsed:
// the endpoint carries 47 families per task, and at the §21 target of 2 000
// allocs that is a response no one should be building a map out of.
const (
	cpuUsageMetric    = "container_cpu_usage_usec_microseconds"
	memoryUsageMetric = "container_memory_usage_bytes"
	pidsCurrentMetric = "container_pids_current"
)

// AllocInfo is what the scraper needs to turn containerd's raw counters into
// the numbers a scaling rule is written against.
type AllocInfo struct {
	// Subject is the per-alloc series subject, "project/service/alloc-id".
	Subject string
	// Service is the service subject, "project/service", which per-alloc
	// samples are averaged into.
	Service string
	// CPUMillis and MemoryBytes are the alloc's declared limits. A percentage
	// is meaningless without them, which is why an alloc that has not been
	// resolved is skipped rather than recorded against a guess.
	CPUMillis   int64
	MemoryBytes int64
}

// AllocResolver maps a containerd container id to the alloc it belongs to.
//
// The scraper cannot know this: containerd labels a sample with a container id
// and nothing else, and which service that is lives in the Store.
type AllocResolver interface {
	Alloc(containerID string) (AllocInfo, bool)
}

// ContainerdConfig configures the scraper.
type ContainerdConfig struct {
	// URL is containerd's metrics endpoint. Empty means the default.
	URL string
	// Metrics receives the samples.
	Metrics *Metrics
	// Allocs resolves container ids. Required.
	Allocs AllocResolver
	// Client is injectable for tests. Nil builds a bounded one.
	Client *http.Client
	Logger *slog.Logger
	Now    func() time.Time
}

// ContainerdScraper turns containerd's Prometheus endpoint into samples.
//
// One HTTP call covers every container on the node. The alternative (asking
// each task for its own metrics) is thousands of shim RPCs a minute at the
// §21 target, which is the cost §9.1 exists to avoid.
//
// It speaks HTTP to containerd's metrics listener rather than going through the
// containerd client, so it carries no dependency on the runtime driver and a
// broken scrape cannot disturb task lifecycle.
type ContainerdScraper struct {
	url     string
	client  *http.Client
	metrics *Metrics
	allocs  AllocResolver
	log     *slog.Logger
	now     func() time.Time

	// mu guards previous, which is what makes a CPU *rate* out of a counter.
	mu       sync.Mutex
	previous map[string]cpuSample
}

// cpuSample is the last CPU counter seen for a container.
type cpuSample struct {
	usec float64
	at   time.Time
}

// NewContainerdScraper builds a scraper.
func NewContainerdScraper(cfg ContainerdConfig) (*ContainerdScraper, error) {
	if cfg.Metrics == nil {
		return nil, errors.New("scaling: a metrics store is required")
	}
	if cfg.Allocs == nil {
		return nil, errors.New("scaling: an alloc resolver is required")
	}
	if cfg.URL == "" {
		cfg.URL = DefaultContainerdMetricsURL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			// Shorter than the scrape interval on purpose: a scrape that has
			// not answered by the time the next one is due is a scrape to
			// abandon, not one to queue behind.
			Timeout: 4 * time.Second,
		}
	}
	return &ContainerdScraper{
		url: cfg.URL, client: cfg.Client, metrics: cfg.Metrics,
		allocs: cfg.Allocs, log: cfg.Logger, now: cfg.Now,
		previous: map[string]cpuSample{},
	}, nil
}

// Run scrapes on a ticker until the context ends.
func (s *ContainerdScraper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = RawInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := s.Scrape(ctx); err != nil {
			// A failed scrape is a gap in a series, not a reason to stop: the
			// next tick is five seconds away, and metrics missing for one tick
			// are recorded as absent rather than as zero.
			s.log.Warn("containerd metrics scrape failed", "url", s.url, "error", err)
		}
	}
}

// Scrape performs one pass and reports how many samples it recorded.
func (s *ContainerdScraper) Scrape(ctx context.Context) (recorded int, err error) {
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
		// Drain a little so the connection can be reused rather than torn down
		// and redialled every five seconds.
		if _, derr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)); derr != nil {
			s.log.Debug("drain error body", "error", derr)
		}
		return 0, fmt.Errorf("scaling: scrape %s: %s", s.url, resp.Status)
	}
	return s.parse(resp.Body, s.now())
}

// parse reads the exposition format and records what it recognises.
//
// Streaming, line by line, matching three names out of the 47 families per task
// that the endpoint carries. Nothing is buffered and no map of the response is
// built: parsing the whole body to discard nine tenths of it would make the
// metrics pipeline the most expensive thing on the node.
//
// spike ② left this open ("re-measure at 2 000-alloc scale") so
// BenchmarkScrapeParse does, on a body of that shape:
//
//	2.2 ms per scrape, 439 MB/s, 1.2 MB allocated
//
// Every five seconds that is roughly 0.04% of one core, which is what makes a
// five-second resolution affordable at the §21 target. The allocations are one
// small string per *matched* line; a line this scraper does not want costs
// nothing, because the name is compared as bytes before anything is built.
func (s *ContainerdScraper) parse(body io.Reader, at time.Time) (int, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)

	// Per-service accumulators, so a service-level average falls out of the
	// same pass rather than costing a second walk over every alloc.
	//
	// CPU and memory are counted separately because they are not always both
	// available: CPU needs two scrapes to become a rate, so on the first pass
	// after a restart a service has memory and no CPU. One shared counter
	// would gate the memory mean on the CPU one and record neither.
	type accumulator struct {
		cpuSum   float64
		cpuCount int
		memSum   float64
		memCount int
	}
	services := map[string]*accumulator{}
	recorded := 0

	for scanner.Scan() {
		// Bytes, not Text: Text allocates a string for every line, and at the
		// §21 target that is 10 000 strings every five seconds of which nine in
		// ten are families this scraper does not want. The name is compared as
		// `string(name)` against constants, which the compiler does without
		// allocating, so a line that does not match costs nothing at all.
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		name, labels, rawValue, ok := splitExpositionLine(line)
		if !ok {
			continue
		}
		switch string(name) {
		case cpuUsageMetric, memoryUsageMetric, pidsCurrentMetric:
		default:
			continue
		}

		value, err := strconv.ParseFloat(string(rawValue), 64)
		if err != nil {
			continue
		}
		id := labelValue(labels, "container_id")
		if id == "" {
			continue
		}
		info, ok := s.allocs.Alloc(id)
		if !ok {
			// A container this node runs that Kanea does not: another tenant of
			// the same containerd, or an alloc already removed from the Store.
			// Recording it would attribute load to a service that is not there.
			continue
		}

		acc := services[info.Service]
		if acc == nil {
			acc = &accumulator{}
			services[info.Service] = acc
		}

		switch string(name) {
		case cpuUsageMetric:
			percent, ok := s.cpuPercent(id, value, at, info.CPUMillis)
			if !ok {
				continue
			}
			s.metrics.Record(Key{Subject: info.Subject, Metric: MetricCPU}, at, percent)
			acc.cpuSum += percent
			acc.cpuCount++
			recorded++
		case memoryUsageMetric:
			s.metrics.Record(Key{Subject: info.Subject, Metric: MetricMemoryBytes}, at, value)
			recorded++
			if info.MemoryBytes > 0 {
				percent := value / float64(info.MemoryBytes) * 100
				s.metrics.Record(Key{Subject: info.Subject, Metric: MetricMemory}, at, percent)
				acc.memSum += percent
				acc.memCount++
				recorded++
			}
		case pidsCurrentMetric:
			s.metrics.Record(Key{Subject: info.Subject, Metric: MetricPIDs}, at, value)
			recorded++
		}
	}
	if err := scanner.Err(); err != nil {
		return recorded, fmt.Errorf("scaling: read metrics: %w", err)
	}

	// The service-level mean is what a scaling rule reads: "cpu 70%" is a
	// statement about the service, and one hot alloc among ten is not it.
	for service, acc := range services {
		if acc.cpuCount > 0 {
			s.metrics.Record(Key{Subject: service, Metric: MetricCPU}, at, acc.cpuSum/float64(acc.cpuCount))
		}
		if acc.memCount > 0 {
			s.metrics.Record(Key{Subject: service, Metric: MetricMemory}, at, acc.memSum/float64(acc.memCount))
		}
	}

	s.forgetVanished()
	return recorded, nil
}

// cpuPercent turns containerd's cumulative CPU counter into a percentage of the
// alloc's limit.
//
// The endpoint reports microseconds of CPU used since the container started, so
// a single reading says nothing about current load: the rate between two
// readings does. The first scrape of a container therefore records nothing,
// which is correct and is why an autoscaler must distinguish "no data" from
// "no load".
func (s *ContainerdScraper) cpuPercent(id string, usec float64, at time.Time, cpuMillis int64) (float64, bool) {
	s.mu.Lock()
	previous, seen := s.previous[id]
	s.previous[id] = cpuSample{usec: usec, at: at}
	s.mu.Unlock()

	if !seen || cpuMillis <= 0 {
		return 0, false
	}
	elapsed := at.Sub(previous.at)
	if elapsed <= 0 {
		return 0, false
	}
	used := usec - previous.usec
	if used < 0 {
		// The counter went backwards: the container was replaced and reused its
		// id, or containerd restarted. There is no meaningful rate across that
		// discontinuity, so this scrape re-baselines instead of reporting one.
		return 0, false
	}

	// Cores used = CPU-microseconds per wall microsecond. The limit is in
	// millicores, so 1 000 millicores is one core.
	cores := used / float64(elapsed.Microseconds())
	return cores / (float64(cpuMillis) / 1000) * 100, true
}

// forgetVanished drops CPU baselines for containers that no longer resolve.
//
// Without it this map is the leak the series cap does not cover: it is keyed by
// container id, and a service that crash-loops mints a new one every restart.
func (s *ContainerdScraper) forgetVanished() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := s.now().Add(-2 * RollupInterval)
	for id, sample := range s.previous {
		if sample.at.Before(cutoff) {
			delete(s.previous, id)
		}
	}
}

// ---- exposition parsing ----

// splitExpositionLine splits `name{labels} value` into three sub-slices.
//
// A hand-written split rather than a Prometheus parsing library: the shape is
// three fields, the hot path runs over tens of megabytes every five seconds,
// and a dependency that builds a metric-family tree is exactly the cost this
// scraper exists to avoid. Everything returned aliases the caller's buffer, so
// a line that turns out to be uninteresting has allocated nothing.
func splitExpositionLine(line []byte) (name, labels, value []byte, ok bool) {
	brace := bytes.IndexByte(line, '{')
	space := bytes.IndexByte(line, ' ')
	if space < 0 {
		return nil, nil, nil, false
	}

	if brace >= 0 && brace < space {
		end := bytes.LastIndexByte(line, '}')
		if end < brace {
			return nil, nil, nil, false
		}
		name, labels = line[:brace], line[brace+1:end]
		space = end + 1
	} else {
		name = line[:space]
	}

	rest := bytes.TrimSpace(line[space:])
	// A sample may carry a trailing timestamp; the value is the first field.
	if cut := bytes.IndexByte(rest, ' '); cut >= 0 {
		rest = rest[:cut]
	}
	if len(rest) == 0 {
		return nil, nil, nil, false
	}
	return name, labels, rest, true
}

// labelValue extracts one label from a raw Prometheus label set.
//
// Quote-aware, and it has to be: a label *value* may legally contain commas;
// a container id, an escaped path. Splitting on commas first truncates such a
// value at the first one, which reads as a perfectly plausible label and
// attributes every sample to the wrong subject.
//
// The returned string is a copy, because it outlives the scanner's buffer.
func labelValue(labels []byte, want string) string {
	for i := 0; i < len(labels); {
		// Skip separators left by the previous pair.
		if labels[i] == ',' || labels[i] == ' ' {
			i++
			continue
		}
		eq := bytes.IndexByte(labels[i:], '=')
		if eq < 0 {
			return ""
		}
		key := bytes.TrimSpace(labels[i : i+eq])
		rest := labels[i+eq+1:]

		var value []byte
		var consumed int
		if len(rest) > 0 && rest[0] == '"' {
			end := 1
			for end < len(rest) {
				if rest[end] == '\\' {
					// An escaped character, whatever it is, cannot end the value.
					end += 2
					continue
				}
				if rest[end] == '"' {
					break
				}
				end++
			}
			if end > len(rest) {
				end = len(rest)
			}
			value, consumed = rest[1:end], end+1
		} else {
			end := bytes.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			value, consumed = rest[:end], end
		}

		if string(key) == want {
			return unescapeLabel(string(value))
		}
		i += eq + 1 + consumed
	}
	return ""
}

// unescapeLabel undoes the exposition format's escaping.
func unescapeLabel(value string) string {
	if !strings.Contains(value, "\\") {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			b.WriteByte(value[i])
			continue
		}
		i++
		switch value[i] {
		case 'n':
			b.WriteByte('\n')
		default:
			// \" and \\ are the only others the format defines; anything else
			// is passed through as written rather than guessed at.
			b.WriteByte(value[i])
		}
	}
	return b.String()
}
