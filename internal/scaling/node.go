package scaling

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Node stats from procfs (PRD §17).
//
// The one metrics source that is not about a workload. It answers "is the node
// itself in trouble", which is the question behind a service that is slow for
// no reason its own metrics explain, and the question an operator asks first.
//
// The point-in-time reading does not go through the time series: these are
// numbers read on demand from files that are already the kernel's own
// aggregation. Since v1.38 exactly two series *are* recorded (RecordNode),
// because a dashboard sparkline needs the history procfs does not keep: CPU
// and memory percent, ≈9 KiB, under metric names the exporter's fixed list
// never publishes so the Prometheus surface is unchanged. Constraint #2 is
// untouched either way: the in-memory TS is not the Store.

// NodeStats is a point-in-time reading.
//
// Every field is a pointer, for the same reason the service sample's are: a
// missing value and a zero are different facts. A node whose CPU reads as
// absent has an unreadable /proc; a node whose CPU reads as 0.0 is idle, and
// treating those alike is how a dashboard reports a broken reader as a quiet
// node.
type NodeStats struct {
	// CPUPercent is use across all cores since the previous reading. Nil on the
	// first read, which has nothing to compare against.
	CPUPercent *float64 `json:"cpu_percent,omitempty"`
	// Load1, Load5 and Load15 are the kernel's load averages.
	Load1  *float64 `json:"load1,omitempty"`
	Load5  *float64 `json:"load5,omitempty"`
	Load15 *float64 `json:"load15,omitempty"`
	// MemoryTotal and MemoryAvailable are bytes. Available rather than free:
	// free excludes reclaimable page cache and reads as alarming on every
	// healthy Linux box.
	MemoryTotal     *uint64  `json:"memory_total_bytes,omitempty"`
	MemoryAvailable *uint64  `json:"memory_available_bytes,omitempty"`
	MemoryPercent   *float64 `json:"memory_percent,omitempty"`
	// GPUs are the node's visible GPUs (v1.42): absent on a node without
	// any, never an empty placeholder.
	GPUs []GPUStats `json:"gpus,omitempty"`
	// GPUUtilPercent is the mean busy percentage across every GPU reporting
	// one (v1.94). Nil when none does, which is every node whose only GPU is
	// integrated: Intel publishes no busy counter in sysfs.
	GPUUtilPercent *float64 `json:"gpu_util_percent,omitempty"`
	// GPUVRAMPercent aggregates VRAM use across every GPU that reports both
	// numbers: used summed over total. Nil when no GPU is visible.
	GPUVRAMPercent *float64 `json:"gpu_vram_percent,omitempty"`
	// Cores is what the CPU percentage is relative to.
	Cores int       `json:"cores"`
	At    time.Time `json:"at"`
}

// NodeReader reads node statistics.
//
// Stateful because CPU use is a delta: /proc/stat counts jiffies since boot,
// and a percentage needs two readings. The first call therefore reports no CPU
// figure rather than a meaningless one computed against boot.
type NodeReader struct {
	// procRoot is "/proc" in production and a fixture directory in tests.
	procRoot string
	now      func() time.Time
	gpu      *GPUReader

	mu   sync.Mutex
	last *nodeCPUSample
	// latest is the sampler's most recent reading, published for Read. Nil
	// until Start runs, which is what makes "nobody started me" a state Read
	// can recognise rather than a reason to serve nothing.
	latest *NodeStats
}

// nodeCPUSample is one /proc/stat reading.
type nodeCPUSample struct {
	total uint64
	idle  uint64
	at    time.Time
}

// NewNodeReader builds a reader over the given procfs root. Empty means /proc.
func NewNodeReader(procRoot string) *NodeReader {
	return NewNodeReaderWithGPU(procRoot, NewGPUReader(GPUReaderConfig{}))
}

// NewNodeReaderWithGPU is NewNodeReader with the GPU half pointed somewhere
// specific: fixtures in tests. Production uses NewNodeReader, whose defaults
// are the real /sys and the real nvidia-smi.
func NewNodeReaderWithGPU(procRoot string, gpu *GPUReader) *NodeReader {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &NodeReader{procRoot: procRoot, now: time.Now, gpu: gpu}
}

// The node's own history series (v1.38). Deliberately not "cpu"/"memory":
// the exporter publishes by metric name, and reusing the workload names under
// subject "node" would silently add kanea_cpu_percent{subject="node"} to a
// Prometheus surface nobody meant to change.
const (
	MetricNodeCPU    = "node_cpu_percent"
	MetricNodeMemory = "node_memory_percent"
	MetricNodeGPU    = "node_gpu_vram_percent"
	// MetricNodeGPUUtil is how busy the node's GPUs are (v1.94). A second
	// series rather than a label on the first: they answer different questions
	// and a card can report either without the other.
	MetricNodeGPUUtil = "node_gpu_util_percent"
	// MetricNodeLoad1 is the kernel's one-minute load average (v1.79). Load5
	// and Load15 are deliberately not recorded: three curves that differ only
	// in how much they are smoothed are three series for one fact, and the
	// point-in-time reading already carries all three.
	MetricNodeLoad1 = "node_load1"
	// MetricNodeAllocsRunning is how many allocs were running at the last
	// alloc-map refresh (v1.79). It is recorded from cmd/kanea, off the
	// listing that refresh already performs, which is the condition under
	// which constraint #2 permits it at all: a Store walk added per scrape to
	// draw one chart line is the read budget the metrics pipeline is told not
	// to spend. It therefore lands at that cadence rather than the scrape's,
	// so most slots hold nothing; those are gaps like any other and carrying
	// the last value forward would be §9.2's mistake.
	MetricNodeAllocsRunning = "node_allocs_running"
)

// RecordNode records a node reading into the time series.
//
// Only non-nil readings are recorded: the first CPU read has no delta and an
// unreadable procfs has nothing, and in both cases the honest history is a
// gap, never a zero (§9.2).
func RecordNode(m *Metrics, stats NodeStats) {
	if m == nil {
		return
	}
	if stats.CPUPercent != nil {
		m.Record(Key{Subject: NodeSubject, Metric: MetricNodeCPU}, stats.At, *stats.CPUPercent)
	}
	if stats.MemoryPercent != nil {
		m.Record(Key{Subject: NodeSubject, Metric: MetricNodeMemory}, stats.At, *stats.MemoryPercent)
	}
	if stats.GPUUtilPercent != nil {
		m.Record(Key{Subject: NodeSubject, Metric: MetricNodeGPUUtil}, stats.At, *stats.GPUUtilPercent)
	}
	if stats.GPUVRAMPercent != nil {
		m.Record(Key{Subject: NodeSubject, Metric: MetricNodeGPU}, stats.At, *stats.GPUVRAMPercent)
	}
	if stats.Load1 != nil {
		m.Record(Key{Subject: NodeSubject, Metric: MetricNodeLoad1}, stats.At, *stats.Load1)
	}
}

// RecordAllocsRunning records how many allocs are running.
//
// It takes a number rather than anything to count, deliberately: this package
// imports neither the Store nor the reconciler and must not start, so the
// caller does the counting where it is already looking (constraint #2).
func RecordAllocsRunning(m *Metrics, at time.Time, running int) {
	if m == nil {
		return
	}
	m.Record(Key{Subject: NodeSubject, Metric: MetricNodeAllocsRunning}, at, float64(running))
}

// Read answers with the node's statistics.
//
// On a started reader this is the last sample the sampler took, verbatim, `At`
// included: a reading at most one interval old that says so, and the same
// numbers the recorded history is drawn from, so a tile and its chart finally
// agree. On a reader nobody started (a development run, an API-only server,
// every test that predates Start) it samples directly, which is what it always
// did.
//
// Why it is not simply "take a reading": cpu() is a delta over the previous
// /proc/stat sample and swapping that baseline is destructive, so before v1.79
// any caller consumed the recorder's. An inbound GET /v1/stats at t=4.9s made
// the recorder's t=5s sample cover a hundred milliseconds; a real reading of
// the wrong interval, which is worse than a gap because nothing about it looks
// wrong. One owner of the schedule is the fix. A short cache would only have
// narrowed the window.
func (r *NodeReader) Read() NodeStats {
	r.mu.Lock()
	latest := r.latest
	r.mu.Unlock()
	if latest != nil {
		return *latest
	}
	return r.sample()
}

// Start gives the delta one owner: this sampler, on this schedule.
//
// It takes a reading immediately so the baseline exists before the first tick
// rather than an interval later, then samples and records until ctx is done.
// Recording is the caller's business through record, which keeps this function
// ignorant of what a metric is; passing nil just publishes readings for Read.
func (r *NodeReader) Start(ctx context.Context, interval time.Duration, record func(NodeStats)) {
	publish := func() {
		stats := r.sample()
		r.mu.Lock()
		r.latest = &stats
		r.mu.Unlock()
		if record != nil {
			record(stats)
		}
	}

	publish()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			publish()
		}
	}()
}

// sample takes a fresh reading, advancing the CPU baseline.
//
// Nothing here fails: a node whose /proc cannot be read still has a control
// plane worth talking to, and returning an error would make an unreadable
// counter break the route that reports everything else. Missing values are
// reported as missing, which is the honest answer and the one the pointer
// fields exist to express.
func (r *NodeReader) sample() NodeStats {
	stats := NodeStats{Cores: runtime.NumCPU(), At: r.now()}
	if runtime.GOOS != "linux" && r.procRoot == "/proc" {
		// procfs is Linux. On a development machine the daemon is not running
		// workloads anyway, and inventing numbers would be worse than omitting
		// them.
		return stats
	}

	if total, available, err := r.memory(); err == nil {
		stats.MemoryTotal, stats.MemoryAvailable = &total, &available
		if total > 0 {
			used := float64(total-available) / float64(total) * 100
			stats.MemoryPercent = &used
		}
	}
	if one, five, fifteen, err := r.loadAverage(); err == nil {
		stats.Load1, stats.Load5, stats.Load15 = &one, &five, &fifteen
	}
	if percent, ok := r.cpu(); ok {
		stats.CPUPercent = &percent
	}
	if r.gpu != nil {
		if gpus := r.gpu.Read(); len(gpus) > 0 {
			stats.GPUs = gpus
			stats.GPUUtilPercent = aggregateUtil(gpus)
			stats.GPUVRAMPercent = aggregateVRAM(gpus)
		}
	}
	return stats
}

// memory reads MemTotal and MemAvailable from /proc/meminfo.
func (r *NodeReader) memory() (total, available uint64, err error) {
	file, err := os.Open(r.procRoot + "/meminfo") // #nosec G304: procfs, or a test fixture
	if err != nil {
		return 0, 0, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	scanner := bufio.NewScanner(io.LimitReader(file, maxProcFile))
	for scanner.Scan() {
		name, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		switch name {
		case "MemTotal":
			total = parseKiB(rest)
		case "MemAvailable":
			available = parseKiB(rest)
		}
		if total > 0 && available > 0 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if total == 0 {
		return 0, 0, fmt.Errorf("scaling: no MemTotal in %s/meminfo", r.procRoot)
	}
	return total, available, nil
}

// maxProcFile bounds a procfs read. These files are a few kilobytes; a bound
// rather than none because a bug elsewhere could point this at anything.
const maxProcFile = 1 << 20

// parseKiB reads "  16384000 kB" into bytes.
func parseKiB(field string) uint64 {
	fields := strings.Fields(field)
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return value * 1024
}

// loadAverage reads /proc/loadavg.
func (r *NodeReader) loadAverage() (one, five, fifteen float64, err error) {
	body, err := os.ReadFile(r.procRoot + "/loadavg") // #nosec G304; procfs, or a test fixture
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(body))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("scaling: %s/loadavg has %d fields", r.procRoot, len(fields))
	}
	for i, target := range []*float64{&one, &five, &fifteen} {
		parsed, perr := strconv.ParseFloat(fields[i], 64)
		if perr != nil {
			return 0, 0, 0, perr
		}
		*target = parsed
	}
	return one, five, fifteen, nil
}

// cpu computes use since the previous reading.
func (r *NodeReader) cpu() (float64, bool) {
	sample, err := r.readCPU()
	if err != nil {
		return 0, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.last
	r.last = &sample

	if previous == nil {
		// The first reading has nothing to compare against. Reporting a
		// percentage computed against boot would be a number that looks
		// plausible and means nothing.
		return 0, false
	}
	totalDelta := sample.total - previous.total
	if sample.total < previous.total || totalDelta == 0 {
		// Counters that went backwards: a reset, or a fixture replaced mid-test.
		// Neither is a number worth publishing.
		return 0, false
	}
	idleDelta := sample.idle - previous.idle
	if sample.idle < previous.idle {
		return 0, false
	}

	busy := float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	return max(0, min(100, busy)), true
}

// readCPU parses the aggregate "cpu" line of /proc/stat.
func (r *NodeReader) readCPU() (_ nodeCPUSample, err error) {
	file, err := os.Open(r.procRoot + "/stat") // #nosec G304: procfs, or a test fixture
	if err != nil {
		return nodeCPUSample{}, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	scanner := bufio.NewScanner(io.LimitReader(file, maxProcFile))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// The aggregate line is "cpu" exactly; "cpu0", "cpu1" and so on are the
		// per-core ones, which this does not need.
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}

		var total, idle uint64
		for i, field := range fields[1:] {
			value, perr := strconv.ParseUint(field, 10, 64)
			if perr != nil {
				return nodeCPUSample{}, perr
			}
			total += value
			// Fields 4 and 5 are idle and iowait. iowait counts as idle here:
			// the CPU was available, it was simply waiting on a disk, and
			// counting it as busy makes a node with a slow disk look
			// compute-bound.
			if i == 3 || i == 4 {
				idle += value
			}
		}
		return nodeCPUSample{total: total, idle: idle, at: r.now()}, nil
	}
	if err := scanner.Err(); err != nil {
		return nodeCPUSample{}, err
	}
	return nodeCPUSample{}, fmt.Errorf("scaling: no aggregate cpu line in %s/stat", r.procRoot)
}
