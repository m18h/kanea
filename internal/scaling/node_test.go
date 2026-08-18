package scaling_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// fakeProc writes a procfs fixture and returns its root.
func fakeProc(t *testing.T, stat, meminfo, loadavg string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{
		"stat": stat, "meminfo": meminfo, "loadavg": loadavg,
	} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

const meminfoFixture = `MemTotal:       16384000 kB
MemFree:         1024000 kB
Buffers:          512000 kB
Cached:          4096000 kB
MemAvailable:    8192000 kB
SwapTotal:             0 kB
`

func TestNodeReaderReadsMemoryAndLoad(t *testing.T) {
	root := fakeProc(t,
		"cpu  100 0 100 800 0 0 0 0 0 0\n",
		meminfoFixture,
		"0.52 1.04 2.08 3/512 12345\n")

	stats := scaling.NewNodeReader(root).Read()

	if stats.MemoryTotal == nil || *stats.MemoryTotal != 16384000*1024 {
		t.Errorf("memory total = %v, want %d bytes", stats.MemoryTotal, 16384000*1024)
	}
	// Available, not free: free excludes reclaimable page cache and reads as
	// alarming on every healthy Linux box.
	if stats.MemoryAvailable == nil || *stats.MemoryAvailable != 8192000*1024 {
		t.Errorf("memory available = %v, want %d bytes", stats.MemoryAvailable, 8192000*1024)
	}
	if stats.MemoryPercent == nil || *stats.MemoryPercent != 50 {
		t.Errorf("memory percent = %v, want 50", stats.MemoryPercent)
	}
	if stats.Load1 == nil || *stats.Load1 != 0.52 {
		t.Errorf("load1 = %v, want 0.52", stats.Load1)
	}
	if stats.Load15 == nil || *stats.Load15 != 2.08 {
		t.Errorf("load15 = %v, want 2.08", stats.Load15)
	}
}

func TestNodeFirstCPUReadingReportsNothing(t *testing.T) {
	// /proc/stat counts jiffies since boot. A percentage from one reading is
	// "average use since the machine started", which looks like a live number
	// and is not one.
	root := fakeProc(t, "cpu  100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.1 0.2 0.3 1/2 3\n")
	stats := scaling.NewNodeReader(root).Read()
	if stats.CPUPercent != nil {
		t.Errorf("the first reading reported %v%% CPU; it has nothing to compare against",
			*stats.CPUPercent)
	}
}

func TestNodeCPUIsADeltaBetweenReadings(t *testing.T) {
	root := fakeProc(t, "cpu  100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.1 0.2 0.3 1/2 3\n")
	reader := scaling.NewNodeReader(root)
	reader.Read()

	// user +50, system +50, idle +50, iowait +50 → total delta 200, idle 100.
	if err := os.WriteFile(filepath.Join(root, "stat"),
		[]byte("cpu  150 0 150 850 50 0 0 0 0 0\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stats := reader.Read()
	if stats.CPUPercent == nil {
		t.Fatal("the second reading reported no CPU figure")
	}
	if got := *stats.CPUPercent; got < 49.9 || got > 50.1 {
		t.Errorf("cpu = %.2f%%, want about 50%%", got)
	}
}

func TestNodeIOWaitCountsAsIdle(t *testing.T) {
	// The CPU was available; it was waiting on a disk. Counting iowait as busy
	// makes a node with a slow disk look compute-bound, which sends an operator
	// looking for the wrong thing.
	root := fakeProc(t, "cpu  100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.1 0.2 0.3 1/2 3\n")
	reader := scaling.NewNodeReader(root)
	reader.Read()

	// Nothing but iowait since: 200 jiffies of waiting, no compute.
	if err := os.WriteFile(filepath.Join(root, "stat"),
		[]byte("cpu  100 0 100 800 200 0 0 0 0 0\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stats := reader.Read()
	if stats.CPUPercent == nil {
		t.Fatal("no CPU figure")
	}
	if got := *stats.CPUPercent; got != 0 {
		t.Errorf("cpu = %.2f%% with nothing but iowait, want 0", got)
	}
}

func TestNodeCountersGoingBackwardsReportNothing(t *testing.T) {
	// A reset, or a fixture replaced underneath. Neither is a number worth
	// publishing, and the subtraction would underflow into something enormous.
	root := fakeProc(t, "cpu  1000 0 1000 8000 0 0 0 0 0 0\n", meminfoFixture, "0.1 0.2 0.3 1/2 3\n")
	reader := scaling.NewNodeReader(root)
	reader.Read()

	if err := os.WriteFile(filepath.Join(root, "stat"),
		[]byte("cpu  10 0 10 80 0 0 0 0 0 0\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if stats := reader.Read(); stats.CPUPercent != nil {
		t.Errorf("a backwards counter produced %v%%", *stats.CPUPercent)
	}
}

func TestNodeUnreadableProcfsIsMissingNotZero(t *testing.T) {
	// A node whose /proc cannot be read still has a control plane worth talking
	// to. Reporting zeroes would make a broken reader indistinguishable from an
	// idle node: the same rule the time series and the exporter follow.
	stats := scaling.NewNodeReader(filepath.Join(t.TempDir(), "nothing-here")).Read()

	if stats.MemoryTotal != nil || stats.Load1 != nil || stats.CPUPercent != nil {
		t.Errorf("an unreadable procfs produced values: %+v", stats)
	}
	// The core count comes from the runtime, not from procfs, so it is still
	// there, and the reading is still a reading rather than an error.
	if stats.Cores <= 0 {
		t.Errorf("cores = %d", stats.Cores)
	}
	if stats.At.IsZero() {
		t.Error("the reading has no timestamp")
	}
}

func TestNodePartialProcfsReportsWhatItCanRead(t *testing.T) {
	// One unreadable file must not take the others with it: a node reporting
	// its load average and no CPU figure is more useful than one reporting
	// nothing.
	root := fakeProc(t, "", meminfoFixture, "1.5 1.0 0.5 1/2 3\n")
	stats := scaling.NewNodeReader(root).Read()

	if stats.Load1 == nil || *stats.Load1 != 1.5 {
		t.Errorf("load1 = %v, want 1.5", stats.Load1)
	}
	if stats.MemoryTotal == nil {
		t.Error("memory was not read despite meminfo being present")
	}
	if stats.CPUPercent != nil {
		t.Error("a CPU figure appeared with no /proc/stat")
	}
}

func TestOnlyTheSamplerAdvancesTheCPUBaseline(t *testing.T) {
	// The v1.79 regression. cpu() is a delta over the previous /proc/stat
	// reading and swapping that baseline is destructive, so before this every
	// GET /v1/stats consumed the recorder's: an inbound request at t=4.9s made
	// the *next* recorded node_cpu_percent cover a hundred milliseconds. A real
	// reading of the wrong interval, which is worse than a gap because nothing
	// about it looks wrong.
	root := fakeProc(t, "cpu  100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.1 0.2 0.3 1/2 3\n")
	reader := scaling.NewNodeReader(root)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var recorded []scaling.NodeStats
	// An interval long enough that the ticker never fires during the test: the
	// only sample here is Start's synchronous first one, which is what makes
	// "did anything else take a reading" observable.
	reader.Start(ctx, time.Hour, func(stats scaling.NodeStats) {
		mu.Lock()
		defer mu.Unlock()
		recorded = append(recorded, stats)
	})

	first := reader.Read()

	// Move the counters. A reader that samples on Read would now compute and
	// report a delta, and would leave the sampler a baseline it never chose.
	if err := os.WriteFile(filepath.Join(root, "stat"),
		[]byte("cpu  150 0 150 850 50 0 0 0 0 0\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for range 50 {
		stats := reader.Read()
		if !stats.At.Equal(first.At) {
			t.Fatalf("Read took a fresh reading (at %v, want the sampler's %v): "+
				"it is consuming the baseline the sampler needs", stats.At, first.At)
		}
		if stats.CPUPercent != nil {
			t.Fatalf("Read reported %v%% CPU from a second sampling; only the "+
				"sampler may advance the delta", *stats.CPUPercent)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(recorded) != 1 {
		t.Fatalf("the sampler ran %d times, want 1: something else is driving it", len(recorded))
	}
}

func TestAnUndrivenReaderStillReads(t *testing.T) {
	// Development runs, an API-only server and every test that predates Start:
	// nobody owns the schedule, so Read samples directly, exactly as it always
	// did. Serving nothing here would be a blank dashboard off a working procfs.
	root := fakeProc(t, "cpu  100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.52 1.04 2.08 3/512 12345\n")
	stats := scaling.NewNodeReader(root).Read()

	if stats.MemoryPercent == nil || *stats.MemoryPercent != 50 {
		t.Errorf("memory percent = %v, want 50", stats.MemoryPercent)
	}
	if stats.Load1 == nil || *stats.Load1 != 0.52 {
		t.Errorf("load1 = %v, want 0.52", stats.Load1)
	}
}

func TestRecordNodeRecordsLoad1AndNotItsSiblings(t *testing.T) {
	m, c := newMetrics(t)
	one, five, fifteen := 0.52, 1.04, 2.08
	scaling.RecordNode(m, scaling.NodeStats{
		At: c.at, Load1: &one, Load5: &five, Load15: &fifteen,
	})

	if _, ok := m.Latest(key(scaling.NodeSubject, scaling.MetricNodeLoad1)); !ok {
		t.Error("node_load1 was not recorded")
	}
	// Three curves differing only in how much they are smoothed would be three
	// series for one fact; the point-in-time reading already carries all three.
	for _, name := range []string{"node_load5", "node_load15"} {
		if _, ok := m.Latest(key(scaling.NodeSubject, name)); ok {
			t.Errorf("%s was recorded; only load1 belongs in the series", name)
		}
	}
}

func TestRecordAllocsRunningIsASeriesAndToleratesNoStore(t *testing.T) {
	m, c := newMetrics(t)
	scaling.RecordAllocsRunning(m, c.at, 7)

	point, ok := m.Latest(key(scaling.NodeSubject, scaling.MetricNodeAllocsRunning))
	if !ok {
		t.Fatal("node_allocs_running was not recorded")
	}
	if point.Value != 7 {
		t.Errorf("running = %v, want 7", point.Value)
	}
	// Nil is the API-only server: the resolver still runs, nothing records.
	scaling.RecordAllocsRunning(nil, c.at, 7)
}
