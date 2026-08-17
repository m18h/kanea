package scaling_test

import (
	"os"
	"path/filepath"
	"testing"

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
