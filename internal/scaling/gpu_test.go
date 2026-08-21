package scaling_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/scaling"
)

// fakeSys builds a sysfs fixture: one directory per /sys/class/drm entry, with
// the given device files inside. A name may carry separators, which is how a
// fixture declares a render node ("drm/renderD128/dev").
func fakeSys(t *testing.T, cards map[string]map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for card, files := range cards {
		device := filepath.Join(root, "class", "drm", card, "device")
		if err := os.MkdirAll(device, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			path := filepath.Join(device, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// renderNode is what a fixture adds to say "this device can compute".
const renderNode = "drm/renderD128/dev"

func noNvidia(context.Context) ([]byte, error) {
	return nil, errors.New("gpu_test: no nvidia-smi here")
}

func TestGPUAmdgpuIsReadFromSysfs(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {
			"mem_info_vram_used":  "2147483648\n",
			"mem_info_vram_total": "8589934592\n",
			"uevent":              "DRIVER=amdgpu\nPCI_ID=1002:73FF\n",
		},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})

	gpus := r.Read()
	if len(gpus) != 1 {
		t.Fatalf("gpus = %d, want 1", len(gpus))
	}
	g := gpus[0]
	if g.Name != "card0 (amdgpu)" {
		t.Errorf("name = %q", g.Name)
	}
	if g.VRAMUsed == nil || *g.VRAMUsed != 2147483648 {
		t.Errorf("used = %v", g.VRAMUsed)
	}
	if g.VRAMTotal == nil || *g.VRAMTotal != 8589934592 {
		t.Errorf("total = %v", g.VRAMTotal)
	}
	if g.VRAMPercent == nil || *g.VRAMPercent != 25 {
		t.Errorf("percent = %v, want 25", g.VRAMPercent)
	}
}

// An integrated GPU has no VRAM because it has none: it shares system memory,
// which the node's own memory reading already covers. Reporting it with no VRAM
// fields is the honest answer, and it is why those fields are pointers. Before
// v1.91 it was skipped, so a node whose only GPU was integrated rendered no
// panel and read as having no GPU at all.
func TestGPUAnIntegratedGPUIsNamedWithNoVRAM(t *testing.T) {
	// card0 is an iGPU publishing no VRAM files; card0-DP-1 is a connector
	// entry the card* glob also matches and which has no device at all.
	sys := fakeSys(t, map[string]map[string]string{
		"card0":      {"uevent": "DRIVER=i915\n", renderNode: ""},
		"card0-DP-1": {},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})

	gpus := r.Read()
	if len(gpus) != 1 {
		t.Fatalf("gpus = %+v, want exactly the iGPU", gpus)
	}
	if gpus[0].Name != "card0 (i915)" {
		t.Errorf("name = %q, want the card and its driver", gpus[0].Name)
	}
	if gpus[0].VRAMUsed != nil || gpus[0].VRAMTotal != nil || gpus[0].VRAMPercent != nil {
		t.Errorf("an iGPU reported VRAM it does not have: %+v", gpus[0])
	}
}

// A server's BMC display adapter is a DRM card and is not a GPU. Without this
// the majority of headless nodes would grow a permanent unmeasurable panel,
// which is a worse lie than the one v1.91 fixes.
func TestGPUADisplayOnlyAdapterIsNotAGPU(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"uevent": "DRIVER=mgag200\n"}, // no render node
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	if gpus := r.Read(); len(gpus) != 0 {
		t.Errorf("gpus = %+v, want none: a BMC VGA cannot run a workload", gpus)
	}
}

// An NVIDIA card appears under /sys/class/drm *and* in nvidia-smi, and only one
// of those two has the numbers. Counting it twice would halve every percentage
// the aggregate reports.
func TestGPUAnNvidiaCardIsNotCountedTwice(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"uevent": "DRIVER=nvidia\n", renderNode: ""},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys,
		NvidiaSMI: func(context.Context) ([]byte, error) {
			return []byte("NVIDIA GeForce RTX 4090, 37, 2048, 24564\n"), nil
		}})

	gpus := r.Read()
	if len(gpus) != 1 {
		t.Fatalf("gpus = %+v, want exactly one", gpus)
	}
	if gpus[0].Name != "NVIDIA GeForce RTX 4090" {
		t.Errorf("name = %q, want nvidia-smi's, which carries the numbers", gpus[0].Name)
	}
}

// nouveau is deliberately not excluded beside the proprietary driver: nvidia-smi
// does not see those cards, so this path is the only thing that would name them.
func TestGPUNouveauIsNamed(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"uevent": "DRIVER=nouveau\n", renderNode: ""},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})

	gpus := r.Read()
	if len(gpus) != 1 || gpus[0].Name != "card0 (nouveau)" {
		t.Fatalf("gpus = %+v, want the nouveau card named", gpus)
	}
}

func TestGPUGarbageSysfsIsAbsentNeverZero(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {
			"mem_info_vram_used":  "not a number\n",
			"mem_info_vram_total": "8589934592\n",
		},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})

	gpus := r.Read()
	if len(gpus) != 1 {
		t.Fatalf("gpus = %d, want 1 (total is still readable)", len(gpus))
	}
	if gpus[0].VRAMUsed != nil {
		t.Errorf("used = %v, want absent for a garbage reading", *gpus[0].VRAMUsed)
	}
	if gpus[0].VRAMPercent != nil {
		t.Errorf("percent = %v, want absent without both halves", *gpus[0].VRAMPercent)
	}
}

func TestGPUNvidiaSMIIsParsed(t *testing.T) {
	sys := fakeSys(t, nil)
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{
		SysRoot: sys,
		NvidiaSMI: func(context.Context) ([]byte, error) {
			return []byte("NVIDIA GeForce RTX 4090, 37, 1024, 24564\nNVIDIA RTX A2000, [N/A], [N/A], [N/A]\n"), nil
		},
	})

	gpus := r.Read()
	if len(gpus) != 2 {
		t.Fatalf("gpus = %d, want 2", len(gpus))
	}
	if gpus[0].Name != "NVIDIA GeForce RTX 4090" {
		t.Errorf("name = %q", gpus[0].Name)
	}
	if gpus[0].VRAMUsed == nil || *gpus[0].VRAMUsed != 1024*1024*1024 {
		t.Errorf("used = %v, want MiB converted to bytes", gpus[0].VRAMUsed)
	}
	if gpus[0].UtilPercent == nil || *gpus[0].UtilPercent != 37 {
		t.Errorf("util = %v, want 37", gpus[0].UtilPercent)
	}
	// The second card answered [N/A]: the name is real, the numbers absent.
	if gpus[1].UtilPercent != nil || gpus[1].VRAMUsed != nil ||
		gpus[1].VRAMTotal != nil || gpus[1].VRAMPercent != nil {
		t.Errorf("[N/A] readings must be absent, got %+v", gpus[1])
	}
}

func TestGPUNvidiaSMIFailureIsNoGPUs(t *testing.T) {
	sys := fakeSys(t, nil)
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	if gpus := r.Read(); gpus != nil {
		t.Errorf("gpus = %+v, want none", gpus)
	}
}

func TestGPUReadingsAreCachedBriefly(t *testing.T) {
	calls := 0
	now := time.Now()
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{
		SysRoot: fakeSys(t, nil),
		NvidiaSMI: func(context.Context) ([]byte, error) {
			calls++
			return []byte("NVIDIA T400, 12, 100, 2048\n"), nil
		},
		Now: func() time.Time { return now },
	})

	r.Read()
	r.Read()
	if calls != 1 {
		t.Errorf("calls after two immediate reads = %d, want 1 (cached)", calls)
	}
	now = now.Add(time.Minute)
	r.Read()
	if calls != 2 {
		t.Errorf("calls after the cache aged out = %d, want 2", calls)
	}
}

func TestNodeReadAggregatesGPUVRAM(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {
			"mem_info_vram_used":  "1073741824\n", // 1 GiB of 8
			"mem_info_vram_total": "8589934592\n",
			"uevent":              "DRIVER=amdgpu\n",
		},
		"card1": {
			"mem_info_vram_used":  "3221225472\n", // 3 GiB of 8
			"mem_info_vram_total": "8589934592\n",
			"uevent":              "DRIVER=amdgpu\n",
		},
	})
	gpu := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	reader := scaling.NewNodeReaderWithGPU(
		fakeProc(t, "cpu 100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.5 0.4 0.3 1/100 200\n"),
		gpu)

	stats := reader.Read()
	if len(stats.GPUs) != 2 {
		t.Fatalf("gpus = %d, want 2", len(stats.GPUs))
	}
	// 4 GiB used of 16 GiB total across both cards.
	if stats.GPUVRAMPercent == nil || *stats.GPUVRAMPercent != 25 {
		t.Errorf("aggregate = %v, want 25", stats.GPUVRAMPercent)
	}
}

// A GPU with no VRAM numbers is visible and contributes nothing to the ratio.
// The aggregate is used-over-total, so folding in a card that reports neither
// would make a node with an iGPU beside a real card read as less used than it
// is - and a node with only an iGPU read as 0%, which is the zero §9.2 forbids.
func TestNodeGPUWithoutVRAMIsVisibleButNotAggregated(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"uevent": "DRIVER=i915\n", renderNode: ""},
	})
	gpu := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	reader := scaling.NewNodeReaderWithGPU(
		fakeProc(t, "cpu 100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.5 0.4 0.3 1/100 200\n"),
		gpu)

	stats := reader.Read()
	if len(stats.GPUs) != 1 {
		t.Fatalf("gpus = %+v, want the iGPU listed", stats.GPUs)
	}
	if stats.GPUVRAMPercent != nil {
		t.Errorf("aggregate = %v, want absent: an iGPU has no VRAM to be a ratio of",
			*stats.GPUVRAMPercent)
	}
}

func TestNodeWithoutGPUsReportsAbsence(t *testing.T) {
	gpu := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: fakeSys(t, nil), NvidiaSMI: noNvidia})
	reader := scaling.NewNodeReaderWithGPU(
		fakeProc(t, "cpu 100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.5 0.4 0.3 1/100 200\n"),
		gpu)

	stats := reader.Read()
	if stats.GPUs != nil {
		t.Errorf("gpus = %+v, want absent", stats.GPUs)
	}
	if stats.GPUVRAMPercent != nil {
		t.Errorf("aggregate = %v, want absent: a GPU-less node is not a 0%% GPU", *stats.GPUVRAMPercent)
	}
}

// --- utilisation (v1.94) ---------------------------------------------------
//
// "Is the transcode actually using the GPU" is a question about occupancy, not
// about memory, so it is the first number the reader publishes and the first
// the dashboard draws.

// amdgpu publishes busy time as a plain percentage file, which is the whole
// reason utilisation costs nothing on that driver.
func TestGPUAmdgpuUtilisationIsReadFromSysfs(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {
			"gpu_busy_percent":    "63\n",
			"mem_info_vram_used":  "2147483648\n",
			"mem_info_vram_total": "8589934592\n",
			"uevent":              "DRIVER=amdgpu\n",
		},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})

	gpus := r.Read()
	if len(gpus) != 1 {
		t.Fatalf("gpus = %d, want 1", len(gpus))
	}
	if gpus[0].UtilPercent == nil || *gpus[0].UtilPercent != 63 {
		t.Errorf("util = %v, want 63", gpus[0].UtilPercent)
	}
}

// An integrated GPU has no busy counter in sysfs: Intel's live behind the perf
// PMU. Absent, never zero - "idle" and "nobody asked" are opposite facts, and
// a 0% reading is the one that would send somebody debugging a working
// transcode (§9.2).
func TestGPUAnIntegratedGPUReportsNoUtilisation(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"uevent": "DRIVER=i915\n", renderNode: ""},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})

	gpus := r.Read()
	if len(gpus) != 1 {
		t.Fatalf("gpus = %+v, want the iGPU listed", gpus)
	}
	if gpus[0].UtilPercent != nil {
		t.Errorf("util = %v, want absent for a driver that publishes none", *gpus[0].UtilPercent)
	}
}

// Garbage and out-of-range readings are absences too. A driver answering 255
// is a driver this code does not understand, and clamping it to 100 would
// publish a number nobody measured.
func TestGPUImplausibleUtilisationIsAbsent(t *testing.T) {
	for name, body := range map[string]string{
		"garbage":      "not a number\n",
		"out of range": "255\n",
	} {
		t.Run(name, func(t *testing.T) {
			sys := fakeSys(t, map[string]map[string]string{
				"card0": {"gpu_busy_percent": body, "mem_info_vram_total": "8589934592\n"},
			})
			r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
			gpus := r.Read()
			if len(gpus) != 1 {
				t.Fatalf("gpus = %+v, want the card (its VRAM is readable)", gpus)
			}
			if gpus[0].UtilPercent != nil {
				t.Errorf("util = %v, want absent", *gpus[0].UtilPercent)
			}
		})
	}
}

// The node aggregate is a mean, not a used-over-total: utilisation is already
// a ratio and there is no second quantity to weight it by.
func TestNodeGPUUtilisationIsTheMeanAcrossCards(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"gpu_busy_percent": "100\n", "uevent": "DRIVER=amdgpu\n"},
		"card1": {"gpu_busy_percent": "40\n", "uevent": "DRIVER=amdgpu\n"},
	})
	gpu := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	reader := scaling.NewNodeReaderWithGPU(
		fakeProc(t, "cpu 100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.5 0.4 0.3 1/100 200\n"),
		gpu)

	stats := reader.Read()
	if stats.GPUUtilPercent == nil || *stats.GPUUtilPercent != 70 {
		t.Errorf("aggregate = %v, want 70", stats.GPUUtilPercent)
	}
}

// A node whose only GPU publishes no busy time records no series at all, so
// the chart shows a gap rather than a flat zero.
func TestNodeGPUUtilisationIsAbsentWhenNoCardReportsIt(t *testing.T) {
	sys := fakeSys(t, map[string]map[string]string{
		"card0": {"uevent": "DRIVER=i915\n", renderNode: ""},
	})
	gpu := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	reader := scaling.NewNodeReaderWithGPU(
		fakeProc(t, "cpu 100 0 100 800 0 0 0 0 0 0\n", meminfoFixture, "0.5 0.4 0.3 1/100 200\n"),
		gpu)

	if stats := reader.Read(); stats.GPUUtilPercent != nil {
		t.Errorf("aggregate = %v, want absent", *stats.GPUUtilPercent)
	}
}
