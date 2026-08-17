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

// fakeSys builds a sysfs fixture: one directory per /sys/class/drm entry,
// with the given device files inside.
func fakeSys(t *testing.T, cards map[string]map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for card, files := range cards {
		device := filepath.Join(root, "class", "drm", card, "device")
		if err := os.MkdirAll(device, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(device, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

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

func TestGPUCardsWithoutVRAMFilesAreSkipped(t *testing.T) {
	// card0 is an iGPU whose driver publishes no VRAM files; card0-DP-1 is a
	// connector entry the card* glob also matches.
	sys := fakeSys(t, map[string]map[string]string{
		"card0":      {"uevent": "DRIVER=i915\n"},
		"card0-DP-1": {},
	})
	r := scaling.NewGPUReader(scaling.GPUReaderConfig{SysRoot: sys, NvidiaSMI: noNvidia})
	if gpus := r.Read(); len(gpus) != 0 {
		t.Errorf("gpus = %+v, want none", gpus)
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
			return []byte("NVIDIA GeForce RTX 4090, 1024, 24564\nNVIDIA RTX A2000, [N/A], [N/A]\n"), nil
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
	// The second card answered [N/A]: the name is real, the numbers absent.
	if gpus[1].VRAMUsed != nil || gpus[1].VRAMTotal != nil || gpus[1].VRAMPercent != nil {
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
			return []byte("NVIDIA T400, 100, 2048\n"), nil
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
