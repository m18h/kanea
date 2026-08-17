package scaling

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GPU VRAM from sysfs and nvidia-smi (PRD v1.42).
//
// The reader takes what is already on the node rather than adding a protocol:
// amdgpu publishes VRAM as plain sysfs files, and NVIDIA's only cgo-free
// surface is the nvidia-smi binary; NVML is a C library, which the single
// static binary rules out. Like the procfs reader, nothing here fails: a node
// without a GPU, an unreadable sysfs and a missing nvidia-smi all report
// nothing, and a missing reading is an absence, never a zero (§9.2).

// GPUStats is one GPU's point-in-time reading. The VRAM fields are pointers
// for the NodeStats reason: a card whose driver reports no usage file and a
// card with an empty VRAM are different facts.
type GPUStats struct {
	Name        string   `json:"name"`
	VRAMUsed    *uint64  `json:"vram_used_bytes,omitempty"`
	VRAMTotal   *uint64  `json:"vram_total_bytes,omitempty"`
	VRAMPercent *float64 `json:"vram_percent,omitempty"`
}

// GPUReaderConfig points the reader somewhere other than the real node.
// The zero value is production: /sys, and the real nvidia-smi.
type GPUReaderConfig struct {
	// SysRoot is "/sys" in production and a fixture directory in tests.
	SysRoot string
	// NvidiaSMI overrides the nvidia-smi invocation; tests inject CSV here.
	NvidiaSMI func(ctx context.Context) ([]byte, error)
	Now       func() time.Time
}

// GPUReader reads per-GPU VRAM.
//
// Readings are cached briefly because the NVIDIA half is an exec, not a file
// read: /v1/stats samples on demand, and without the cache a burst of
// requests would fork one nvidia-smi per request.
type GPUReader struct {
	sysRoot string
	nvidia  func(ctx context.Context) ([]byte, error)
	now     func() time.Time

	mu       sync.Mutex
	cached   []GPUStats
	cachedAt time.Time
}

// gpuCacheFor bounds how often the sources are consulted; well under the 5 s
// metrics interval, so the recorder never reads a stale sample twice.
const gpuCacheFor = 2 * time.Second

// nvidiaSMITimeout bounds the exec. A wedged driver can hang nvidia-smi
// indefinitely, and the stats route must not inherit that.
const nvidiaSMITimeout = 2 * time.Second

// NewGPUReader builds a reader over the given sources.
func NewGPUReader(cfg GPUReaderConfig) *GPUReader {
	if cfg.SysRoot == "" {
		cfg.SysRoot = "/sys"
	}
	if cfg.NvidiaSMI == nil {
		cfg.NvidiaSMI = nvidiaSMI
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &GPUReader{sysRoot: cfg.SysRoot, nvidia: cfg.NvidiaSMI, now: cfg.Now}
}

// Read reports every visible GPU, or nothing.
func (r *GPUReader) Read() []GPUStats {
	if runtime.GOOS != "linux" && r.sysRoot == "/sys" {
		// sysfs and the NVIDIA driver are Linux; same posture as NodeReader.
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.cachedAt.IsZero() && r.now().Sub(r.cachedAt) < gpuCacheFor {
		return r.cached
	}
	gpus := append(r.amdgpu(), r.nvidiaGPUs()...)
	r.cached, r.cachedAt = gpus, r.now()
	return gpus
}

// cardDir matches the card nodes under /sys/class/drm. The glob also catches
// connector entries like card0-DP-1, which have no device to read.
var cardDir = regexp.MustCompile(`^card\d+$`)

// amdgpu walks /sys/class/drm for cards whose driver publishes VRAM files.
// An NVIDIA card also appears here but carries no mem_info_vram_*: it is
// skipped and counted once, by nvidia-smi.
func (r *GPUReader) amdgpu() []GPUStats {
	cards, err := filepath.Glob(r.sysRoot + "/class/drm/card*")
	if err != nil {
		return nil
	}
	var out []GPUStats
	for _, card := range cards {
		if !cardDir.MatchString(filepath.Base(card)) {
			continue
		}
		device := card + "/device"
		used, usedOK := readSysUint(device + "/mem_info_vram_used")
		total, totalOK := readSysUint(device + "/mem_info_vram_total")
		if !usedOK && !totalOK {
			continue
		}

		g := GPUStats{Name: filepath.Base(card)}
		if driver := sysDriver(device); driver != "" {
			g.Name += " (" + driver + ")"
		}
		if usedOK {
			g.VRAMUsed = &used
		}
		if totalOK {
			g.VRAMTotal = &total
		}
		if usedOK && totalOK && total > 0 {
			percent := float64(used) / float64(total) * 100
			g.VRAMPercent = &percent
		}
		out = append(out, g)
	}
	return out
}

// readSysUint reads one integer sysfs file. Garbage is an absence, not a zero.
func readSysUint(path string) (uint64, bool) {
	body, err := os.ReadFile(path) // #nosec G304: sysfs, or a test fixture
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// sysDriver reads the DRIVER= line of a device's uevent.
func sysDriver(device string) string {
	body, err := os.ReadFile(device + "/uevent") // #nosec G304: sysfs, or a test fixture
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if driver, found := strings.CutPrefix(line, "DRIVER="); found {
			return strings.TrimSpace(driver)
		}
	}
	return ""
}

// nvidiaGPUs asks nvidia-smi, bounded by its own timeout.
func (r *GPUReader) nvidiaGPUs() []GPUStats {
	ctx, cancel := context.WithTimeout(context.Background(), nvidiaSMITimeout)
	defer cancel()
	body, err := r.nvidia(ctx)
	if err != nil {
		return nil
	}
	return parseNvidiaSMI(body)
}

// nvidiaSMI runs the real binary. LookPath first, so a node without the
// driver pays a path scan, never a fork.
func nvidiaSMI(ctx context.Context) ([]byte, error) {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu=name,memory.used,memory.total",
		"--format=csv,noheader,nounits").Output()
}

// parseNvidiaSMI reads "name, used, total" CSV lines; the memory values are
// MiB under nounits. A value nvidia-smi could not report ("[N/A]") parses to
// nothing, which serves it as the absence it is.
func parseNvidiaSMI(body []byte) []GPUStats {
	var out []GPUStats
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" {
			continue
		}

		g := GPUStats{Name: name}
		if mib, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64); err == nil {
			used := mib * 1024 * 1024
			g.VRAMUsed = &used
		}
		if mib, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 64); err == nil {
			total := mib * 1024 * 1024
			g.VRAMTotal = &total
		}
		if g.VRAMUsed != nil && g.VRAMTotal != nil && *g.VRAMTotal > 0 {
			percent := float64(*g.VRAMUsed) / float64(*g.VRAMTotal) * 100
			g.VRAMPercent = &percent
		}
		out = append(out, g)
	}
	return out
}

// aggregateVRAM is used summed over total, across every GPU reporting both.
// One number rather than per-GPU series: it is what the Overview sparkline
// and the node history read, and a card reporting only half its numbers
// contributes nothing rather than skewing the ratio.
func aggregateVRAM(gpus []GPUStats) *float64 {
	var used, total uint64
	for _, g := range gpus {
		if g.VRAMUsed != nil && g.VRAMTotal != nil {
			used += *g.VRAMUsed
			total += *g.VRAMTotal
		}
	}
	if total == 0 {
		return nil
	}
	percent := float64(used) / float64(total) * 100
	return &percent
}
