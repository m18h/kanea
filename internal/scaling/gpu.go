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
	Name string `json:"name"`
	// UtilPercent is how busy the GPU is, 0-100 (v1.94). It is the first
	// number anybody wants from a GPU - "is the transcode actually using it"
	// is a question about occupancy, not about memory - and it is a pointer
	// for the same reason the VRAM fields are: a driver that does not publish
	// busy time is an absence, and rendering it as 0% would say the card is
	// idle when the truth is that nobody asked it.
	UtilPercent *float64 `json:"util_percent,omitempty"`
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
	gpus := append(r.drmGPUs(), r.nvidiaGPUs()...)
	r.cached, r.cachedAt = gpus, r.now()
	return gpus
}

// cardDir matches the card nodes under /sys/class/drm. The glob also catches
// connector entries like card0-DP-1, which have no device to read.
var cardDir = regexp.MustCompile(`^card\d+$`)

// drmGPUs walks /sys/class/drm and reports every GPU it finds there, with VRAM
// where the driver publishes it.
//
// Two kinds of card come out of this. A card publishing `mem_info_vram_*`
// (amdgpu) is reported with its numbers. A card publishing neither is reported
// with **no VRAM fields at all**, which is why they are pointers: an Intel
// integrated GPU has no VRAM to report, because it has none - it shares system
// memory, which the node's own memory reading already covers - and "this GPU
// exists and its memory is not separately measurable" is a different fact from
// "there is no GPU here". Before v1.91 such a card was skipped entirely, so a
// node whose only GPU was integrated rendered no GPU panel and read as having
// none, which is the §9.2 mistake in the shape it takes when the absent thing
// is the device rather than the number.
//
// Two cards are deliberately *not* reported, and each exclusion earns itself:
//
//   - **A card with no render node.** A server's BMC display adapter (ast,
//     mgag200) is a DRM card and is not a GPU; it cannot run a workload, so
//     calling it one would put a permanent unmeasurable panel on the majority
//     of headless nodes. `device/drm/renderD*` is the kernel's own answer to
//     "can this device compute", which is better than a driver-name allowlist
//     that would need editing for every new driver.
//   - **An NVIDIA card with no VRAM files.** nvidia-smi reports it, with real
//     numbers, and a card counted twice is worse than one counted once. The
//     open `nouveau` driver is *not* excluded: nvidia-smi does not see those,
//     so this path is the only thing that would ever name them.
//
// The render-node check applies only to a card with no VRAM files. Publishing
// VRAM is already proof of being a GPU, and gating an amdgpu card on a second
// signal would risk losing a reading that works today for a tidier rule.
func (r *GPUReader) drmGPUs() []GPUStats {
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
		busy, busyOK := readSysPercent(device + "/gpu_busy_percent")
		driver := sysDriver(device)
		// Any published number is proof of being a GPU; the render-node check
		// is the fallback for a card that publishes none.
		if !usedOK && !totalOK && !busyOK {
			if driver == driverNvidia || !hasRenderNode(device) {
				continue
			}
		}

		g := GPUStats{Name: filepath.Base(card)}
		if driver != "" {
			g.Name += " (" + driver + ")"
		}
		// amdgpu publishes busy time as a plain percentage file, which is the
		// whole reason utilisation costs nothing on that driver. i915 has no
		// equivalent: Intel's busy counters live behind the perf PMU, so an
		// integrated GPU reports its presence and its absence of numbers.
		if busyOK {
			g.UtilPercent = &busy
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

// driverNvidia is the proprietary driver's name in a card's uevent. Its cards
// are reported by nvidia-smi, which has the numbers this path does not.
const driverNvidia = "nvidia"

// hasRenderNode reports whether a DRM device exposes a render node, which is
// the kernel saying the device can be used for rendering or compute rather
// than only for scanning out a display.
func hasRenderNode(device string) bool {
	nodes, err := filepath.Glob(device + "/drm/renderD*")
	return err == nil && len(nodes) > 0
}

// readSysPercent reads a 0-100 sysfs file. A value outside that range is a
// driver this code does not understand, and is an absence rather than a clamp:
// clamping publishes a number nobody measured.
func readSysPercent(path string) (float64, bool) {
	value, ok := readSysUint(path)
	if !ok || value > 100 {
		return 0, false
	}
	return float64(value), true
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
		"--query-gpu=name,utilization.gpu,memory.used,memory.total",
		"--format=csv,noheader,nounits").Output()
}

// parseNvidiaSMI reads "name, util, used, total" CSV lines; the memory values
// are MiB under nounits and the utilisation is a bare percentage. A value
// nvidia-smi could not report ("[N/A]") parses to nothing, which serves it as
// the absence it is.
func parseNvidiaSMI(body []byte) []GPUStats {
	var out []GPUStats
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" {
			continue
		}

		g := GPUStats{Name: name}
		if busy, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64); err == nil && busy <= 100 {
			percent := float64(busy)
			g.UtilPercent = &percent
		}
		if mib, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 64); err == nil {
			used := mib * 1024 * 1024
			g.VRAMUsed = &used
		}
		if mib, err := strconv.ParseUint(strings.TrimSpace(fields[3]), 10, 64); err == nil {
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

// aggregateUtil is the mean busy percentage across every GPU reporting one.
//
// A mean rather than VRAM's used-over-total, because utilisation is already a
// ratio and there is no second quantity to weight it by: two cards at 100% and
// 0% are a node at 50%, whichever is larger. Nil when no card reports busy
// time, so a node whose only GPU is integrated records no series at all rather
// than a flat zero (§9.2).
func aggregateUtil(gpus []GPUStats) *float64 {
	var sum float64
	var n int
	for _, g := range gpus {
		if g.UtilPercent != nil {
			sum += *g.UtilPercent
			n++
		}
	}
	if n == 0 {
		return nil
	}
	mean := sum / float64(n)
	return &mean
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
