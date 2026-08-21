//go:build linux

package scaling

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Intel GPU occupancy, from the kernel's i915 perf PMU (PRD v1.96, spike 7).
//
// Unlike amdgpu, which writes `gpu_busy_percent` into sysfs as a plain number,
// Intel publishes no busy counter there at all: the only occupancy the kernel
// offers for an i915 device comes through perf_event_open(2). The spike
// established what that costs on real hardware, which is the reason this is
// built rather than refused:
//
//   - **No privilege beyond what kanead already has.** A root open succeeded
//     under `perf_event_paranoid = 3`, Debian's hardened setting and stricter
//     than upstream's maximum. kanead runs as root with no
//     CapabilityBoundingSet (cmd/kanea/units.go puts one only on the edge unit,
//     which has a dedicated user), so nothing about the unit changes.
//   - **About 4µs** for a full sample of four counters, against a 5s scrape.
//   - **Four file descriptors**, held for the process's life.
//
// The descriptors are deliberately never closed. There is one GPUReader per
// daemon, built at startup by NewNodeReader and read until the process exits;
// four fds that die with it are not a leak, and a Close nobody could sensibly
// call would be API surface for its own sake.

// i915Sampler holds one open PMU counter per engine.
type i915Sampler struct {
	fds map[string]int
}

// openI915Sampler discovers the i915 PMU and opens a counter per busy engine.
//
// It answers nil for every node that has no such PMU - no Intel GPU, a kernel
// that does not expose it, the `xe` driver rather than `i915` - and nil is not
// a failure to report: the caller renders no utilisation, which is the same
// absence the card had before this existed. Nothing here logs, because it runs
// once and its silence is a supported state.
func openI915Sampler(sysRoot string) EngineBusyReader {
	base := filepath.Join(sysRoot, "bus/event_source/devices/i915")
	raw, err := os.ReadFile(filepath.Join(base, "type")) // #nosec G304: sysfs
	if err != nil {
		return nil
	}
	pmu, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return nil
	}

	// Only the *-busy events. The PMU also offers frequency, interrupts, rc6
	// residency and per-engine sema/wait counters; none of them is occupancy,
	// and the frequency ones are actively misleading (spike 7 measured the
	// clock at 97% of maximum while the GPU was idle and 32% while it was
	// 70.8% busy, because video decode does not drive the render clock).
	events, _ := filepath.Glob(filepath.Join(base, "events/*-busy"))
	fds := make(map[string]int, len(events))
	for _, path := range events {
		config, ok := i915EventConfig(path)
		if !ok {
			continue
		}
		attr := unix.PerfEventAttr{
			Type:   uint32(pmu),
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Config: config,
		}
		// pid -1, cpu 0: system-wide on the PMU's own CPU. The i915 PMU is
		// uncore-like and *cannot* be opened per process, which is why this is
		// a node metric and can never be attributed to one alloc - the reason
		// there is no per-service GPU number and no GPU-driven scaling rule.
		fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, 0)
		if err != nil {
			continue
		}
		fds[strings.TrimSuffix(filepath.Base(path), "-busy")] = fd
	}
	if len(fds) == 0 {
		return nil
	}
	return &i915Sampler{fds: fds}
}

// i915EventConfig reads the `config=0x2000` an event's sysfs file describes
// itself with.
func i915EventConfig(path string) (uint64, bool) {
	body, err := os.ReadFile(path) // #nosec G304: sysfs
	if err != nil {
		return 0, false
	}
	for _, part := range strings.Split(strings.TrimSpace(string(body)), ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || key != "config" {
			continue
		}
		config, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 64)
		if err != nil {
			return 0, false
		}
		return config, true
	}
	return 0, false
}

// Busy reads every counter. The values are cumulative busy nanoseconds since
// the counter was opened, so a caller differences two readings.
func (s *i915Sampler) Busy() (map[string]uint64, error) {
	out := make(map[string]uint64, len(s.fds))
	for engine, fd := range s.fds {
		var buf [8]byte
		n, err := unix.Read(fd, buf[:])
		if err != nil {
			return nil, fmt.Errorf("scaling: read i915 %s counter: %w", engine, err)
		}
		if n != len(buf) {
			return nil, fmt.Errorf("scaling: short read on i915 %s counter: %d bytes", engine, n)
		}
		out[engine] = binary.NativeEndian.Uint64(buf[:])
	}
	return out, nil
}

// Close releases the counters. Production never calls it (see the file
// comment); it exists so a test can hold a real sampler without leaking.
func (s *i915Sampler) Close() error {
	for _, fd := range s.fds {
		_ = unix.Close(fd)
	}
	s.fds = nil
	return nil
}
