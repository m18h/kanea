// Command spike-i915 answers whether Kanea can read Intel GPU utilisation.
//
// PRD v1.94 ships utilisation for amdgpu (a sysfs percentage file) and NVIDIA
// (nvidia-smi). Intel publishes neither: its occupancy lives behind the kernel's
// i915 perf PMU, which is a syscall and a privilege rather than a file read.
// This program surveys what the node offers and then actually opens the
// counters and samples them, because the questions that matter here - does the
// open succeed, as whom, and does the number move under load - cannot be
// answered by reading documentation.
//
// It is read-only apart from the perf file descriptors it opens and closes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	duration = flag.Duration("duration", 10*time.Second, "how long to sample the counters")
	sysRoot  = flag.String("sys", "/sys", "sysfs root, for testing this program off a node")
	procRoot = flag.String("proc", "/proc", "procfs root")
)

// result tallies the checks so the summary is not hand-counted.
type result struct{ pass, fail, info int }

var tally result

func pass(check, format string, args ...any) {
	tally.pass++
	fmt.Printf("PASS  %-3s %s\n", check, fmt.Sprintf(format, args...))
}

func fail(check, format string, args ...any) {
	tally.fail++
	fmt.Printf("FAIL  %-3s %s\n", check, fmt.Sprintf(format, args...))
}

func info(check, format string, args ...any) {
	tally.info++
	fmt.Printf("INFO  %-3s %s\n", check, fmt.Sprintf(format, args...))
}

func main() {
	flag.Parse()
	fmt.Printf("spike-i915: Intel GPU utilisation for the node reader\n")
	fmt.Printf("uid=%d  sampling for %s\n\n", os.Getuid(), *duration)

	checkA()
	pmu, engines := checkBC()
	if pmu == 0 {
		fmt.Println("\nNo i915 PMU: checks D-G cannot run. See the report's NO-GO branch.")
		summary()
		return
	}
	fds := checkD(pmu, engines)
	checkE(fds)
	checkF(fds)
	for _, fd := range fds {
		_ = unix.Close(fd.fd)
	}
	summary()
}

func summary() {
	fmt.Printf("\n%d PASS, %d FAIL, %d INFO\n", tally.pass, tally.fail, tally.info)
	if tally.fail > 0 {
		os.Exit(1)
	}
}

// ---- A: what sysfs offers -------------------------------------------------

// checkA surveys every DRM card the way internal/scaling does, so the report
// records whether v1.91's detection finds this GPU at all, and settles whether
// some kernel has quietly grown a cheap busy file after all.
func checkA() {
	cards, _ := filepath.Glob(filepath.Join(*sysRoot, "class/drm/card[0-9]*"))
	sort.Strings(cards)
	if len(cards) == 0 {
		fail("A", "no /sys/class/drm/card* at all: this node has no DRM device")
		return
	}
	for _, card := range cards {
		name := filepath.Base(card)
		if strings.Contains(name, "-") {
			continue // a connector entry (card0-DP-1), not a card
		}
		device := filepath.Join(card, "device")
		driver := readLine(filepath.Join(device, "uevent"), "DRIVER=")
		render, _ := filepath.Glob(filepath.Join(device, "drm/renderD*"))

		fmt.Printf("      --- %s (driver %q) ---\n", name, driver)
		info("A", "%s render node: %v (v1.91 needs one to call this a GPU)", name, len(render) > 0)

		// The cheap paths, in the order the shipping reader tries them.
		for _, f := range []string{
			"gpu_busy_percent",    // amdgpu's, and the one Intel lacks
			"mem_info_vram_used",  // amdgpu
			"mem_info_vram_total", // amdgpu
			"lmem_total_bytes",    // discrete Intel (Arc), not an iGPU
		} {
			if v, ok := readTrimmed(filepath.Join(device, f)); ok {
				pass("A", "%s/%s = %q  (a cheap number exists here)", name, f, v)
			} else {
				info("A", "%s/%s absent", name, f)
			}
		}
		// Frequency is NOT utilisation and must not be reported as it: a GPU
		// can sit at max clock doing nothing, or at min clock saturated on a
		// memory-bound task. Recorded only so the report can say what exists.
		for _, f := range []string{"gt_act_freq_mhz", "gt_cur_freq_mhz", "gt_max_freq_mhz"} {
			if v, ok := readTrimmed(filepath.Join(card, f)); ok {
				info("A", "%s/%s = %q  (clock, NOT occupancy)", name, f, v)
			}
		}
	}
}

// ---- B, C: the PMU and its events -----------------------------------------

type engine struct {
	name   string
	config uint64
}

// checkBC finds the i915 PMU's dynamic type id and the busy events it offers.
func checkBC() (uint32, []engine) {
	base := filepath.Join(*sysRoot, "bus/event_source/devices/i915")
	raw, ok := readTrimmed(filepath.Join(base, "type"))
	if !ok {
		// Newer Intel hardware uses the `xe` driver, whose PMU is named after
		// the card. Worth reporting rather than concluding "no PMU".
		alts, _ := filepath.Glob(filepath.Join(*sysRoot, "bus/event_source/devices/xe*"))
		fail("B", "no i915 PMU at %s (xe PMUs present: %v)", base, alts)
		return 0, nil
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		fail("B", "i915 PMU type %q does not parse: %v", raw, err)
		return 0, nil
	}
	pass("B", "i915 PMU present, type=%d", n)

	if mask, ok := readTrimmed(filepath.Join(base, "cpumask")); ok {
		info("B", "cpumask=%q (a per-PMU counter is opened on one CPU, not every CPU)", mask)
	}

	names, _ := filepath.Glob(filepath.Join(base, "events/*"))
	sort.Strings(names)
	var engines []engine
	var others []string
	for _, path := range names {
		name := filepath.Base(path)
		if strings.HasSuffix(name, ".unit") || strings.HasSuffix(name, ".scale") {
			continue
		}
		body, ok := readTrimmed(path)
		if !ok {
			continue
		}
		if !strings.HasSuffix(name, "-busy") {
			others = append(others, name)
			continue
		}
		config, err := parseConfig(body)
		if err != nil {
			info("C", "event %s: %v", name, err)
			continue
		}
		engines = append(engines, engine{name: name, config: config})
	}
	if len(engines) == 0 {
		fail("C", "the PMU offers no *-busy events; there is nothing to measure")
		return uint32(n), nil
	}
	for _, e := range engines {
		pass("C", "busy event %-16s config=%#x", e.name, e.config)
	}
	// vcs* is video (a transcode); rcs0 is render (a desktop or compute).
	info("C", "other events: %s", strings.Join(others, " "))
	return uint32(n), engines
}

// parseConfig reads sysfs's "config=0x1,foo=2" event description.
func parseConfig(body string) (uint64, error) {
	for _, part := range strings.Split(body, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || key != "config" {
			continue
		}
		return strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 64)
	}
	return 0, fmt.Errorf("no config= in %q", body)
}

// ---- D: the open, and the privilege it needs ------------------------------

type counter struct {
	engine engine
	fd     int
}

// checkD opens one counter per busy event. This is the check the whole feature
// turns on: an EACCES as root would end it, and success only under a permissive
// perf_event_paranoid would make it a node-configuration dependency rather than
// something Kanea can promise.
func checkD(pmu uint32, engines []engine) []counter {
	if p, ok := readTrimmed(filepath.Join(*procRoot, "sys/kernel/perf_event_paranoid")); ok {
		info("D", "perf_event_paranoid=%s (>=2 normally blocks a system-wide open for non-root)", p)
	}

	var out []counter
	for _, e := range engines {
		attr := unix.PerfEventAttr{
			Type:   pmu,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Config: e.config,
		}
		// pid=-1, cpu=0: a system-wide counter on the PMU's CPU. The i915 PMU
		// is uncore-like, so it cannot be opened per-process, which is itself
		// part of the answer - this measures the whole GPU, never one alloc.
		fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, 0)
		if err != nil {
			fail("D", "open %s: %v", e.name, err)
			continue
		}
		pass("D", "opened %s (fd %d)", e.name, fd)
		out = append(out, counter{engine: e, fd: fd})
	}
	if len(out) > 0 {
		info("D", "held file descriptors: %d, one per engine, for the process's life", len(out))
	}
	return out
}

// ---- E: does it move? -----------------------------------------------------

// checkE samples each counter over the flag's duration. The counters report
// busy *nanoseconds*, so a percentage is the delta over the elapsed wall time -
// the same arithmetic the CPU reader already does against procfs.
func checkE(fds []counter) {
	if len(fds) == 0 {
		return
	}
	first := make([]uint64, len(fds))
	for i, c := range fds {
		v, err := readCounter(c.fd)
		if err != nil {
			fail("E", "read %s: %v", c.engine.name, err)
			return
		}
		first[i] = v
	}
	start := time.Now()
	time.Sleep(*duration)
	elapsed := time.Since(start)

	var busiest float64
	var sum float64
	for i, c := range fds {
		v, err := readCounter(c.fd)
		if err != nil {
			fail("E", "read %s: %v", c.engine.name, err)
			return
		}
		percent := float64(v-first[i]) / float64(elapsed.Nanoseconds()) * 100
		sum += percent
		if percent > busiest {
			busiest = percent
		}
		verb := info
		if percent > 0 {
			verb = pass
		}
		verb("E", "%-16s %6.2f%% busy over %s (delta %d ns)",
			c.engine.name, percent, elapsed.Truncate(time.Millisecond), v-first[i])
	}
	info("E", "busiest engine %.2f%%, sum across engines %.2f%%", busiest, sum)
	info("E", "  ^ which of those a node reader should publish is a decision this")
	info("E", "    report has to make: a sum can exceed 100%% on a card whose")
	info("E", "    engines run concurrently, and the busiest is what a transcode")
	info("E", "    actually saturates.")
	if busiest == 0 {
		info("E", "nothing moved. Re-run with a transcode actually in flight:")
		info("E", "  ffmpeg -nostdin -stream_loop -1 -hwaccel vaapi \\")
		info("E", "         -vaapi_device /dev/dri/renderD128 -i IN -f null - >/dev/null 2>&1 &")
		info("E", "  -nostdin matters: a backgrounded ffmpeg reads stdin, takes SIGTTIN")
		info("E", "  from the terminal and suspends before decoding a frame. Check with")
		info("E", "  `jobs`: a job reading \"Stopped\" produced no load at all.")
		info("E", "  -stream_loop -1 matters too: a short sample clip can finish decoding")
		info("E", "  before the sampling window closes.")
	}
}

// ---- F: what it costs -----------------------------------------------------

// checkF times a full read of every counter, which is what the node reader
// would do once per scrape interval.
func checkF(fds []counter) {
	if len(fds) == 0 {
		return
	}
	const rounds = 1000
	start := time.Now()
	for range rounds {
		for _, c := range fds {
			if _, err := readCounter(c.fd); err != nil {
				fail("F", "read: %v", err)
				return
			}
		}
	}
	per := time.Since(start) / rounds
	pass("F", "one full sample of %d counters: %s (the reader does this every 5s)", len(fds), per)
}

func readCounter(fd int) (uint64, error) {
	var buf [8]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, fmt.Errorf("short read: %d bytes", n)
	}
	return *(*uint64)(unsafe.Pointer(&buf[0])), nil
}

// ---- small helpers --------------------------------------------------------

func readTrimmed(path string) (string, bool) {
	body, err := os.ReadFile(path) // #nosec G304: sysfs paths this program built
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(body)), true
}

func readLine(path, prefix string) string {
	body, err := os.ReadFile(path) // #nosec G304: sysfs
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, found := strings.CutPrefix(line, prefix); found {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
