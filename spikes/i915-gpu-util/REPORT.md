# REPORT; Spike: Intel GPU utilisation for the node reader

**Date:** 2026-08-21 · **Verdict: PENDING on check E alone** · **PRD amendments required:** _(decide once E lands)_

> Partial. Checks **A, B, C, D and F ran on the real node** and their lines
> below are copied from that run verbatim. **E did not run**: the `ffmpeg`
> command meant to load the GPU failed to start (no VA-API driver), so the
> counters were sampled against an idle GPU and read zero, which proves
> nothing either way. **G** was not attempted. The verdict waits on E.

## Why this spike exists

PRD v1.94 ships GPU utilisation as the first number the node reader publishes,
because *is the GPU actually being used* is the question an operator opens the
page with. It arrives free on the two drivers that publish it as a plain value:
**amdgpu** writes `gpu_busy_percent` into sysfs beside the VRAM files the reader
already reads, and **`nvidia-smi`** answers `utilization.gpu` in the query the
reader already runs.

**Intel publishes neither.** `i915` exposes no busy counter in sysfs at all; its
occupancy lives behind the kernel's perf PMU. So an integrated GPU currently
reports its presence and its name and no numbers, which is honest (§9.2: absent,
never zero) and unsatisfying on a node whose whole job is hardware transcoding.

Closing that gap is not a field to read. It is `perf_event_open(2)`, a file
descriptor held per engine for the process's life, and a privilege
(`CAP_PERFMON`, or a `perf_event_paranoid` low enough to permit a system-wide
open). Each of those is a real cost inside a control plane, and none of them can
be judged anywhere but on the hardware. Hence a spike, and hence a spike that
can return **NO-GO** as a real answer.

## Environment

| | Node |
|---|---|
| Host | the media server (`media`) |
| Distro | Debian 12 (ffmpeg 5.1.9-0+deb12u1) |
| Arch | x86_64 |
| GPU | Intel UHD 630 (Coffee Lake), integrated |
| Driver | `i915`, render node present (`/dev/dri/renderD128`) |
| `perf_event_paranoid` | **3** (Debian's hardened setting: no unprivileged use at all) |
| VA-API | **not working**: `No VA display found for device /dev/dri/renderD128` |
| Result (partial) | **10 PASS, 0 FAIL, 23 INFO** |

## The questions

| | Question | Finding |
|---|---|---|
| A | What does this node's sysfs expose for the GPU? | **PASS.** `card0`, driver `i915`, render node present, so v1.91's detection finds it. No `gpu_busy_percent`, no `mem_info_vram_*`, no `lmem_total_bytes`: the PRD's claim that Intel publishes nothing cheap is confirmed on the hardware |
| B | Does the i915 perf PMU exist, and where? | **PASS.** Present, `type=19`, `cpumask=0` |
| C | Which engine busy events does it offer? | **PASS.** Four: `rcs0` (render), `bcs0` (blitter), `vcs0` (video), `vecs0` (video enhance). A transcode is `vcs0`'s |
| D | Does `perf_event_open` succeed, and as whom? | **PASS, and better than hoped.** All four opened as root under `perf_event_paranoid=3`, Debian's most restrictive setting. See "The privilege question is already answered" below |
| E | Does the counter move under a real transcode? | **NOT RUN.** `ffmpeg` failed to start; the sample covered an idle GPU |
| F | What does holding and reading the counters cost? | **PASS.** 4 file descriptors held, and **9.742µs** for one full sample of all four. The reader would do that once per 5s scrape |
| G | Do the numbers agree with `intel_gpu_top`? | Not attempted |

## How it was run

```sh
# On the node:
cd spikes/i915-gpu-util
go build -o spike-i915 .

sudo ./spike-i915 -duration 10s                    # idle
# ...then with the GPU working:
ffmpeg -hwaccel vaapi -vaapi_device /dev/dri/renderD128 -i IN -f null - &
sudo ./spike-i915 -duration 10s                    # under load
sudo intel_gpu_top -l -s 1000 | head -20           # for check G
```

## Output (GPU idle; the intended load never started)

```
spike-i915: Intel GPU utilisation for the node reader
uid=0  sampling for 10s

      --- card0 (driver "i915") ---
INFO  A   card0 render node: true (v1.91 needs one to call this a GPU)
INFO  A   card0/gpu_busy_percent absent
INFO  A   card0/mem_info_vram_used absent
INFO  A   card0/mem_info_vram_total absent
INFO  A   card0/lmem_total_bytes absent
INFO  A   card0/gt_act_freq_mhz = "0"  (clock, NOT occupancy)
INFO  A   card0/gt_cur_freq_mhz = "1067"  (clock, NOT occupancy)
INFO  A   card0/gt_max_freq_mhz = "1100"  (clock, NOT occupancy)
PASS  B   i915 PMU present, type=19
INFO  B   cpumask="0" (a per-PMU counter is opened on one CPU, not every CPU)
PASS  C   busy event bcs0-busy        config=0x1000
PASS  C   busy event rcs0-busy        config=0x0
PASS  C   busy event vcs0-busy        config=0x2000
PASS  C   busy event vecs0-busy       config=0x3000
INFO  C   other events: actual-frequency bcs0-sema bcs0-wait interrupts rc6-residency
          rcs0-sema rcs0-wait requested-frequency software-gt-awake-time vcs0-sema
          vcs0-wait vecs0-sema vecs0-wait
INFO  D   perf_event_paranoid=3 (>=2 normally blocks a system-wide open for non-root)
PASS  D   opened bcs0-busy (fd 4)
PASS  D   opened rcs0-busy (fd 7)
PASS  D   opened vcs0-busy (fd 8)
PASS  D   opened vecs0-busy (fd 9)
INFO  D   held file descriptors: 4, one per engine, for the process's life
INFO  E   bcs0-busy          0.00% busy over 10.009s (delta 0 ns)
INFO  E   rcs0-busy          0.00% busy over 10.009s (delta 0 ns)
INFO  E   vcs0-busy          0.00% busy over 10.009s (delta 0 ns)
INFO  E   vecs0-busy         0.00% busy over 10.009s (delta 0 ns)
INFO  E   busiest engine 0.00%, sum across engines 0.00%
PASS  F   one full sample of 4 counters: 9.742µs (the reader does this every 5s)

10 PASS, 0 FAIL, 23 INFO
```

The load that was supposed to run alongside it did not:

```
[AVHWDeviceContext @ 0x...] No VA display found for device /dev/dri/renderD128.
Device creation failed: -22.
```

`/dev/dri/renderD128` exists. VA-API itself is not working on this node, which
is a property of the node rather than of this spike, and is what check E is
blocked on.

## Output, under a transcode

```
(pending: re-run once VA-API works)
```

## `intel_gpu_top` for comparison

```
(pending)
```

## Findings so far

### The privilege question is already answered, and the answer is yes

This was the objection most likely to end the feature: if the PMU needed
`CAP_PERFMON` added to `kanead`, that is a capability granted to the control
plane for one chart line, and §5.2.6's conservatism about what that process
holds would have been a fair reason to refuse.

It does not need one. `perf_event_paranoid` is **3** on this node - Debian's
hardened extension, stricter than upstream's maximum of 2, meaning no
unprivileged use at all - and all four counters opened anyway, because the
process was root. `kanead` **already runs as root with no
`CapabilityBoundingSet`**: `cmd/kanea/units.go` puts a bounding set only on the
edge unit, which is the one with a dedicated user. So the open would succeed
today, with no unit change, no capability grant and no node configuration.

### The cost is not a consideration

9.742µs for a full sample of four counters, against a 5-second scrape interval.
Four file descriptors held for the process's life. Neither is a number that
needs weighing.

### Frequency is not occupancy, demonstrated rather than argued

The idle sample read `gt_act_freq_mhz = 0` beside `gt_cur_freq_mhz = 1067`. A
reader that had taken the cheap path and published the current clock would have
reported this GPU as running at 97% of its maximum while it was doing nothing
at all.

### What is left

Only that the counters move. Everything else about the mechanism is confirmed;
check E is blocked on the node's VA-API, not on anything Kanea does.

## Decisions this report has to make

These are open by construction: the spike produces the numbers, and the report
is where the call gets made. Each one is a design decision, not a measurement.

1. **Which number does a node publish?** The counters are per engine. A
   transcode saturates `vcs*` while `rcs0` idles, so a **mean across engines**
   would report a busy GPU as mostly idle, while a **sum** can exceed 100% on
   hardware whose engines run concurrently. The *busiest engine* is the
   candidate that matches what somebody means by "the GPU is busy", and it
   needs saying out loud because it disagrees with how `node_gpu_util_percent`
   currently aggregates across *cards* (a mean, v1.94).

2. ~~**Is the privilege affordable?**~~ **Answered: no privilege is needed.**
   `perf_event_paranoid=3` did not block a root open, and `kanead` already runs
   as root with no `CapabilityBoundingSet`. This was the likeliest NO-GO and it
   is closed.

3. **What happens on a node where it fails?** Whatever the answer, the reader
   must degrade to today's behaviour - a named card with no number - rather
   than logging per scrape or failing a start. A GPU counter is not worth a
   noisy log, let alone a daemon that will not run.

4. **Is it per node or per alloc?** The i915 PMU is uncore-like and cannot be
   opened per process, so this measures the whole GPU and can never be
   attributed to one alloc. That closes the door on a per-service GPU metric
   and on a `scaling` rule driven by GPU load, and both absences belong in the
   PRD rather than being discovered later by someone asking for them.

## Verdict

_pending_

**If GO:** a `GPUReader` branch that discovers the PMU once, holds one fd per
engine and turns a delta of busy-nanoseconds over elapsed wall time into a
percentage - the same shape the CPU reader already has against procfs, reported
through the existing `GPUStats.UtilPercent` with no API change and no new field.

**If NO-GO:** the PRD's current sentence stands and gains its reason. Intel
integrated GPUs report presence and VRAM-less absence, and the report is the
citation for why, so the next person to ask finds an answer instead of a gap.
