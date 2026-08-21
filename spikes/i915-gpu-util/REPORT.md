# REPORT; Spike: Intel GPU utilisation for the node reader

**Date:** _(fill in)_ · **Verdict: PENDING** · **PRD amendments required:** _(decide from the findings)_

> Nothing below is filled in yet. Every `PASS`/`FAIL`/`INFO` line must be copied
> from a real run of `spike-i915` on the node, not written from expectation:
> that is the only property that makes a spike report worth more than the
> reasoning that preceded it. Delete this block when the run is done.

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
| Host | _(the media server; address and role)_ |
| Distro / kernel | _(uname -a)_ |
| Arch | _(x86_64)_ |
| GPU | Intel UHD 630 (Coffee Lake), integrated |
| Driver | _(i915 or xe; from the card's uevent)_ |
| `perf_event_paranoid` | _(cat /proc/sys/kernel/perf_event_paranoid)_ |
| `intel_gpu_top` present | _(yes/no; the external number to agree with)_ |
| Kanea | _(the release running there, if any)_ |
| Result | _(N PASS, N FAIL, N INFO)_ |

## The questions

| | Question | Finding |
|---|---|---|
| A | What does this node's sysfs expose for the GPU? | _pending_ |
| B | Does the i915 perf PMU exist, and where? | _pending_ |
| C | Which engine busy events does it offer? | _pending_ |
| D | Does `perf_event_open` succeed, and as whom? | _pending_ |
| E | Does the counter move under a real transcode? | _pending_ |
| F | What does holding and reading the counters cost? | _pending_ |
| G | Do the numbers agree with `intel_gpu_top`? | _pending_ |

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

## Output, idle

```
(paste verbatim)
```

## Output, under a transcode

```
(paste verbatim)
```

## `intel_gpu_top` for comparison

```
(paste verbatim)
```

## Findings

_(one short section per question, written after the run)_

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

2. **Is the privilege affordable?** If the open needs `CAP_PERFMON`, that is a
   capability added to `kanead` for one chart line. §5.2.6 and the unit files
   are deliberately conservative about what the control plane holds; "a metric
   is not a reason to widen a process's capabilities" is a defensible NO-GO and
   should be written as one if that is where this lands.

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
