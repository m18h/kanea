# REPORT; Spike: Intel GPU utilisation for the node reader

**Date:** 2026-08-21 · **Verdict: GO (7/7)** · **PRD amendments required:** one, for the aggregate rule

> Every `PASS`/`INFO` line below is copied from a real run on the media server,
> not written from expectation. Two earlier attempts produced flat zeros
> because the load never ran: a backgrounded `ffmpeg` reads stdin, takes
> `SIGTTIN` from the terminal and suspends after printing its banner. `jobs`
> reading **Stopped** is the only symptom. `-nostdin` is in the harness's own
> instructions now.

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
| E | Does the counter move under a real transcode? | **PASS.** `vcs0-busy` read **70.82%** over 10.008s (7.088s of busy time) while `rcs0`, `bcs0` and `vecs0` all stayed at exactly 0.00% |
| F | What does holding and reading the counters cost? | **PASS.** 4 file descriptors held, and **3.8-9.7µs** for one full sample of all four across runs. The reader would do that once per 5s scrape |
| G | Do the numbers agree with `intel_gpu_top`? | **PASS.** `intel_gpu_top` VCS/0 over the following window: 18 samples, mean **71.17%**, range 63.20-78.25%. The spike said 70.82%. **0.35 percentage points apart**, across adjacent windows |

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

HEVC Main10 decode of an HDR10 sample, looped, VA-API through `/dev/dri/renderD128`.
Only the lines that differ from the idle run:

```
INFO  A   card0/gt_act_freq_mhz = "350"  (clock, NOT occupancy)
INFO  A   card0/gt_cur_freq_mhz = "350"  (clock, NOT occupancy)
INFO  A   card0/gt_max_freq_mhz = "1100" (clock, NOT occupancy)
INFO  E   bcs0-busy          0.00% busy over 10.008s (delta 0 ns)
INFO  E   rcs0-busy          0.00% busy over 10.008s (delta 0 ns)
PASS  E   vcs0-busy         70.82% busy over 10.008s (delta 7088293225 ns)
INFO  E   vecs0-busy         0.00% busy over 10.008s (delta 0 ns)
INFO  E   busiest engine 70.82%, sum across engines 70.82%
PASS  F   one full sample of 4 counters: 3.831µs (the reader does this every 5s)

11 PASS, 0 FAIL, 20 INFO
```

## `intel_gpu_top` for comparison

```
 Freq MHz      IRQ RC6     Power W     IMC MiB/s      RCS/0     BCS/0     VCS/0    VECS/0
 req  act       /s   %   gpu   pkg     rd     wr          %         %         %         %
 268  268       54  33  0.36 15.65   7665   4934       0.00      0.00     64.36      0.00
 363  363       97  30  0.40 10.73   6863   5071       0.00      0.00     67.03      0.00
 361  361       96  28  0.39 10.66   6831   5064       0.00      0.00     68.97      0.00
 363  363       95  29  0.38 11.08   6972   5074       0.00      0.00     68.20      0.00
 355  354      108  33  0.34 10.48   6684   5187       0.00      0.00     63.20      0.00
 365  365       98  27  0.38 10.65   6837   5106       0.00      0.00     69.76      0.00
 397  397       91  21  0.43 10.79   7172   4892       0.00      0.00     76.12      0.00
 385  385       91  19  0.44 10.86   7065   4908       0.00      0.00     78.25      0.00
 411  411       96  21  0.46 10.88   7099   4895       0.00      0.00     76.51      0.00
 416  417       89  21  0.47 10.94   7175   4926       0.00      0.00     76.39      0.00
 418  418       93  23  0.44 10.71   7073   4991       0.00      0.00     73.93      0.00
 405  405       95  24  0.44 10.83   7047   4971       0.00      0.00     73.22      0.00
 366  366       99  29  0.39 10.54   6935   5072       0.00      0.00     68.09      0.00
 368  368      103  28  0.39 11.20   7023   4988       0.00      0.00     68.60      0.00
 378  377       96  25  0.42 10.59   7253   4891       0.00      0.00     71.92      0.00
 386  386       96  25  0.41 10.73   6993   5002       0.00      0.00     71.23      0.00
 384  384       92  22  0.43 10.76   7093   5003       0.00      0.00     75.20      0.00
 368  368      105  26  0.39 10.82   6833   5083       0.00      0.00     70.03      0.00
```

mean 71.17%, range 63.20-78.25%. The spike measured 70.82% over the window
immediately before. The two disagree by **0.35 percentage points**, which for
independent windows over a live workload is agreement.

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

### The counters are right, not merely non-zero

`vcs0` at 70.82% while every other engine sat at **exactly** 0.00% is the shape
a transcode should produce: HEVC decode runs on the video engine and touches
neither render nor blitter. And `intel_gpu_top`, which reads the same PMU
through its own code, agreed to 0.35 percentage points over the next window.

### The frequency shortcut would have been worse than useless

Not merely imprecise - **inverted**. Idle, the card read `gt_cur_freq_mhz` of
1067 against a maximum of 1100. Busy at 70.82%, it read 350.

| | real occupancy | `gt_cur_freq_mhz` / max |
|---|---|---|
| idle | 0% | **97%** |
| decoding | **70.8%** | 32% |

Video decode runs on the VCS engine and does not drive the render clock, so the
GT frequency falls while the GPU is at its busiest. A reader that had taken the
cheap path would have drawn a chart that was not just wrong but backwards.

## Decisions this report has to make

These are open by construction: the spike produces the numbers, and the report
is where the call gets made. Each one is a design decision, not a measurement.

1. **Which number does a node publish? The busiest engine.** Decided by the
   measurement rather than by argument: `vcs0` at 70.82% with three engines at
   exactly zero means a **mean across engines** would have published **17.7%**
   for a GPU that was three-quarters saturated, and `intel_gpu_top` - which is
   what anybody would check it against - shows 71%. A **sum** is wrong in the
   other direction and can exceed 100% on hardware whose engines run
   concurrently. This does *not* contradict `node_gpu_util_percent` being a
   mean across **cards** (v1.94): busiest-engine is how one card's utilisation
   is derived, and the mean is how several cards combine. Worth stating in the
   PRD so the two rules are not read as one inconsistent rule.

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

**GO (7/7).** Every objection this spike existed to test came back clear:

- The PMU exists, offers per-engine busy counters, and opens.
- **No privilege is needed.** `perf_event_paranoid=3` did not block a root
  open, and `kanead` already runs as root with no `CapabilityBoundingSet`.
- The cost is 3.8-9.7µs per sample against a 5-second scrape, and four file
  descriptors.
- The number is correct, agreeing with `intel_gpu_top` to 0.35 points.

**What to build:** a `GPUReader` branch that discovers the PMU type once, opens
one counter per `*-busy` event, and turns a delta of busy-nanoseconds over
elapsed wall time into a percentage - the same shape `NodeReader.cpu()` already
has against procfs. It reports through the existing `GPUStats.UtilPercent`, so
there is **no API change, no new field and no dashboard change**: v1.94 already
draws utilisation first, and Intel cards simply stop rendering a dash.

Four things the implementation must get right, each of them a finding above:

1. **Publish the busiest engine**, not the mean or the sum of them.
2. **Degrade to today's behaviour** on any failure - a named card with no
   number - and do it without logging per scrape. This runs every five seconds
   forever; a GPU counter is not worth a log line, let alone a failed start.
3. **Hold the descriptors**, do not reopen per scrape. The delta needs a stable
   counter, and reopening would also make the syscall cost per-sample rather
   than per-process.
4. **Sample the delta the way the CPU reader does.** `NodeReader.cpu()` swaps
   its baseline on every call, and v1.79 records what went wrong when two
   callers shared one instance: a reading of the wrong interval, which is worse
   than a gap because nothing about it looks wrong. The same trap applies here.

**Out of scope, and now confirmed rather than assumed:** the i915 PMU is
uncore-like and cannot be opened per process, so this measures the whole GPU
and can never be attributed to one alloc. That closes the door on a per-service
GPU metric and on a `scaling` rule driven by GPU load. Both belong in the PRD
as stated absences rather than being rediscovered by the next person who asks.
