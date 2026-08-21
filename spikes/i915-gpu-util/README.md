# Spike: Intel GPU utilisation for the node reader

PRD v1.94 ships GPU utilisation for the two drivers that publish it as a plain
number: amdgpu's `gpu_busy_percent` and `nvidia-smi`'s `utilization.gpu`. Intel
publishes neither, so an integrated GPU reports its name and a dash.

This spike answers whether that can change, and at what price. Intel's
occupancy lives behind the kernel's **i915 perf PMU**, which means
`perf_event_open(2)` rather than a file read - a syscall, a held file
descriptor per engine, and a privilege (`CAP_PERFMON`, or a permissive
`perf_event_paranoid`). None of that is obviously affordable inside a control
plane, and none of it can be judged from a laptop. Hence a spike.

## Running it

On the node with the Intel GPU:

```sh
cd spikes/i915-gpu-util
go build -o spike-i915 .

# Read-only survey plus a 10s sample. Run it twice: once idle, once with a
# transcode in flight, because a counter that never moves is indistinguishable
# from one that is not wired up.
sudo ./spike-i915 -duration 10s

# Then, in another shell, put the GPU to work and run it again:
#   ffmpeg -hwaccel vaapi -vaapi_device /dev/dri/renderD128 \
#          -i some-input.mkv -f null -
sudo ./spike-i915 -duration 10s
```

It writes a `PASS`/`FAIL`/`INFO` line per check and a summary. Paste the whole
output into `REPORT.md` verbatim: the report's value is that nothing in it was
fabricated.

Also worth capturing beside it, if the tools are present:

```sh
sudo intel_gpu_top -l -s 1000 | head -20   # the number to agree with
cat /proc/sys/kernel/perf_event_paranoid   # the privilege question, in one file
```

## Checks

| | Question | Why it gates the feature |
|---|---|---|
| A | What does this node's sysfs expose for the GPU? | Confirms v1.91's detection works here, and settles whether any cheap busy file exists on this kernel after all |
| B | Does the i915 perf PMU exist, and where? | No PMU, no feature: everything below is moot |
| C | Which engine events does it offer? | A transcode is `vcs*` (video); a desktop is `rcs0` (render). The aggregate has to know which engines exist |
| D | Does `perf_event_open` succeed, as whom? | The privilege question. An `EACCES` as root would end the feature; success only at `paranoid <= 0` makes it a node-configuration dependency rather than a capability |
| E | Does the counter move under load? | A counter that reads zero during a transcode is worse than no counter |
| F | What does it cost to hold and read? | One fd per engine per CPU, read every scrape. The node reader must not become a fd-holder or a syscall storm |
| G | Do the numbers agree with `intel_gpu_top`? | The only external check that the arithmetic is right |

## What a GO would mean

A `GPUReader` branch that discovers the PMU once, holds one fd per engine, and
turns a delta of busy-nanoseconds over elapsed-nanoseconds into a percentage -
the same shape the CPU reader already has, and reported through the existing
`GPUStats.UtilPercent` with no API change. A NO-GO is also a real answer, and
the honest one to write into the PRD beside the sentence that currently says
Intel publishes nothing.
