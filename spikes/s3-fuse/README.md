# Spike ③: S3 FUSE driver choice

Throwaway M0 validation code (PRD §20). **Nothing here ships.** M2 implements the
chosen driver behind the `storage "s3"` volume type (PRD §8).

## Questions this spike answers

1. **Semantics**: what can a workload actually do on the mount? (append, write at
   offset, rename, truncate, symlink, chmod: the drivers differ a lot)
2. **Performance**: sequential throughput and metadata cost, and **when a write
   actually becomes durable** in the bucket
3. **Container volume**: can the mount be handed to a containerd alloc, and does the
   alloc see writes that happen after it starts?
4. **Reliability**: when the object store disappears, does the mount fail or hang,
   and does it recover?

Verdict and the driver recommendation: **[`REPORT.md`](./REPORT.md)**.

## Candidates

| Driver | Version | Note |
|---|---|---|
| s3fs | 1.93 (apt) | the FUSE veteran, most POSIX-complete |
| rclone mount | 1.74.4 (upstream .deb) | VFS cache modes, defers uploads |
| mountpoint-s3 | 1.23.0 (AWS .deb) | **substituted for goofys** |
| ~~goofys~~ |-| **not tested:** last release v0.24.0 (Apr 2020), amd64-only asset: cannot run on Kanea's arm64 target |

The S3 endpoint is a **local MinIO** (`127.0.0.1:9000`), so no cloud credentials are
needed and the results are reproducible offline. Loopback has no round-trip cost, so
the `perf` phase can add one with `tc netem`: see below.

## How to run (on the `kanea-spike` OrbStack VM, Ubuntu 24.04 arm64)

Requires spike ②'s VM (containerd) for the container-volume phase.

```sh
# one-time, inside the VM: MinIO + the three drivers + bucket + credentials
orb -m kanea-spike bash /Users/michael/Projects/kanea/spikes/s3-fuse/provision-vm.sh

# on macOS: cross-build (no Go toolchain in the VM; /Users is shared into it)
cd spikes/s3-fuse
GOOS=linux GOARCH=arm64 go build -o spike-linux .

# in the VM (root needed for mounts, containerd and systemctl)
cd /Users/michael/Projects/kanea/spikes/s3-fuse
sudo ./spike-linux all           # every phase, every driver
sudo ./spike-linux matrix        # POSIX semantics table
sudo ./spike-linux perf          # throughput + metadata, zero-latency store
sudo ./spike-linux perf 15ms     # same, with +15ms one-way on loopback (~30ms RTT)
sudo ./spike-linux container     # mount as a containerd volume
sudo ./spike-linux failure       # stop MinIO mid-flight, measure blocking + recovery
sudo ./spike-linux clean         # unmount everything, restart MinIO, empty the bucket
```

`perf <delay>` shapes **all** loopback traffic for the duration of the run and removes
the qdisc afterwards. `failure` stops and restarts the MinIO unit; `clean` always
restarts it.

## What the code is

| File | Role |
|---|---|
| `provision-vm.sh` | MinIO + s3fs + rclone + mount-s3 + bucket/credentials |
| `main.go` | subcommands, driver loop, PASS/FAIL + capability matrix |
| `drivers.go` | the three mount command lines, mount/unmount, `mc` helper |
| `matrix.go` | POSIX semantics probes |
| `perf.go` | throughput, metadata, time-to-durable |
| `container.go` | rbind the mount into a containerd task |
| `failure.go` | object-store outage and recovery |
| `clean.go` | idempotent reset (also the way out of a wedged mount) |
