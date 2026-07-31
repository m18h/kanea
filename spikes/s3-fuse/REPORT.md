# REPORT — Spike ③: S3 FUSE driver choice

**Date:** 2026-07-30 · **Verdict: GO for `storage "s3"` volumes — with `mountpoint-s3` as the default (read-only) driver and `s3fs` as the opt-in read-write driver. `goofys` is dropped; `rclone mount` is rejected as a built-in default.** · **PRD amendments required: yes (§8, §21 — see the last section)**

The headline is not throughput. All three drivers move bulk data acceptably. What
separates them is **semantics** (what a workload may do on the mount), **durability**
(when a write is actually in the bucket), and **behaviour during an outage** — and on
those three axes they are not interchangeable.

## Environment

| | |
|---|---|
| Host | OrbStack VM `kanea-spike` (Ubuntu 24.04, arm64), 18 vCPU / 8 GiB |
| Object store | MinIO `RELEASE.2025-09-07T16-13-09Z`, single node, `127.0.0.1:9000` |
| Drivers | s3fs **1.93** · rclone **1.74.4** (`rclone mount`) · mountpoint-s3 **1.23.0** |
| Container runtime | containerd 2.3.3 (spike ②) for the volume phase |

Provision: `provision-vm.sh`. Reproduce: `README.md`. Full suite: **45/48 PASS**
(`spike all`) — the three failures are the outage findings in Q5, not defects in the
harness; plus `spike unpriv` 9/9 and `spike perf 15ms` for the shaped numbers.

**goofys was not tested and is dropped from the candidate list.** Its last release is
**v0.24.0 (April 2020)** and the release carries a single amd64 binary — there is no
arm64 build, and Kanea targets `linux amd64/arm64` (PRD §21). An unmaintained,
architecture-incomplete dependency cannot sit behind Kanea's CVE release gates
(AGENTS.md #7). **AWS `mountpoint-s3`** takes its place as the "fast, read-mostly"
candidate.

**On the numbers:** the store is on loopback, so raw MiB/s reflects *driver overhead*,
not S3. To get a decision-relevant picture the `perf` phase can shape loopback with
`tc netem`; results are reported both at zero latency and at **+15 ms one-way (~30 ms
RTT)**, which is what a same-region S3 feels like. Under shaping, sequential-throughput
numbers are pessimistic for every driver (netem delays every packet and defeats the
parallel range requests mountpoint-s3 is built around) — read the shaped run as a
**per-operation round-trip sensitivity test**, which is exactly what metadata cost is.

---

## Q1 — POSIX semantics: **the drivers are not interchangeable**

`spike matrix`, capability table as printed:

| operation | s3fs | rclone | mount-s3 |
|---|---|---|---|
| mkdir | yes | yes | yes |
| write + read back | yes | yes | yes |
| stat size | yes | yes | yes |
| **append** | yes | yes | **NO** (`EPERM`) |
| **write at offset** | yes | yes | **NO** (`EPERM`) |
| **truncate** | **NO** (silent!) | **NO** (`EIO`) | **NO** (`EPERM`) |
| rename | yes | yes | yes |
| symlink | yes | **NO** (`EIO`) | **NO** (`EPERM`) |
| chmod | yes | yes | **NO** (`EPERM`) |
| delete | yes | yes | yes |
| sees another writer's object | yes (immediate) | yes (~5 s, `--dir-cache-time`) | yes (immediate) |

Two findings matter more than the rest:

- **s3fs silently ignores `truncate`.** `truncate(2)` returns success and the file size
  does not change (measured: still 262 152 bytes after truncating to 4 096). A failure
  that reports success is worse than `EPERM`: a workload that truncates a log or a state
  file believes it worked. Kanea must document this, and anything Kanea itself writes to
  an S3 volume must never rely on truncate.
- **mountpoint-s3 is deliberately not a POSIX filesystem.** No append, no writes at an
  offset, no chmod, no symlink — it supports sequential create-and-write of new objects
  plus reads. That is fine for media, static assets and backup targets, and fatal for a
  database or anything that rewrites files in place.

## Q2 — Throughput, metadata cost and durability

`spike perf` (zero-latency, local MinIO):

| | s3fs | rclone | mount-s3 |
|---|---|---|---|
| sequential write 128 MiB | 307 MiB/s | 741 MiB/s | 665 MiB/s |
| **durable in bucket after `close()`** | **yes (+29 ms)** | **NO — +5.8 s** | **yes (+24 ms)** |
| sequential read 128 MiB (fresh mount) | 1049 MiB/s | 907 MiB/s | 702 MiB/s |
| create 200 × 4 KiB | 1.11 s (5.5 ms/file) | 0.10 s (0.5 ms/file) | 1.75 s (8.8 ms/file) |
| list 200 entries | 40 ms | ~0 ms | 6 ms |
| stat 200 files | 0.05 ms/stat | 0.06 ms/stat | ~0 ms/stat |
| delete 200 files | 176 ms | 27 ms | 292 ms |

`spike perf 15ms` (+15 ms one-way on loopback, ~30 ms RTT):

| | s3fs | rclone | mount-s3 |
|---|---|---|---|
| sequential write 128 MiB | 112 MiB/s | 447 MiB/s¹ | 222 MiB/s |
| durable after `close()` | yes (+153 ms) | **NO — +6.7 s** | yes (+156 ms) |
| sequential read 128 MiB | 15.9 MiB/s | 458 MiB/s¹ | 17.5 MiB/s |
| create 200 × 4 KiB | **28.1 s** (140 ms/file) | 0.12 s (0.6 ms/file)¹ | **39.9 s** (199 ms/file) |
| list 200 entries | 435 ms | ~0 ms¹ | 56 ms |
| delete 200 files | 7.0 s | 19 ms¹ | 22.8 s |

¹ rclone's numbers are *not comparable*: with `--vfs-cache-mode writes` its cache
directory survives a remount, so reads and metadata are served locally and uploads are
deferred. That is why it looks 100× faster and why its data is not yet in the bucket.

**The durability result is the important one.** rclone reports `close()` success and
uploads ~6 seconds later. Kanea stops allocs routinely — scale-down, rolling deploy,
drain — so a workload that writes a file and exits can have its data discarded with the
alloc. s3fs and mountpoint-s3 both upload synchronously in `close()`.

The metadata numbers say the obvious thing loudly: an S3 volume costs one round trip
per file operation. 200 small files take **28–40 seconds** to create at 30 ms RTT.
PRD §8's "not for latency-sensitive data" is right and should be stated as
"not for many-small-files workloads" too.

## Q3 — As a container volume: **GO for all three**

`spike container` (12/12 PASS). For each driver: mount established on the host, then
`rbind`-ed into a containerd task at `/data`.

```
PASS  <driver>: alloc starts with the FUSE mount rbind-ed at /data
PASS  <driver>: alloc reads a file created before it started
PASS  <driver>: alloc write reaches the bucket
PASS  <driver>: alloc sees host writes made after it started
```

This is the PRD §8 lifecycle ("mounts are established before task start"), and it works
as specified — including the case that usually breaks with FUSE: objects written on the
host *after* the container started are visible inside the alloc, so the bind does not
snapshot the mount.

## Q4 — Unprivileged mounts: **GO for all three**

`spike unpriv` (9/9 PASS). Each driver is mounted by a dedicated system user
(`kanea-s3`, `nologin`, no shell) via `sudo -u`, which is how a systemd `User=` helper
unit would run it:

```
PASS  <driver>: mounts as an unprivileged user
PASS  <driver>: FUSE daemon runs as the helper user                 daemon owner="kanea-s3"
PASS  <driver>: root can read through the unprivileged mount (allow_other)
```

PRD §8's "FUSE mounts run under a dedicated, unprivileged helper process per mount" is
achievable with all three drivers. Two host prerequisites, both of which `kanea init`
must handle:

- **`user_allow_other` in `/etc/fuse.conf`.** Without it the helper cannot pass
  `allow_other`, and then root — i.e. containerd, binding the mount into an alloc —
  gets `EACCES` walking the mount. This is the one setting that decides whether an
  unprivileged mount is usable as a container volume at all.
- **Per-helper credential files** (0600, owned by the helper user): s3fs reads
  `-o passwd_file=`, rclone its config section, mountpoint-s3 `~/.aws/credentials`.
  The root-owned copies are unreadable to the helper, so Kanea's secret materialisation
  must target the helper's uid.

## Q5 — Object-store outage: **the sharpest difference**

`spike failure`. MinIO is stopped with a read and a write in flight, then restarted.

| | s3fs | rclone | mount-s3 |
|---|---|---|---|
| read during outage | error after **1 m 40 s** | **never returned** (>2 min cap) | error after **39–48 s** |
| write during outage | error after **1 m 00 s** | **never returned** (>2 min cap) | error after **36–60 s** |
| recovery on the same mount | **NO** — `ENOENT` for 90 s+ after the store returned; the object *is* intact in the bucket, the mount is stale | yes | yes |

- **rclone blocks indefinitely.** Neither the read nor the write returned within the
  2-minute cap. A workload thread stuck in a FUSE call is not killable, and if Kanea's
  own reconciler ever stats such a mount, the control plane inherits the hang.
- **s3fs blocks for ~1–1.7 minutes, then errors — and then does not heal.** After MinIO
  returned, the mount kept serving `ENOENT` for a file that was verifiably still in the
  bucket. Recovery requires a remount, which means Kanea's mount supervisor must detect
  and re-establish it.
- **mountpoint-s3 fails fastest and recovers by itself.** Errors within ~40 s, then
  serves normally once the store is back, with no remount.

All three block for tens of seconds by default. Kanea must therefore (a) never touch a
volume mount from the reconciler's critical path without a timeout, and (b) set explicit
connect/read timeouts and retry budgets per driver rather than accepting defaults.

---

## Recommendation

| Use | Driver | Why |
|---|---|---|
| **Default for `type = "s3"`** | **mountpoint-s3** | fastest recovery, synchronous durability, no data-loss surprise; its missing POSIX operations do not matter for read-mostly volumes |
| **Read-write S3 volumes** (opt-in) | **s3fs** | the only candidate with append + write-at-offset + chmod + symlink; ships with documented caveats (silent truncate, remount-on-outage) |
| Rejected as a built-in | **rclone mount** | deferred durability (~6 s) plus unbounded blocking is the worst combination for an orchestrator that stops containers; still the right tool for *offline* sync jobs |
| Dropped | **goofys** | unmaintained since 2020, no arm64 build |

Concretely for M2:

1. `storage "s3"` gains a `mode` (or `read_only`) that selects the driver, defaulting to
   read-only + mountpoint-s3. Writable S3 volumes are an explicit choice.
2. The mount helper (PRD §8, one unprivileged process per mount) **supervises**: a
   periodic `stat` with a hard timeout, remount on failure, alloc-visible event on both.
   s3fs makes this mandatory, not optional.
3. Explicit timeouts/retries are part of the generated mount command, never defaults.
4. Kanea's own writes to S3 volumes must not use `truncate`, and the docs must state the
   per-driver capability table above.

---

## PRD amendments required

1. **§8 storage table** — replace "FUSE mount (s3fs / goofys / rclone — chosen in M2
   spike)" with the outcome: **mountpoint-s3 (default, read-mostly) / s3fs (opt-in
   read-write)**; goofys removed (unmaintained, amd64-only); rclone noted as not a
   built-in driver.
2. **§8** — record the capability limits as product behaviour: no `truncate` on any
   driver (s3fs silently no-ops it), no append/offset-write/chmod/symlink on the default
   driver, and "not for many-small-files workloads" alongside the existing latency
   caveat.
3. **§8 lifecycle** — the mount helper must **supervise and remount** (health-check with
   timeout), because s3fs does not self-heal after an object-store outage; mount access
   from the control plane always carries a timeout.
4. **§21** — add an S3-volume expectation to the non-functional table: file operations on
   an S3 volume cost one round trip each (~30 ms typical), so a 200-file directory
   listing/creation is seconds, not milliseconds.

## M2 implementation notes

- Mount commands validated by this spike are in `drivers.go`; each daemonizes, and
  `findmnt <target>` is the readiness signal (poll, ~100 ms).
- `fusermount3 -u` is the unmount path; `umount -l` is the escape hatch for a wedged
  daemon — the mount supervisor needs both.
- Bind into the alloc with `rbind` after the mount is live; host-side writes stay visible.
- Credentials come from the Kanea secret store (PRD §12) into a per-driver file:
  s3fs `-o passwd_file=`, rclone config section, mountpoint-s3 `~/.aws/credentials` —
  all three must be 0600 and owned by the helper user.
- `user_allow_other` in `/etc/fuse.conf` plus `allow_other` is what lets root-run
  containerd traverse a helper-owned mount.
