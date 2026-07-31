# REPORT — Spike ②: containerd lifecycle, CNI, metrics, cgroup isolation

**Date:** 2026-07-30 · **Verdict: GO on all four questions** · **PRD amendments required: none**

## Environment

| | |
|---|---|
| Host | OrbStack VM `kanea-spike` (Ubuntu 24.04, arm64), 18 vCPU / 8 GiB |
| Kernel | 7.0.11-orbstack, **cgroups v2** (cgroup2fs), systemd PID 1 |
| Runtime | containerd **2.3.3** (static, config **v4**), runc **1.5.1** |
| CNI | plugins **1.9.1** (bridge + host-local IPAM) |
| Client libs | `github.com/containerd/containerd/v2` v2.3.3, `github.com/containernetworking/cni` v1.3.0 |
| Image | `docker.io/library/alpine:3.21` @ `sha256:48b0309c…c07d` |

Provision: `provision-vm.sh` (pinned versions, sha256-verified). Reproduce: `README.md`.
All checks below ran as the spike binary (`lifecycle` 12/12, `metrics` 4/4, `cgroups` 23/23 PASS).

---

## Q1 — Task lifecycle with the raw v2 client (no CRI, no k8s): **GO**

Evidence (`spike lifecycle`):

```
PASS  image pull (cached ok)                    docker.io/library/alpine:3.21 in 1ms
  ✓ create+start lc-1                           40ms      ✓ create+start lc-2  31ms
PASS  task.Wait reported exit                   code=137            (after SIGKILL)
PASS  /tasks/exit event received                topic=/tasks/exit ns=kanea-spike
PASS  restart same container + re-network       new pid=3988 ip=10.200.0.4/24
PASS  namespace clean after teardown            0 containers left
```

- Pull → create → start ≈ **30–70 ms per alloc**; CRI grpc plugin untouched (not needed by the raw client).
- Crash detection works two ways simultaneously: `task.Wait()` (exit code + timestamp) and the event service (`/tasks/exit` envelopes, namespace-filterable). This is the reconciler's failure signal for M1.
- Restart = delete dead task → new task on the **same container object** (rootfs/snapshot intact) → re-network. Verified with connectivity after restart.

## Q2 — CNI invoked by our own process: **GO, with findings**

`libcni` ADD/DEL against `/proc/<task-pid>/ns/net` works (~10–20 ms per ADD):
per-alloc IPv4 (host-local), `eth0` inside the alloc, **east-west** (alloc↔alloc ping),
gateway reachability, **north-south via ipMasq** (TCP to 1.1.1.1:80) all PASS.

**Findings (all feed M1):**

1. **CNI bridge needs explicit `isDefaultGateway: true`** (plugins ≥ 1.x): field defaults to
   `false` → container gets *no default route* → silent north-south failure. Must be in M2's
   generated CNI config. (Cilium spike ① uses Cilium's own config instead.)
2. **bridge `ipMasq` programs a per-container /32 POSTROUTING jump, and CNI DEL against an
   already-dead netns skips iptables teardown** → leaked masquerade rules on the crash path.
   ⇒ M1 must **pre-create persistent named netns** (`/var/run/netns/<alloc>`) so DEL always
   works regardless of task state, and order **CNI DEL before task kill** on the normal path.
3. **No `dns{}` in CNI config ⇒ empty `resolv.conf`** in the alloc. Outbound IP connectivity
   is unaffected, but name resolution needs M2's internal DNS wiring (§7.1) — expected, noted.
4. `libcni.NewCNIConfig(path, nil)` is the correct construction (nil → library-default exec);
   a zero-value `&invoke.DefaultExec{}` **panics** (nil embedded `*RawExec`).

## Q3 — Single `/v1/metrics` scrape for all allocs: **GO**

One GET of `http://127.0.0.1:1338/v1/metrics` carried **47 metric families per task** for all
three allocs — *including* the alloc placed under our own `kanea-workloads.slice` hierarchy
(custom `CgroupsPath`), so **§5.2.11 placement does not break metrics**:

```
container_cpu_usage_usec_microseconds{container_id="m-1",namespace="kanea-spike",
  runtime="io.containerd.runc.v2"} 4.088331e+06
```

- containerd 2.3 names/units: `container_cpu_usage_usec_microseconds`,
  `container_memory_{usage,working_set?,…}_bytes` (working_set is absent; use
  `usage - inactive_file` if needed), `container_pids_current`, `container_pids_limit`,
  per-task `oom` counters (`container_memory_oom_total`). Labels: `container_id`, `namespace`, `runtime`.
- Cost: **414 KB body, mean 6.5 ms** per scrape with 3 allocs (served from in-memory cache;
  containerd does not re-walk sysfs per request). Payload scales with alloc count — M6 should
  re-measure at 2000-alloc scale (PRD §9.1/§21) and can drop unused families via Prometheus
  scrape relabeling if needed.
- `container_io_*` was present for the two plain allocs but **absent for the custom-cgroup
  alloc**: our slice delegated only `+cpu +memory +pids`. Delegate `+io` in M1 if IO metrics
  are wanted (§9.1).
- Fallback if this ever regresses: per-task `task.Metrics()` API polling (available in the
  same client) or edge-proxy-primary L7 metrics per PRD §9.1 (R2). Not needed today.

## Q4 — cgroups v2 isolation per PRD §5.2.11: **GO, one documented caveat**

Hierarchy created **directly** (`/sys/fs/cgroup` writes — the PRD's non-systemd fallback path;
systemd units are M10 packaging):

```
T1  kanea.slice: memory.min=1GiB, swap.max=0, cpu.weight=10000 ............ PASS
T1  kanea-workloads.slice: memory.max=RAM−1GiB, swap.max=0, weight=100 ... PASS
T2  alloc cgroup under workloads slice via OCI CgroupsPath ............... PASS
T2  memory.max=128MiB: memhog breach → exit 137, oom_kill 0→1 ............ PASS
T2  cpu.max=0.5 core: hog throttled (nr_throttled +30/3s) ................ PASS
T2  pids.max=64: fork bomb contained (pids.current=64, events max 0→36) .. PASS
T3  ceiling 2GiB: 300M hog survives, 2000M hog OOM-killed ................ PASS
T4  moderate pressure (5.4G hog): floor cache 399→399 MiB ................ PASS
T4  extreme pressure (7G hog): hog OOM-killed, floor proc alive,
    floor ANON 601→601 MiB ............................................... PASS
T4  extreme pressure: floor page cache 399→0 MiB ......................... (see caveat)
```

**Caveat (kernel semantics, verified with two isolated probes):** `memory.min` is
**best-effort**. Under *moderate* global pressure the floor's page cache is fully protected;
under *adversarial last-resort* pressure (one unbounded allocator forcing the kernel to the
OOM brink) the kernel reclaims protected page cache before OOM-killing
(`VM_FAULT_OOM leaked out to the #PF handler` observed). **Anonymous memory was never
reclaimed in any test** (swap disabled everywhere) and the OOM killer always picked the
workload hog, never the floor process (`oom_score_adj=-900`).

⇒ Control-plane survival rests on **anon working set + OOM policy**, which is exactly what
PRD §5.2.11 specifies (and why `mlock` was rejected). Go services keep hot state in heap
(anon); a last-resort cache reclaim causes refaults (latency), not death. **No PRD change
needed**; the ops docs should state this explicitly.

**Additional mechanics validated:** the no-internal-process rule means slices with delegated
controllers cannot hold procs directly — per-alloc *child* cgroups (as §5.2.11 draws them)
are required, and runc creates them fine via `Linux.CgroupsPath`.

## Toolkit notes for M1 (all hit during this spike)

- containerd 2.3 uses **config v4**: the Prometheus listener is
  `[plugins.'io.containerd.server.v1.metrics'] address` (set via `/etc/containerd/conf.d/*.toml`
  import); the old `[metrics]` table is gone. `containerd-static` tarball does **not** bundle runc.
- Task exec output capture can race a fast-exiting process (buffer read after `Wait` may be
  empty) ⇒ M1 log pipeline must **stream** IO continuously, not buffer-after-exit (§17).
- busybox `tail -c N /dev/zero` does *not* allocate (seeks instead of buffering) — useless as
  an OOM test; the spike bind-mounts its own `memhog` into the alloc instead.
- A Go test workload must never idle on bare `select {}` (deadlock detector kills it).
- Page cache is charged to its **first instantiator**; `drop_caches` needs `sync` first.
- OrbStack VM reboot keeps containerd + images intact (observed incidentally).

## Fallbacks (M0 exit criterion)

| Component | Primary | Fallback |
|---|---|---|
| cgroup metrics | single `/v1/metrics` scrape | per-task `task.Metrics()` polling; edge-proxy metrics primary for L7 (§9.1, R2) |
| workload networking | CNI from our agent (validated) | — (spike ① replaces bridge with Cilium for M2) |
| memory floor | `memory.min` + `OOMScoreAdjust` (validated, caveat above) | none needed — anon guarantee is hard |

## Go / No-Go

**GO.** M1 (runtime core) proceeds as specified: raw v2 client, own-process CNI with
persistent netns, OCI-spec limits + workload-parent cgroup, `/v1/metrics` as the metrics
substrate. No PRD amendments required.
