# REPORT — Spike ④: image builds as containerd tasks

**Date:** 2026-07-30 · **Verdict: GO. Driver decision: `BuildKit` as a rootless host daemon — the only build driver. `kaniko` removed; `buildah` measured as a working drop-in but not shipped.** · **PRD amendments required: yes (§6.1, §10.2, §21, §22 R4, §23.2 — see the last section)**

> **Decision note.** The first pass of this report recommended buildah, because BuildKit
> as a *one-shot containerd task* requires a privileged container. The project owner
> chose BuildKit and asked for the **daemon path** instead, which this report then
> validated (Q6): run `buildkitd` rootless as an unprivileged host user. That removes
> the privileged-container objection entirely and is faster on warm builds; it costs one
> supervised daemon (~157 MiB resident) and changes build isolation from per-build cgroup
> caps to a collective cap. The owner then scoped it to a **single driver** — buildah is
> measured here but not shipped — and required **`Containerfile`** to work alongside
> `Dockerfile`, which Q6 validates. The evidence for every shape is below.

The mechanism the PRD assumes is sound: a short-lived containerd task builds a
Dockerfile and pushes to an authenticated registry, with the digest handed back for
the deploy to pin. The problem is the driver. **kaniko's upstream repository is
archived** — read-only since June 2025, last release v1.24.0 (2025-05-23) — which
puts an unmaintained component on the critical path of Kanea's supply chain, against
the release gates in AGENTS.md #7.

## Environment

| | |
|---|---|
| Host | OrbStack VM `kanea-spike` (Ubuntu 24.04, arm64), 18 vCPU / 8 GiB |
| Runtime | containerd 2.3.3, runc 1.5.1 (spike ②) |
| Registry | `registry:3` as a containerd task, **htpasswd basic auth enforced** (401 verified) |
| Builders | kaniko **v1.24.0** · BuildKit **v0.32.0** (rootless image) · buildah image **v1.43.1** (source v1.45.0) |
| Build | multi-stage Alpine Dockerfile: `apk add`, `adduser`, `COPY`, `chown`, `COPY --from` |

Provision: `provision-vm.sh`. Reproduce: `README.md`. Full suite: **26/27 PASS**
(`spike all`) — the single failure is `buildkit: runs without a privileged container`,
which is the finding itself rather than a defect in the harness.

---

## Q1 — Build and push from a containerd task: **GO for all three**

```
PASS  kaniko:   builds and pushes as a containerd task (default caps)   1m0.68s
PASS  buildkit: builds and pushes as a containerd task (privileged)     37.11s
PASS  buildah:  builds and pushes as a containerd task (default caps)   39.77s
PASS  <each>:   image is retrievable from the registry
PASS  <each>:   reports the produced image digest, pinnable by the deploy
```

All three: no Docker daemon, no `/var/run/docker.sock`, credentials from a mounted
`config.json`, and a digest written to a file the pipeline runner can read — which is
what PRD §10.2's "the deploy pins the produced digest" needs. BuildKit reports the
digest inside a JSON metadata document rather than as a bare digest file.

## Q2 — Minimum privilege: **the deciding result**

`spike hardening` probes each builder at Kanea's workload default, then at
containerd's default capability set, then privileged:

| builder | drop ALL caps + no-new-privs | default caps | privileged | minimum |
|---|---|---|---|---|
| kaniko | ✗ `chown /etc/shadow: operation not permitted` | ✓ | ✓ | **default caps** |
| BuildKit | ✗ `mkdir …: permission denied` | ✗ `mount … operation not permitted` | ✓ | **privileged** |
| buildah | ✗ `write /proc/18/gid_map: operation not permitted` | ✓ | ✓ | **default caps** |

- **No builder runs under Kanea's hardened workload defaults.** Image building means
  `chown`ing files to arbitrary uids and mapping uids — `CAP_CHOWN`, `CAP_FOWNER`,
  `CAP_DAC_OVERRIDE`, `CAP_SETUID`/`CAP_SETGID` are inherent to the job. Build tasks
  are therefore a **documented exception** to AGENTS.md #6, running at containerd's
  default capability set — not with the workload profile, and not privileged.
- **BuildKit needs a privileged container.** Its worker shells out to a nested `runc`
  that performs bind mounts, which needs `CAP_SYS_ADMIN`. Getting it to run at all as
  a containerd task also required: uid 0 (rootlesskit fails inside an existing
  sandbox — `newuidmap: Could not set caps`), a host `/sys/fs/cgroup` bind mount
  (else every `RUN` fails with `no cgroup mount found in mountinfo`), an existing
  `XDG_RUNTIME_DIR`, and `--oci-worker-net=host`. That is four environmental
  concessions plus `privileged` — for a project whose pitch is "no privileged Docker
  socket", this is the wrong trade.

## Q3 — Layer cache: **works for all three; only two save time**

```
PASS  kaniko:   warm build reuses cached layers   marker "Using caching version of cmd"; cold 33.8s -> warm 33.5s (1.0x)
PASS  buildkit: warm build reuses cached layers   marker "CACHED";      cold 19.9s -> warm  4.4s (4.5x)
PASS  buildah:  warm build reuses cached layers   marker "Using cache"; cold 48.7s -> warm 11.1s (4.4x)
```

kaniko demonstrably *hits* the cache (verified in its logs: `Using caching version of
cmd` for every step) yet gains no wall-clock, because its cost is dominated by
snapshotting the filesystem rather than by executing the `RUN` steps. buildah and
BuildKit both cut ~4.4× off the warm build. This is an argument for buildah beyond
maintenance status: **kaniko's cache is real but does not make rebuilds fast**, which
is the whole point of a cache in a GitOps loop.

## Q4 — Build isolation (PRD §10.2): **GO for all three**

```
PASS  kaniko:   builds under cgroup memory/CPU caps   21.9s in /kanea-workloads.slice/kanea-build-kaniko
PASS  buildkit: builds under cgroup memory/CPU caps   18.2s in /kanea-workloads.slice/kanea-build-buildkit
PASS  buildah:  builds under cgroup memory/CPU caps   17.5s in /kanea-workloads.slice/kanea-build-buildah
```

All three complete inside a **1 GiB memory / 2 CPU** cap, placed in the
`kanea-workloads.slice` hierarchy from spike ②. PRD §10.2's "builds run with cgroup
CPU/memory caps and a concurrency limit so they can't starve workloads" is
implementable as specified — the build task is just another cgroup-limited alloc.

## Q6 — BuildKit as a rootless host daemon: **GO, 9/9 — the chosen path**

`spike daemon`. `buildkitd` runs under `rootlesskit` as the unprivileged system user
`kanea-buildkit` (subuid/subgid ranges, `newuidmap`), supervised by systemd; `kanead`
drives it as root over its unix socket with `buildctl`.

```
PASS  buildkitd runs as an unprivileged user (not root)     daemon uid="kanea-buildkit"
PASS  root can drive the daemon over its socket (kanead's path)
PASS  rootless daemon builds and pushes (no privileged container anywhere)   22.76s
PASS  image is retrievable from the registry
PASS  reports the produced image digest, pinnable by the deploy
PASS  warm build reuses cached layers                       cold 22.76s -> warm 546ms
PASS  failing build exits non-zero with an actionable log   exit code: 17
PASS  nothing is pushed on failure
PASS  builds a context that has only a Containerfile        exit 0 -> sha256:8a2739…
PASS  Containerfile takes precedence when both are present   built image prints "containerfile-wins"
PASS  daemon runs under a systemd resource cap              MemoryMax=2G CPUQuota=2s (COLLECTIVE)
INFO  daemon resident cost                                  MemoryCurrent=156.6 MiB (permanent)
INFO  build storage location                                /home/kanea-buildkit/.local/share/buildkit
```

**`Containerfile` support is not free.** BuildKit's `dockerfile.v0` frontend defaults to
the literal name `Dockerfile`; anything else must be passed as `--opt filename=`. The
runner therefore detects the recipe itself — **`Containerfile` first, then `Dockerfile`**,
matching the Podman/buildah convention. Precedence was verified end-to-end rather than by
inspecting build output: a context containing *both* files, whose two recipes bake
different content, was built and then **pulled back through containerd and run** — it
printed `containerfile-wins`. (That verification also exercised an authenticated pull from
a private registry, which M1's runtime needs anyway.)

**How it compares to the same builder as a task:**

| | BuildKit as a task | BuildKit as a rootless daemon |
|---|---|---|
| privilege | **privileged container** + host `/sys/fs/cgroup` | **unprivileged, non-root** |
| warm build | 4.4 s | **546 ms** |
| resident cost | none between builds | **156.6 MiB, permanent** |
| resource cap | per build (own cgroup) | **collective** (systemd unit) |
| worker sandbox | `no-process-sandbox` | full `process-mode:sandbox` |

Four operational facts M7 must encode, each discovered the hard way here:

1. **The socket must live outside `--copy-up=/run`.** rootlesskit replaces `/run` with a
   namespace-private tmpfs, so a socket under it is invisible to clients on the host. The
   socket lives in the daemon user's `$HOME` instead.
2. **The socket is root-only.** The daemon's home is `0750`, so only root (i.e. `kanead`)
   can reach it — correct by default; a group would be needed if anything else must.
3. **`--net=host`** keeps the node's loopback reachable, which is how the daemon reaches a
   node-local registry.
4. **Build storage is the daemon's, not containerd's** (`$HOME/.local/share/buildkit`, its
   own overlayfs snapshotter). Image GC and disk watermarks (§5.2.4) must cover that path
   too — it is not in containerd's content store.

The daemon also declines to use containerd's worker (`connect: permission denied` on
`containerd.sock`, as it must — it is unprivileged), so builds do not share containerd's
snapshotter. That is the trade for rootlessness.

## Q5 — Failure surfacing (PRD §22 R4): **GO for all three**

```
PASS  <each>: failing build exits non-zero          kaniko exit 17 · buildkit exit 1 · buildah exit 17
PASS  <each>: failure log identifies the failing step
PASS  <each>: nothing is pushed on failure          registry returns 404 for the tag
```

Each surfaces the failing instruction and its exit status through containerd's IO, and
none leaves a partial image in the registry. kaniko and buildah propagate the
instruction's own exit code (17); BuildKit exits 1 and reports the code in the message.

---

## Decision

**BuildKit as a rootless host daemon is the only build driver.**

| | BuildKit (rootless daemon) — **shipped** | buildah (task) — measured, not shipped | kaniko (task) — removed |
|---|---|---|---|
| upstream | active (v0.32.0, 2026-07-29) | active (v1.45.0, 2026-07-30) | **archived** 2025-06 |
| privilege | **none — unprivileged, non-root** | default caps, root-in-container | default caps, root-in-container |
| warm build | **546 ms** | 11.1 s (4.4×) | 33.5 s (1.0× — hits cache, saves nothing) |
| resident cost | 157 MiB, permanent | none | none |
| resource cap | collective (daemon unit) | per build | per build |
| shape | long-lived service | one-shot task | one-shot task |

It is the only configuration tested that needs **no elevated privilege anywhere** — not a
privileged container, not root on the host — while being the fastest on rebuilds by a wide
margin. It fits the node's existing shape: containerd, cilium-agent and etcd are already
supervised units; `buildkitd` is a fourth.

Shipping **one** driver is a deliberate choice: one builder to pin, patch and support,
and no user-visible knob whose branches would need equal testing. The runner keeps a
narrow internal seam, and this report is the evidence that buildah is a working drop-in
(26/27, task-shaped) if that ever becomes necessary.

**Costs to accept, explicitly:**

- **~157 MiB permanently resident** inside the §21 1 GiB control-plane reserve, on top
  of cilium-agent's ~153 MiB. The reserve still holds, but it is now the second-largest
  component and `system_reserve_memory` sizing must account for it.
- **Build isolation is collective.** PRD §10.2's per-build cgroup caps become one cap on
  the daemon unit; the "concurrency limit (default 1)" moves inside buildkitd
  (`--oci-max-parallelism`) rather than being enforced by the scheduler.
- **A second content store** under the daemon user's home, outside containerd's GC.
- **Single-driver risk**: a Dockerfile the BuildKit frontend rejects has no in-product
  escape hatch. Accepted; R4 records the mitigation.

## PRD amendments required

1. **§10.2** — the build driver decision is made: **BuildKit as a rootless `buildkitd`
   host service is the only driver**, driven by `buildctl` over a unix socket. **kaniko
   is removed** (upstream archived, cache buys nothing); **buildah is not shipped**.
2. **§10.2** — build isolation changes shape: the daemon carries **one collective**
   systemd memory/CPU cap and bounds concurrency internally
   (`--oci-max-parallelism`), instead of a cgroup cap per build. The fallback task
   driver keeps the per-build cap.
3. **§10.2 / §14** — **no hardening exception is needed**: the daemon is unprivileged and
   non-root, so §14's workload defaults are untouched. (Every task-shaped builder measured
   *would* have needed one — that is what decided the driver.)
4. **§5.2.11 / `kanea init`** — provision the `kanea-buildkit` system user with
   subuid/subgid ranges, the `uidmap` package, and the `buildkitd` unit; its socket is
   root-reachable only. Add the daemon to the units carrying the memory floor.
5. **§21** — the 1 GiB control-plane reserve now also covers `buildkitd` at ~157 MiB
   resident (second only to cilium-agent).
6. **§5.2.4** — image GC and disk watermarks must cover the daemon's own content store
   (`$HOME/.local/share/buildkit`), which containerd does not manage.
7. **§22 R4** — restate: the risk is the default builder's edge cases, mitigated by the
   pluggable driver interface with buildah as the tested fallback.
8. **§23.2** — replace kaniko with `moby/buildkit` (digest-pinned, binaries extracted to
   the host) as the sole build dependency.
9. **§6.1 / §10.2** — `Containerfile` is accepted alongside `Dockerfile`, taking
   precedence when both exist; `build.dockerfile` becomes an optional override. The
   runner must pass `--opt filename=` explicitly, since the frontend defaults to
   `Dockerfile`.

## M7 implementation notes

- The daemon unit, rootlesskit flags and socket placement validated here are in
  `provision-vm.sh`; the `buildctl` invocation is in `daemon.go`.
- Recipe detection: `Containerfile` then `Dockerfile`, passed as `--opt filename=`
  (`dockerfileName()` in `daemon.go`).
- Command lines for the task-shaped builders remain in `builders.go` as reference for the
  internal driver seam; they are not shipped.
- Digest capture: buildah `--digestfile`, kaniko `--digest-file`, BuildKit
  `--metadata-file` (JSON, key `containerimage.digest`).
- Registry auth is a mounted `config.json` (or `--authfile`); materialise it from the
  secret store to a tmpfs path, 0600, never into the build context.
- Build tasks need DNS: bind-mount `/etc/resolv.conf`. The spike used host networking
  to reach a loopback registry; a real deployment should give the build task a CNI
  endpoint and a routable registry address instead (spike ① showed how).
- Place build tasks in `kanea-workloads.slice` with explicit memory/CPU caps and
  concurrency 1 (PRD §10.2); a build that exceeds the cap is OOM-killed like any alloc.
- `.git` must be excluded from the context before the task starts (PRD §14) — none of
  the builders does that for you.
