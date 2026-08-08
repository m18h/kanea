# AGENTS.md — Kanea

Guidance for AI agents (and humans) working in this repository. Read this before writing any code.

## What this is

**Kanea** is a lightweight, single-binary container orchestration platform written in Go — "Nomad's simplicity, eBPF's power, one binary." It runs services on **containerd**, networks them with **standalone Cilium** (no Kubernetes anywhere), terminates TLS with **Let's Encrypt**, and ships a **React + shadcn/ui** dashboard, an **MCP server** for AI agents, GitOps pipelines (kaniko), eBPF-driven autoscaling, and S3-backed state replication.

**[`PRD.md`](./PRD.md) is the north star.** It is complete and internally consistent (v1.4). Every architectural decision, naming rule, milestone, and risk is specified there. When this file and the PRD disagree, the PRD wins — and the disagreement means one of them needs an amendment.

## Current status

**M0–M10 complete.** Remaining v1.0 gaps are listed under *Not yet built* below.

| Milestone | State | What landed |
|---|---|---|
| M0 spikes | ✅ | Four GO reports in `spikes/*/REPORT.md`; drove PRD v1.5–v1.9 |
| M1 runtime core | ✅ | Store, reconciler, containerd driver, HCL parser, CLI, local volumes |
| M2 networking & storage | ✅ | Cilium endpoints/policy/LB, internal DNS, NFS/SMB/S3 volumes |
| M3 ingress & TLS | ✅ | `kanea-edge`, middleware, ACME HTTP-01 |
| M4 dashboard | ✅ | React SPA, live websocket, log streaming |
| M5 auth & OWASP | ✅ | Deny-by-default auth, audit log, OIDC+PKCE, rate limits, DNS-01 + wildcards, `docs/THREAT_MODEL.md` |
| M6 metrics & autoscaling | ✅ | In-memory TS, three scrapers, evaluator + guardrails, circuit breaker, Prometheus exporter |
| M7 GitOps & pipelines | ✅ | Run objects, git sync (in-process go-git), signed webhooks, BuildKit runner, serialised queue, coordinator, API/CLI/dashboard |
| M8 notifications | ✅ | Event vocabulary, glob filters, SSRF egress guard, five channels, coalescing dispatcher, bounded event feed |
| M9 MCP server | ✅ | Rolling updates on spec drift, project/stats/restart/notify-test routes, hand-written MCP over both transports, 20 tools in three tiers |
| M10 hardening & packaging | ✅ | Encrypted archives, hand-written S3 sink, CDC replication, staged + offline restore, schema migrations, `kanea init` key ceremony, systemd units, DR runbook |

Things a future change is most likely to trip over:

- **Metrics never touch the Store** (constraint #2). `internal/scaling` is an in-memory ring, ~27 MiB at the 2 000-alloc target, measured by `TestFootprintAtTargetScale`.
- **"No data" is never zero** — in the time series, the evaluator, the exporter and the dashboard alike. A missing metric and an idle service lead to opposite decisions, and each layer has a test saying so.
- **The autoscaler is not a second scheduler.** It writes one number; the reconciler converges. `kanea scale` uses the same route.
- **The scale-decision budget is 20 s** from a sustained breach (PRD v1.21), not the 15 s v1.1 promised — see the amendment for why 15 s costs more than it buys.
- **Accounts live in the Store, not the config file** (PRD v1.18), and `--oidc-client-secret` / `--acme-dns-tsig-secret` are `secret:` references, never literals.
- **A repository speaks for its own project and no other** (PRD v1.23). `gitops.parseCheckout` refuses a synced spec that declares another project — it is the same boundary R5 draws for secrets, and it is the only thing between "can push to one repo" and "owns every service on the node".
- **The git webhook route is the one non-§13 authentication** (`docs/THREAT_MODEL.md` §3.8): a per-project HMAC over the raw body, replay-rejected, audited. It never deploys from the request — it marks the project and the sync loop re-reads the source over Kanea's own credential.
- **Builds are serialised and refused when full, never blocked** — §10.2 makes isolation collective, so a second concurrent build shares the first's budget. `queued` is a real state, and shutdown cancels what is still waiting.
- **`notify.Publish` never blocks and never returns an error**, by design (constraint #8). An error return would invite `if err != nil { return err }` in a reconcile loop, turning an undeliverable Slack message into a failed deploy. Drops are counted; the queue-full warning fires once, so a notification storm cannot become a logging storm.
- **The event vocabulary lives in one place** (`internal/notify`), and `jobspec` validates filters against it. That is why the dependency points jobspec → notify and the route *builder* lives in `cmd/kanea` — two implementations of "is this a known event" drift, and they drift into a spec that passes `kanea plan` and matches nothing at runtime.
- **Notification egress is checked at dial time, on every resolved address**, and redirects are refused (§14 A10, `docs/THREAT_MODEL.md`). A hostname is not a destination.
- **go-git ≥ 5.19.1 and go-billy ≥ 5.9.0 are security floors**, not preferences (GO-2026-5693, GO-2026-5597). The billy one is a path traversal in the chroot filesystem `Materialize` clones a working tree through — repository-controlled paths written to disk. A downgrade fails `make security`, which is how it should be found.
- **A service with a `build` block and no `task.image` is legitimate** (§6.2 R8) and the reconciler skips it until the first build pins a digest. `${GIT_SHA_SHORT}` and its siblings survive parsing as literal references — their value only exists once a commit is checked out.
- **A deploy is a spec-hash mismatch** (PRD v1.25). `reconciler.SpecHash` covers only what is baked into a container at creation; adding a field to `Desired` does *not* change it unless you add it to the hash's own struct, and whether a new field should roll allocs is a decision to make there. A record with an empty hash is adopted, never rolled — that is what stops an upgrade of `kanead` from replacing every alloc on the node.
- **`max_parallel` bounds allocs that are down, not replacements in flight.** Anything already unavailable spends the budget first, so a deploy that starts going wrong stops instead of walking through every replica. `min_healthy` applies only to allocs the current deploy has already replaced.
- **`AllocRecord.Healthy` is only ever written by a probe.** A service with no `check` block has it false for every alloc, forever. Read it through `Probed()` or behind `Check.configured()`; testing the field alone reports every check-free service as broken.
- **A restart is a spec change, not a second path to the runtime** (PRD v1.26). `POST /v1/services/{p}/{s}/restart` bumps `Desired.Generation`, which is in the spec hash. The generation belongs to the running service, so `handleApply` carries it over — an apply that reset it would restart the service a second time.
- **MCP tools reach the platform only by HTTP against the API's own handler** (§16.3). That is what makes "no side channels" structural: a tool's only verb is "send this request", so it cannot be more privileged than the credential its caller presented. Nothing in `internal/mcp` may take a `Store`, a secrets store, or an auth store.
- **There are no secret tools, at any tier** (PRD v1.26). §16.3's safety rule is that no tool returns a secret value; the implementation goes further and gives an agent no secrets verb at all. `TestNoToolReadsASecret` fails if one appears.
- **An MCP refusal is a tool result, not a JSON-RPC error.** A protocol error is handled by the client library and never reaches the model; a `isError` result does. An *unknown tool* is the reverse — that is a client bug.
- **An archive's last chunk is sealed under different additional data** (PRD v1.27). That is the only thing standing between a truncated snapshot and a restore that decrypts cleanly to half a platform. A final chunk is always written, possibly empty, so "a short read is the last chunk" stays true when the plaintext is an exact multiple of the chunk size.
- **The change log is pruned only after the upload returns**, segments only below the *oldest kept* archive, and a replay that meets an unreadable segment stops rather than skipping it. Skipping one resurrects whatever a delete in it removed, and the reconciler starts it.
- **The replication cursor is derived from the sink**, never stored. In the Store, writing it emits a change that needs shipping, which writes it again.
- **The Store does not migrate itself at Open** (§15.4). A migration rewrites state in place, and the copy that makes a bad one survivable needs the database open and the migration not started — exactly one window, between `Open` and `Migrate`. Each step's data change and version bump share a transaction.
- **A restore is staged, never performed in place.** `internal/api`'s `Backups` interface has no method that restores; the daemon does it at the next start, before anything opens the Store. That is the interface, not a check.
- **`buildReplication` returns `api.Backups`, not `*backupService`.** A nil concrete pointer in an interface field is a non-nil interface: every "is a destination configured" test would answer yes and then panic.
- **A Sink's `Put` does not own the reader it is given.** `net/http` uses an `io.ReadCloser` request body directly and the transport closes it, so passing an `*os.File` hands the caller's handle to net/http. That defect uploaded every S3 snapshot successfully and then failed before writing the manifest — an invisible archive, every time — and no fake server could catch it, because every unit test passed a `strings.Reader`. The `s3-interop` CI job against MinIO is what found it.
- **The systemd units carry constraint #11**, not the Go code. `MemoryMin` and `OOMScoreAdjust` are systemd's to set, and `kanea-edge` must never gain an `After=kanead.service` — north-south traffic surviving a control-plane restart is why it is a separate process at all. The units use `Type=exec`: nothing sends `sd_notify`.

**Not yet built** (v1.0 gaps, stated so they are not rediscovered):

- **`kanea upgrade`** — §15.4's binary-upgrade orchestration (drain the edge, restart it, then kanead). The state-migration half is built; the sequencing half is `systemctl restart` by hand.
- **`kanea exec`** and **`kanea ui`** — still `todo` in the command table.
- **Signed releases** — the installer verifies a checksum and prefers a cosign signature; nothing publishes one yet.
- **Multipart upload** — an archive above 5 GiB is refused by name rather than split.
- **Node CPU/memory stats** — §17 lists procfs node stats; no scraper collects them, and `get_node_stats` reports control-plane facts instead of inventing them.
- **A dashboard page for the event feed and for backups** — the API routes exist; the React pages do not.

**M0 — technical spikes** (PRD §20), all four GO:

1. ~~Standalone Cilium: CNI from containerd, endpoint labels, service LB, network policy, Hubble metrics without k8s~~ — **done, GO** ([`spikes/cilium-standalone/REPORT.md`](./spikes/cilium-standalone/REPORT.md), 25/25 on Cilium 1.19.6; drove **PRD v1.5**). Key M2 notes: attach order is `netns → CNI ADD → PATCH /v1/endpoint labels (retry 5xx) → task start` (CNI args cannot carry labels; an unlabelled endpoint is `reserved:init` = deny both ways); labels must include `k8s:io.kubernetes.pod.namespace=<project>` or every policy selector matches nothing; **the writable service and policy REST APIs were removed in Cilium 1.18** — use `--lb-state-file` and `--static-cnp-path` (temp-then-`rename(2)`, and a malformed policy file is **fatal** to the agent → validate before writing); alloc IDs ≥ 5 chars; never import `github.com/cilium/cilium` (pulls client-go — constraint #10), speak the REST API over the unix socket
2. ~~containerd task lifecycle + CNI + cgroup metrics + cgroup isolation~~ — **done, GO** ([`spikes/containerd-lifecycle/REPORT.md`](./spikes/containerd-lifecycle/REPORT.md)); key M1 notes: pre-create persistent netns + CNI DEL-before-kill, `isDefaultGateway: true` in bridge conf, metrics listener is config v4 `[plugins.'io.containerd.server.v1.metrics']`, `memory.min` is best-effort for page cache (hard for anon)
3. ~~S3 FUSE mount choice (s3fs vs goofys vs rclone)~~ — **done, GO** ([`spikes/s3-fuse/REPORT.md`](./spikes/s3-fuse/REPORT.md); drove **PRD v1.6**). Decision: **mountpoint-s3** default (read-mostly), **s3fs** opt-in read-write, **goofys dropped** (unmaintained since 2020, amd64-only), **rclone mount rejected** as a built-in (uploads land ~6 s after `close()` → data loss when an alloc stops). Key M2 notes: no `truncate` on any driver (**s3fs silently no-ops it**); mount helper must **supervise + remount** (s3fs serves stale `ENOENT` after an outage); every control-plane touch of a mount needs a timeout (FUSE blocks 40 s–2 min uninterruptibly with a dead backend); `user_allow_other` + per-helper 0600 credential files are `kanea init` prerequisites
4. ~~kaniko executor running as a containerd task~~ — **done, GO** ([`spikes/kaniko-build/REPORT.md`](./spikes/kaniko-build/REPORT.md), 11/11 daemon + 26/27 task forms; drove **PRD v1.7–v1.9**). Decision: **BuildKit as a rootless `buildkitd` host service is the ONLY build driver** — unprivileged and non-root end to end, 546 ms warm builds. kaniko removed (upstream archived, cache saves nothing); buildah measured as a working drop-in but **not shipped** (one builder to pin and patch). Key M7 notes: **`Containerfile` and `Dockerfile` both work — Containerfile wins when both exist**, and the runner must pass `--opt filename=` because BuildKit's frontend defaults to `Dockerfile`; the daemon socket must live **outside** rootlesskit's copy-up'd `/run` (namespace-private tmpfs → invisible to clients) and is root-only (`0750` home); `--net=host` keeps a node-local registry reachable; the daemon has its **own content store** at `$HOME/.local/share/buildkit` that containerd's GC does not cover; **build isolation is collective** (one systemd cap on the unit + `--oci-max-parallelism`), not per build; ~157 MiB permanently resident inside the §21 reserve; **no §14 hardening exception is needed** (that is what decided the driver); digest via `buildctl --metadata-file` (JSON `containerimage.digest`)

Spike code is throwaway: keep it in `spikes/<topic>/` with its own `go.mod` and a `REPORT.md` (see `spikes/README.md`). Two spike findings are still load-bearing in M6 code: containerd's metrics endpoint carries 47 families per task (hence the streaming, allowlisting parser), and `--hubble-metrics` silently ignores a comma-separated list (hence the startup probe).

## Binding constraints (never violate these)

These come from PRD §18 and the security review. Violating them is a bug, even if the code works.

1. **PRD amendment discipline** — any deviation from the PRD requires editing `PRD.md` first (bump version, add an amendment note). No stealth architecture changes.
2. **State** — all mutations go through the `Store` interface with monotonic indexes (Raft-FSM-compatible shape). **Metrics and logs never touch the Store** (in-memory TS + file pipelines only). bbolt is single-writer: keep read transactions bounded/paginated.
3. **Process split** — `kanead` (control plane) and `kanea-edge` (ingress) are separate processes from one binary. Never couple edge traffic to control-plane lifecycle.
4. **Secrets** — referenced as `secret:<path>`, never inlined; **project-scoped at validation time** (a spec may not reference another project's secrets); injected via tmpfs files by default, env vars only as the documented weaker option; never logged; write-only over API/MCP.
5. **Naming** — project/service names are DNS-1123 labels, enforced at parse time. Names compose into DNS; `description` carries free text.
6. **Workload hardening defaults** — drop ALL capabilities, `no-new-privileges`, default seccomp, no `privileged` escape hatch in the v1 spec, per-alloc PID/IPC namespaces.
7. **Security gates are release gates** — `govulncheck`, `gosec`, `gitleaks`, `npm audit` must pass; OWASP Top 10 mapping (PRD §14) is reviewed per milestone. Auth is deny-by-default on every API/WS/MCP route.
8. **Backpressure discipline** — log drains are non-blocking with drop counters; a full pipeline must never block a workload's `write()`.
9. **Derived state** — Cilium/kvstore state is always rebuildable from the Store; never persist or restore etcd files.
10. **No Kubernetes dependencies.** No client-go, no CRDs, no kube imports, ever.
11. **Resource isolation** — the control plane (`kanead`, `kanea-edge`, containerd, cilium, etcd) has a kernel-guaranteed memory floor via cgroups v2 `memory.min` (default 1 GiB, PRD §5.2.11) and `OOMScoreAdjust=-900`; all workloads run under one parent cgroup with `memory.max` = total RAM − reserve. No container ever runs unlimited (defaults apply when `resources` is omitted, PRD §6.2 R11). Never use `mlock` on the Go control plane (`RLIMIT_MEMLOCK` + GC heap growth = crash risk) — the guarantee comes from cgroup protection + OOM-killer policy.

## Tech stack

| Layer | Choice |
|---|---|
| Language | Go (latest stable), single static binary `kanea` |
| Runtime driver | `github.com/containerd/containerd/v2` client |
| Networking | Cilium CNI + agent REST API over `/var/run/cilium/cilium.sock` (hand-written client, **never** `github.com/cilium/cilium`) + the `--lb-state-file` / `--static-cnp-path` file interfaces; standalone mode, etcd kvstore; `cilium-agent` **≥ 1.18 on host (pin 1.19.x)** |
| State | `go.etcd.io/bbolt` behind a `Store` interface |
| Job specs & config | `github.com/hashicorp/hcl/v2` (HCL) |
| ACME | `github.com/go-acme/lego/v4` |
| Dashboard | React 18+, Vite, TypeScript strict, Tailwind CSS, **shadcn/ui**, TanStack Query, zod — embedded via `go:embed` |
| MCP | streamable HTTP transport on the API server + stdio via `kanea mcp` |
| Builds | rootless `buildkitd` + `buildctl` (M0 spike ④ replaced kaniko) |

## Repository layout (created)

```
/cmd/kanea/            # binary entrypoint (agent, edge, mcp, CLI subcommands)
/internal/api/         # REST + WS server, auth middleware, audit
/internal/logging/     # slog foundation: JSON/text sinks, lumberjack rotation (used by everything)
/internal/store/       # Store interface + bbolt impl (+ future raft impl)
/internal/reconciler/  # convergence loop, scheduler interface
/internal/runtime/     # containerd driver
/internal/network/     # Cilium driver (endpoints, services, policies, DNS)
/internal/edge/        # kanea-edge: routing, TLS, middleware; the projections kanead publishes to it
/internal/acme/        # ACME issuance + renewal — runs in kanead, never in the edge (§5.2.6)
/internal/jobspec/     # HCL schema, parsing, validation (incl. R1–R16 rules)
/internal/scaling/     # metrics TS, evaluator
/internal/gitops/      # git sync, webhooks, kaniko runner
/internal/notify/      # notification channels, coalescing
/internal/backup/      # CDC replicator, snapshots, restore
/internal/mcp/         # MCP server (tools, resources, transports)
/dashboard/            # React SPA (own package.json; build → go:embed) — scaffolded in M4
/spikes/               # M0 throwaway validation code (own go.mod per spike)
/docs/                 # THREAT_MODEL.md (M5, written), DR_RUNBOOK.md (stub; M10)
```

## Commands

```bash
make help        # list all targets
make build       # build ./bin/kanea (version-stamped via ldflags)
make test        # go test ./... -race -count=1
make vet         # go vet ./...
make lint        # golangci-lint run (config: .golangci.yml)
make security    # gosec + govulncheck + gitleaks (AGENTS.md constraint #7)
make dashboard   # dashboard gates (no-op until M4 scaffolds dashboard/)
make tools       # install dev tools
make check       # ALL gates — CI parity; must pass before any merge
```

CI (`.github/workflows/ci.yml`) runs the same gates on every PR: Go build/vet/test, golangci-lint, gosec, govulncheck, gitleaks, and dashboard checks (auto-skipped until `dashboard/` exists). Dependabot watches gomod, npm, and GitHub Actions.

## Coding conventions

- **Go:** standard project layout; `goimports`-formatted; no global state (dependencies injected); errors wrapped with `fmt.Errorf("...: %w", err)`; context plumbed through all blocking calls; interfaces defined at the consumer, small and focused (`Store`, `Scheduler`, runtime/network drivers).
- **Logging:** everything logs through `log/slog` via `internal/logging`; components receive a `*slog.Logger` by injection. The stdlib `log` package is **depguard-banned**; direct `fmt.Print*` is **forbidigo-banned** (CLI output lives in `cmd/kanea` and goes through `fmt.Fprint*(os.Stdout/os.Stderr, …)`). Daemon file sinks rotate via lumberjack (bounded size/backups, gzip); workload logs follow PRD §17 (non-blocking drains, drop counters) and must never let a rotation stall a workload `write()`.
- **HCL:** all spec changes extend `internal/jobspec` schema with validation errors carrying file/line diagnostics; keep the PRD §6 examples valid.
- **Dashboard:** TypeScript strict; shadcn/ui components only (no new component lib); all user-controlled strings escaped (XSS — PRD §14 A03); live data via the single multiplexed WS.
- **Commits/PRs:** conventional commits (`feat:`, `fix:`, `chore:`, `docs:` …), one logical change per PR, `make check` green required. PR template enforces the binding constraints.
- **Tests:** table-driven; reconciler and jobspec validation must have >80% coverage — they are the correctness core.

## Milestones (PRD §20)

M0 spikes → M1 runtime core → M2 networking/storage → M3 ingress/TLS/middleware → M4 dashboard → M5 auth/OWASP → M6 metrics/autoscaling → M7 GitOps/pipelines → M8 notifications → M9 MCP → M10 hardening/packaging.

Each milestone's definition-of-done: OWASP §14 checks reviewed, `govulncheck` clean, tests green, docs updated.

## Key documents

| File | Content |
|---|---|
| `PRD.md` | Full product requirements (v1.21) — the north star |
| `AGENTS.md` | This file |
| `docs/THREAT_MODEL.md` | Threat model — boundaries, adversaries, §14 status as built (M5) |
| `docs/DR_RUNBOOK.md` | Disaster recovery procedure (to be written during M10) |
