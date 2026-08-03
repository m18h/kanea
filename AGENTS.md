# AGENTS.md — Kanea

Guidance for AI agents (and humans) working in this repository. Read this before writing any code.

## What this is

**Kanea** is a lightweight, single-binary container orchestration platform written in Go — "Nomad's simplicity, eBPF's power, one binary." It runs services on **containerd**, networks them with **standalone Cilium** (no Kubernetes anywhere), terminates TLS with **Let's Encrypt**, and ships a **React + shadcn/ui** dashboard, an **MCP server** for AI agents, GitOps pipelines (kaniko), eBPF-driven autoscaling, and S3-backed state replication.

**[`PRD.md`](./PRD.md) is the north star.** It is complete and internally consistent (v1.4). Every architectural decision, naming rule, milestone, and risk is specified there. When this file and the PRD disagree, the PRD wins — and the disagreement means one of them needs an amendment.

## Current status

**M0–M6 complete. M7 (GitOps & pipelines) is next.**

| Milestone | State | What landed |
|---|---|---|
| M0 spikes | ✅ | Four GO reports in `spikes/*/REPORT.md`; drove PRD v1.5–v1.9 |
| M1 runtime core | ✅ | Store, reconciler, containerd driver, HCL parser, CLI, local volumes |
| M2 networking & storage | ✅ | Cilium endpoints/policy/LB, internal DNS, NFS/SMB/S3 volumes |
| M3 ingress & TLS | ✅ | `kanea-edge`, middleware, ACME HTTP-01 |
| M4 dashboard | ✅ | React SPA, live websocket, log streaming |
| M5 auth & OWASP | ✅ | Deny-by-default auth, audit log, OIDC+PKCE, rate limits, DNS-01 + wildcards, `docs/THREAT_MODEL.md` |
| M6 metrics & autoscaling | ✅ | In-memory TS, three scrapers, evaluator + guardrails, circuit breaker, Prometheus exporter |

Things a future change is most likely to trip over:

- **Metrics never touch the Store** (constraint #2). `internal/scaling` is an in-memory ring, ~27 MiB at the 2 000-alloc target, measured by `TestFootprintAtTargetScale`.
- **"No data" is never zero** — in the time series, the evaluator, the exporter and the dashboard alike. A missing metric and an idle service lead to opposite decisions, and each layer has a test saying so.
- **The autoscaler is not a second scheduler.** It writes one number; the reconciler converges. `kanea scale` uses the same route.
- **The scale-decision budget is 20 s** from a sustained breach (PRD v1.21), not the 15 s v1.1 promised — see the amendment for why 15 s costs more than it buys.
- **Accounts live in the Store, not the config file** (PRD v1.18), and `--oidc-client-secret` / `--acme-dns-tsig-secret` are `secret:` references, never literals.

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
