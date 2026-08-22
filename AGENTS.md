# AGENTS.md: Kanea

Guidance for AI agents (and humans) working in this repository. Read this before writing any code.

## What this is

**Kanea** is a lightweight, single-binary container orchestration platform written in Go, "container orchestration in one binary." It runs services on **containerd**, networks them with **its own eBPF datapath** (nothing from the Kubernetes stack underneath, and since PRD v1.36 no Cilium either), terminates TLS with **Let's Encrypt**, and ships a **React + shadcn/ui** dashboard, an **MCP server** for AI agents, GitOps pipelines (kaniko), eBPF-driven autoscaling, and S3-backed state replication.

**[`PRD.md`](./PRD.md) is the north star.** It is complete and internally consistent (v1.96). Every architectural decision, naming rule, milestone, and risk is specified there. When this file and the PRD disagree, the PRD wins, and the disagreement means one of them needs an amendment.

## Current status

**Every subsystem the PRD specifies is built and released.** What is still owed before
v1.0 is evidence rather than code: the real-hardware runs no test can stand in for are
tracked, with dates, in [`docs/VALIDATION.md`](./docs/VALIDATION.md).

**The decision record lives in [`docs/DECISIONS.md`](./docs/DECISIONS.md)**: the
per-subsystem status table, the per-amendment "things a change is most likely to trip
over" bullets, *Deliberately not built*, *Known limits*, and the spike log. **Read that
file's bullets for any area before changing it**, and treat an apparent gap as a
decision until that document says otherwise: several of the most tempting "fixes" in
this codebase are listed there as refusals.

### Recurring design rules

Cross-cutting patterns the decision record applies over and over. Each is one sentence
here; the bullets in `docs/DECISIONS.md` carry the details and the history.

1. **SpecHash discipline (the R23 lesson)**: a new `Desired` field needs `omitempty`
   *and* an explicit decision about whether it is hash material; a missing `omitempty`
   rolls every alloc on the node at upgrade, and pre-existing records must serialize
   byte-identically, pinned by test.
2. **A record with an empty spec hash is adopted, never rolled** - that is what stops a
   `kanead` upgrade from replacing every alloc on the node.
3. **"No data" is never zero**: absence and a measured zero lead to opposite decisions,
   in the time series, the evaluator, the exporter and the dashboard alike.
4. **A control that cannot be enforced is refused, never silently dropped** (R21).
5. **Parse-time and apply-time checks are duplicated on purpose**, with shared exported
   cores (`CheckCapabilities`, `ParseEnvRef`, ...) so the two paths cannot drift.
6. **Client-side conversion never bakes in node-dependent values**: `toDesired` runs in
   the CLI, MCP and the pipeline, so TLS modes, pull-policy defaults and their kin are
   resolved on the node.
7. **Server-owned fields (`Generation`, `PinnedImage`) are carried over by
   `handleApply`**, never reset by a client's apply.
8. **Small constants are deliberately duplicated across package boundaries**
   (`CapabilityNone`, `ownershipRefusedBy`, `MaxBcryptCost`) - matching them by import
   would point a dependency the wrong way; they are not DRY violations.
9. **Attacker-chosen keys are never persisted**, and every map keyed by one is bounded,
   with refusals counted: a cap nobody can see is indistinguishable from a leak.
10. **Steady state writes nothing**: an unchanged value is never rewritten, because a
    Store write is a CDC change and an S3 upload.
11. **Anything added to a published snapshot must be added to its equality check**, or
    it publishes exactly once and never again (the `routesArePublished` lesson).
12. **A spec names a grant, never a path** - GitOps deploys specs automatically, so a
    spec is an untrusted document and node-side config holds the mapping.
13. **Config files come in two families and must not mix**: the reload family
    (keep-last-good, content-fingerprinted - certificates, secret providers) and
    load-once `kanea.hcl` (absent is off, malformed is fatal).
14. **Fail closed**: a missing certificate, verifier or identity is a 503 or a drop,
    never open.
15. **Every optional daemon dependency must be wired in `cmd/kanea`**, pinned by tests
    that read the source - the recurring bug class is invisible in dev and fatal on the
    first real systemd node.

One spike finding is still load-bearing in the metrics code: containerd's metrics
endpoint carries 47 families per task, hence `internal/scaling`'s streaming,
allowlisting parser.

## Binding constraints (never violate these)

These come from PRD §18 and the security review. Violating them is a bug, even if the code works.

1. **PRD amendment discipline**: any deviation from the PRD requires editing `PRD.md` first (bump version, add an amendment note). No stealth architecture changes.
2. **State**: all mutations go through the `Store` interface with monotonic indexes (Raft-FSM-compatible shape). **Metrics and logs never touch the Store** (in-memory TS + file pipelines only). bbolt is single-writer: keep read transactions bounded/paginated.
3. **Process split**: `kanead` (control plane) and `kanea-edge` (ingress) are separate processes from one binary. Never couple edge traffic to control-plane lifecycle.
4. **Secrets**: referenced as `secret:<path>`, never inlined; **project-scoped at validation time** (a spec may not reference another project's secrets); injected via tmpfs files by default, env vars only as the documented weaker option; never logged; write-only over API/MCP.
5. **Naming**: project/service names are DNS-1123 labels, enforced at parse time. Names compose into DNS; `description` carries free text.
6. **Workload hardening defaults**: capabilities dropped to the R13 baseline set (PRD v1.56; `capabilities = ["none"]` restores drop-ALL per service, and nothing a spec can declare reaches past the permitted set: `CAP_NET_RAW` and everything privilege-equivalent stays an explicit or refused grant), `no-new-privileges`, default seccomp, no `privileged` escape hatch in the v1 spec, per-alloc PID/IPC namespaces.
7. **Security gates are release gates**: `govulncheck`, `gosec`, `gitleaks`, `npm audit` must pass; OWASP Top 10 mapping (PRD §14) is reviewed before every release. Auth is deny-by-default on every API/WS/MCP route.
8. **Backpressure discipline**: log drains are non-blocking with drop counters; a full pipeline must never block a workload's `write()`.
9. **Derived state**: datapath state (pinned BPF maps, programs, links) is always rebuildable from the Store; never persist or restore anything under the bpffs pin root.
10. **No Kubernetes dependencies.** No client-go, no CRDs, no kube imports, ever.
11. **Resource isolation**: the control plane (`kanead`, `kanea-edge`, containerd, buildkitd) has a kernel-guaranteed memory floor via cgroups v2 `memory.min` (default 256 MiB, PRD §5.2.11 v1.62; it covers a control plane that does not build; a node running pipelines raises `--reserve`, buildkitd alone holds ~157 MiB) and `OOMScoreAdjust=-900`; all workloads run under one parent cgroup with `memory.max` = total RAM − reserve. That collective ceiling and the floor are the isolation; a *declared* per-alloc limit is enforced exactly, and an omitted one means the node's capacity (zero in the record = unbounded, PRD §6.2 R11, v1.58); never fill a default in. `pids.max` caps every alloc (256 by default; `resources.pids` declares a service's own value, PRD §6.2 R11 v1.89 - the cap's presence is fixed, only its value moves). Never use `mlock` on the Go control plane (`RLIMIT_MEMLOCK` + GC heap growth = crash risk); the guarantee comes from cgroup protection + OOM-killer policy.

## Tech stack

| Layer | Choice |
|---|---|
| Language | Go (latest stable), single static binary `kanea` |
| Runtime driver | `github.com/containerd/containerd/v2` client |
| Networking | Internal eBPF datapath (`internal/datapath`, PRD v1.36 §5.2.5): `github.com/cilium/ebpf` (standalone loader library, **never** `github.com/cilium/cilium`), `vishvananda/netlink`, `google/nftables`; programs committed as bpf2go output; kernel ≥ 5.10, no BTF/CO-RE requirement |
| Host components | Installed and supervised by Kanea at manifest-pinned versions (`internal/provision/components.json`): containerd, `runc`, rootless buildkit, `containerd-shim-wasmtime-v1` (runwasi, PRD v1.39). **Not host prerequisites** since PRD v1.30; cilium, etcd and the CNI plugins left the manifest with PRD v1.36 |
| State | `go.etcd.io/bbolt` behind a `Store` interface |
| Job specs & config | `github.com/hashicorp/hcl/v2` (HCL) |
| ACME | `github.com/go-acme/lego/v4` |
| Dashboard | React 18+, Vite, TypeScript strict, Tailwind CSS, **shadcn/ui**, TanStack Query, zod, embedded via `go:embed` |
| MCP | streamable HTTP transport on the API server + stdio via `kanea mcp` |
| Builds | rootless `buildkitd` + `buildctl` (spike ④ replaced kaniko) |

## Repository layout (created)

```
/cmd/kanea/            # binary entrypoint (agent, edge, mcp, CLI subcommands)
/internal/api/         # REST + WS server, auth middleware, audit
/internal/logging/     # slog foundation: JSON/text sinks, lumberjack rotation (used by everything)
/internal/store/       # Store interface + bbolt impl (+ future raft impl)
/internal/reconciler/  # convergence loop, scheduler interface
/internal/runtime/     # containerd driver
/internal/network/     # driver-neutral vocabulary (services, policies, attachments) + the embedded DNS
/internal/datapath/    # the eBPF datapath (PRD §5.2.5): programs (committed bpf2go output),
                       # pinned maps, veth/IPAM plumbing, policy + LB map writers
/internal/edge/        # kanea-edge: routing, TLS, middleware, published-port listeners;
                       # the projections kanead publishes to it
/internal/acme/        # ACME issuance + renewal, runs in kanead, never in the edge (§5.2.6)
/internal/certsource/  # where a certificate comes from (PRD §7.3): the Source seam, the
                       # self-signed CA, operator-provided grants, and the Publisher that
                       # merges them into the one bundle the edge reads. Also in kanead only
/internal/jobspec/     # HCL schema, parsing, validation (incl. R1-R27 rules)
/internal/scaling/     # metrics TS, evaluator
/internal/gitops/      # git sync, webhooks, kaniko runner
/internal/notify/      # notification channels, coalescing
/internal/backup/      # CDC replicator, snapshots, restore
/internal/provision/   # host components (PRD §5.2.12): the pinned manifest, verified
                       # fetch, traversal-safe extract, their units, offline bundles.
                       # components.json IS the §15.4 version matrix
/internal/mcp/         # MCP server (tools, resources, transports)
/dashboard/            # React SPA (own package.json; build → go:embed)
/spikes/               # throwaway validation code (own go.mod per spike)
/docs/                 # THREAT_MODEL.md, DR_RUNBOOK.md,
                       # VALIDATION.md (the real-hardware runs §21 needs)
/site/                 # the landing page (GitHub Pages): no build step, but no longer
                       # hand-written: index.html is a design-tool export, rendered at load by
                       # site/assets/dc-runtime.js over React. Edit it in the tool and re-export,
                       # never by hand: the {{ }} bindings and the component class in the
                       # inline text/x-dc script are its source. Assets are all local (fonts,
                       # React, screenshots as WebP); nothing is fetched from a CDN.
                       # style.css belongs to site/docs/index.html, NOT to the landing page;
                       # docs/ is still hand-written and links ../style.css, so deleting the
                       # stylesheet with the old landing page leaves the docs unstyled. It did.
                       # docs/ also links ../#install and expects that id to exist on the
                       # export; #homebrew stopped existing and the link had to move.
                       # TWO hand edits exist. (1) the MOBILE-PATCH block in index.html's
                       # head (mobile overrides + anchor offset + the deep-link re-jump
                       # script). (2) the em dashes are gone from every string in the
                       # export, title and meta description included: the project writes
                       # " - " instead, so change it in the tool too or a re-export
                       # brings them all back.
                       # Re-apply both after any tool re-export. Two traps the patch embodies: the
                       # runtime re-fetches the page and regexes for the template tag, so
                       # that tag's literal name must never appear in a comment; and the
                       # runtime re-serializes inline styles through React, so overrides
                       # match the rendered form (minmax(0px, …)), not the template's.
                       # install.sh there is COPIED from scripts/ by .github/workflows/pages.yml
                       # and gitignored: two copies drift, and the one that drifts is curled
/scripts/install.sh    # the installer; its asset names are a contract with .github/workflows/release.yml
```

## Commands

```bash
make help        # list all targets
make build       # build ./bin/kanea (version-stamped via ldflags)
make test        # go test ./... -race -count=1
make vet         # go vet ./...
make lint        # golangci-lint run (config: .golangci.yml)
make security    # gosec + govulncheck + gitleaks (AGENTS.md constraint #7)
make dashboard   # dashboard gates (lint, typecheck, test, build, audit)
make tools       # install dev tools
make check       # ALL gates, CI parity; must pass before any merge
```

CI (`.github/workflows/ci.yml`) runs the same gates on every PR: Go build/vet/test, golangci-lint, gosec, govulncheck, gitleaks, and dashboard checks (auto-skipped until `dashboard/` exists). Dependabot watches gomod, npm, and GitHub Actions.

## Releases

Tagging `v*` triggers `.github/workflows/release.yml` (it runs `make check` first, then
builds the archives, offline bundles and the keyless cosign signature). **The tag is the
last step, not the first**: before pushing it, walk this list, because these are the
things that drift silently and every one of them has drifted at least once:

1. **Docs describe what ships.** New user-visible behaviour since the last tag (a flag,
   a page, a login mechanism, a changed flow) is reflected in `README.md`,
   `site/index.html` (feature cards + quickstart), `site/docs/index.html` (the CLI and
   architecture references), and `docs/DR_RUNBOOK.md` where backup/restore behaviour
   moved. The quickstarts must show the *current* flow, not the flow the last release had.
2. **Version strings that name a release.** Two of them, and they do not look alike:
   `VERSION=vX.Y.Z` in `README.md`'s manual-install example, and a bare
   `<span>vX.Y.Z</span>` in `site/index.html`'s header, beside the theme toggle. Bump
   both to the tag being cut. (The README one shipped as `v0.1.0` for four releases
   before anyone noticed. The site one shipped stale in v0.18.0 because this list had
   just been edited to say the site carried no version: a grep for `VERSION=` finds the
   README's form and not the site's, and the conclusion drawn from that grep was written
   down as fact.) **Grep for the tag you are replacing, not for a pattern you expect:**
   `grep -rn "v0\.$((MINOR-1))\." README.md site/` catches both forms and anything else
   that named the last release.
3. **PRD version references.** `README.md`'s documentation table and this file's header
   both name the PRD version ("the north star (v1.NN)"). They must match `PRD.md`'s
   actual header. (README said v1.37 while the PRD was at v1.44.)
4. **`docs/DECISIONS.md`'s amendment bullets.** Every PRD amendment since the last tag
   has its guidance bullet in that file's "things a change is most likely to trip over"
   list: the list is only useful while it is current.
5. **The docs changes land on `main` before the tag**, as their own PR like anything
   else: the release workflow builds from the tagged commit, and `site/` is published
   from `main` by `pages.yml`, so a tag cut before the docs merge releases a binary whose
   website describes the previous one.

Version numbering: minor bump for features (`v0.4.0` → `v0.5.0`), patch for fixes.
Tags are annotated, in the style of the existing ones: a one-line title
(`Kanea vX.Y.Z: <the three-word story>`) and a short paragraph of what changed.

## Coding conventions

- **Go:** standard project layout; `goimports`-formatted; no global state (dependencies injected); errors wrapped with `fmt.Errorf("...: %w", err)`; context plumbed through all blocking calls; interfaces defined at the consumer, small and focused (`Store`, `Scheduler`, runtime/network drivers).
- **Logging:** everything logs through `log/slog` via `internal/logging`; components receive a `*slog.Logger` by injection. The stdlib `log` package is **depguard-banned**; direct `fmt.Print*` is **forbidigo-banned** (CLI output lives in `cmd/kanea` and goes through `fmt.Fprint*(os.Stdout/os.Stderr, …)`). Daemon file sinks rotate via lumberjack (bounded size/backups, gzip); workload logs follow PRD §17 (non-blocking drains, drop counters) and must never let a rotation stall a workload `write()`.
- **HCL:** all spec changes extend `internal/jobspec` schema with validation errors carrying file/line diagnostics; keep the PRD §6 examples valid.
- **Dashboard:** TypeScript strict; shadcn/ui components only (no new component lib); all user-controlled strings escaped (XSS, PRD §14 A03); live data via the single multiplexed WS.
- **Commits/PRs:** conventional commits (`feat:`, `fix:`, `chore:`, `docs:` …), one logical change per PR, `make check` green required. PR template enforces the binding constraints. **Merging and history:** plain merges only. Never rebase, never force-push, and never ask GitHub to rewrite a branch's commits, not as a merge strategy, not as a "clean-up", unless the user expressly says so for the case at hand.
- **Tests:** table-driven; reconciler and jobspec validation must have >80% coverage: they are the correctness core.

## Definition of done

Every change, not just a large one: OWASP §14 checks reviewed, `govulncheck` clean, tests green, docs updated. PRD §20 keeps the milestone record of how the platform was built; it is history now, and nothing in this file is scheduled against it.

## Key documents

| File | Content |
|---|---|
| `PRD.md` | Full product requirements (v1.96), the north star |
| `AGENTS.md` | This file |
| `docs/DECISIONS.md` | The decision record: status, trip-over bullets, refusals, spikes |
| `README.md` | The public front door: install, quickstart, requirements |
| `SECURITY.md` | How to report a vulnerability; what is in and out of scope |
| `LICENSE` | Apache-2.0 |
| `docs/THREAT_MODEL.md` | Threat model: boundaries, adversaries, §14 status as built |
| `docs/DR_RUNBOOK.md` | Disaster recovery procedure: read it before you need it |
| `docs/VALIDATION.md` | What has been exercised on real hardware, the §21 claims no test can stand in for |
