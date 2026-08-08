# Kanea — Product Requirements Document

| | |
|---|---|
| **Status** | Draft v1.26 |
| **Author** | Michael K. Essandoh (<michael@essandoh.dev>) |
| **Last updated** | 2026-08-08 |
| **Document type** | Product Requirements Document (PRD) |

> **v1.1 amendments** — incorporates the engineering review (performance/reliability/security): edge proxy split into `kanea-edge` (§5.2.6), Store-level CDC replication + master-key escrow (§15.3), upgrade & migration framework (§15.4), workload hardening defaults + CSRF/CSWSH/OIDC hardening (§14), ACME wildcard-default policy (§7.3), metrics pipeline redesign (§9.1), storm controls (§4.3, §11), realistic RTO targets (§15.3, §21), total-platform footprint budget (§21).

> **v1.2 amendments** — adds the **MCP server** (first-class AI-agent interface: §5.2.1, §13.3, §16.3, M9→M10 renumbering) and **edge middleware** on the `expose` block — IP restriction, rate limiting, header manipulation (§5.2.6, §6.1, §7.2, M3).

> **v1.3 amendments** — **image-only deployment** is explicit as the minimal, first-class path (G14, §6.2 R8, CLI quick-run) and adds **service references & dependencies**: `${service.<name>.host}` / `${service.<name>.port.*}` interpolation, `depends_on`, topological health-gated starts, cycle rejection (§6.2 R9–R10, §7.1.1, §4.3).

> **v1.26 amendments** — settles **§16.3's MCP scope**. Three of its tools name a subsystem that does not exist: `list_backups`, `create_backup` and `restore_backup` need `internal/backup`, which is M10. They are **marked M10 in the tool list and are not registered** — an agent that is offered a tool which can only ever fail is worse served than one that is not offered it, and `tools/list` is the only place it can find out. Four more named routes that had never been built (`GET /v1/projects`, `GET /v1/stats`, service restart, the §11 notification test); those are added rather than deferred, because the tools are the point. Records three decisions the section left open: **tool tiers are advertised as well as enforced**, and the advertisement fails closed; **a refusal is a tool result rather than a protocol error**, because the model is what has to react to it; and **no secret tools exist at all** — §16.3's safety rule says no tool returns a secret value, and the strongest reading of that is that an agent has no secrets verb whatsoever, not even a write. Also states that the **restart primitive is a spec change**, not a second path to the runtime: it bumps a generation that participates in the spec hash, so it rolls through the update policy the same way a deploy does — the same rule §9.2 sets for the autoscaler, which writes one number and lets the reconciler converge.

> **v1.25 amendments** — gives the **`update` block semantics** (§4.3, §6.1). The block has been in the spec since v1.0 and in the parser since M1, and it went no further: nothing carried it onto the desired state, and the planner returned "no action" for every *running* alloc regardless of what was declared. The consequence was not a missing feature but a wrong one — **`kanea run` against a service that was already up did nothing at all**. A new image, a changed environment variable, a raised memory limit: all accepted, all recorded as desired state, none of them ever reaching a container until it happened to crash. M7's "push → build → rolling deploy" ended at the deploy. This amendment records the model that closes it: an alloc carries a **spec hash** of the parts of its service that are baked in at creation (image, command, env, resources, volumes, ports, capabilities, rootfs — and *only* those, so raising a replica ceiling or editing a health check does not roll a service nobody asked to disturb), and a running alloc whose hash no longer matches what is declared is replaced. `max_parallel` **bounds allocs that are down, not replacements in flight**: anything already unavailable — starting, unhealthy, or too newly replaced to trust — spends the budget first, so a deploy that starts going wrong stops instead of walking through every replica. `min_healthy` (default 10 s) applies to allocs *this deploy has already replaced*, not to every young alloc. A changed spec **resets the restart budget**, because deploying the fix is how a crash loop is resolved and an alloc that inherited the failed image's exhausted attempts could not be fixed at all. `strategy` is a closed set — `rolling` (default) and `replace`; canary stays post-v1 (§19.3) and is now *rejected* at parse time rather than silently rolling.

> **v1.24 amendments** — corrects the **§6.1 `notifications` block**, which had the same defect §10's blocks had twice before: it named credentials it gave no field for, and inlined one it should have referenced. The sketch said "bot token from secrets" while the schema had nowhere to put the reference (`telegram.token_ref` now exists), and its `webhook { url = "https://hooks.slack.com/services/…" }` example **inlined a Slack incoming-webhook URL — which is a credential in path form**: anyone holding it can post as the app. Slack is now its own block taking `url_ref`, and there is no field to inline one into. Adds the channels §11 always listed but the schema never had — `slack`, `ntfy`, `smtp` — plus a `severity` floor that composes with `on` as an AND, so `on = ["*"]` with `severity = "warning"` means "everything that matters", which is the configuration most operators actually want. **An empty `on` is a spec error**, not a permissive default: a channel nobody has told what to send is silent, and a silent notification channel is indistinguishable from a system with nothing to report. Patterns are validated against the event vocabulary at parse time for the same reason. Also records that **notification targets are https-only with private, loopback and link-local destinations refused** (§14 A10) — checked at *dial* time rather than on the hostname, because a name that resolves publicly when it is validated can resolve to 127.0.0.1 when it is connected to.

> **v1.23 amendments** — adds **`build.registry_auth_ref`** to the §6.1 build block and states the **repository/project boundary** in §10.1. §10.2 required the registry push credential to come from the secrets store as a materialised `config.json` but named no field for it, so there was no way to write down which secret that is; the field is scoped by **R5** like every other reference. §10.1 now says explicitly that **a repository speaks for its own project and no other**: a synced spec that declares services in another project is refused, because otherwise write access to one project's git source is write access to every service on the node — the same cross-project escalation R5 blocks for secrets, arriving through a different door. Also records that **`${GIT_SHA_SHORT}` and its siblings survive parsing as literal references** when nobody supplies them: R2 lists them as built-ins, but their value only exists once a commit is checked out, which is the pipeline runner — long after the file is parsed. Without that, the PRD's own §6.1 example (`tag = "${GIT_SHA_SHORT}"`) failed to parse in `kanea plan`, `kanea run` and every sync.

> **v1.22 amendments** — corrects the **§6.1 example's `git.auth_ref`**, which read `secret:git/github-deploy-key` and contradicted **R5** — the rule that says a reference names the declaring project's scope or `shared/`, and that "git, registry, storage, and notification credentials follow the same scoping". `git/` is neither; under R5's semantics it names a project called `git`. The example is now `secret:shop/…`, and M7's parse-time validation enforces R5 on project-level git credentials, so a spec that copied the old example fails `kanea plan` with the reason rather than failing sixty seconds later inside a poll loop nobody is watching. Also adds `git.webhook_secret_ref`, `git.poll_interval` and `git.require_approval` to the block §6.1 sketches: §10.1 requires all three and the schema had none of them. The webhook secret is deliberately a **separate** reference from `auth_ref` — one lets Kanea read the repository, the other lets the repository tell Kanea something, and reusing a deploy key as a webhook secret would put a credential that can read source into a header on every push.

> **v1.21 amendments** — restates the **scale-decision latency budget** (§21, §9.2) from 15 s to **20 s from a sustained breach**, because 15 s was not reachable without giving up the guardrail that makes the number trustworthy. The pipeline is: containerd and the edge are scraped every 5 s; a rule averages over a window before acting; the evaluator ticks. The averaging window exists so a single anomalous scrape cannot move a service, and three samples is the smallest window that does that — which at 5 s resolution is 15 s, plus one 5 s evaluation tick. **Reacting faster means reacting to one or two samples**, which is how an autoscaler chases noise instead of load, and a service that flaps between 2 and 8 replicas every minute is worse than one that reacts five seconds later. The 20 s is a ceiling on a *sustained* breach; a large spike crosses its target sooner, because the average moves faster the further the load is from the target. §9.2's guardrails are now stated with their defaults: 10% tolerance band, 2×/0.5× step caps, 5-minute scale-down stabilization, 2-minute cooldown.

> **v1.20 amendments** — settles **which DNS-01 providers ship** (§7.3) and **drops TLS-ALPN-01 from M5**. v1.1 said "lego (supports many DNS providers)", and lego does — but importing its provider catalogue links every vendor SDK it knows into a binary whose whole premise is being one small file, and even its `rfc2136` provider drags a Kerberos stack in for the GSS-TSIG case Kanea does not use. So DNS-01 ships as a **direct RFC 2136 solver**, TSIG-signed, written against `miekg/dns` — which Kanea already carries for its own resolver (§7.1). That covers BIND, Knot and PowerDNS with no new dependency. **Hosted providers (Cloudflare, Route 53, …) are a curated list**, added one at a time with the weight of each SDK weighed against the operators it serves — not a catalogue import. Unsigned updates are refused outright: a dynamic update nobody authenticates is a passing ACME challenge for every name in the zone. **TLS-ALPN-01 is deferred past M5**, on the reasoning §7.3 already gives for it: it exists for a node that does not own port 80, and Kanea's edge does. It buys nothing here and would be a second challenge path to keep correct.

> **v1.19 amendments** — separates **GitHub from OIDC** (§13.2). v1.1 listed "generic OIDC plus presets for GitHub and GitLab OAuth" under one bullet whose guarantees are ID-token guarantees: signature, issuer, audience, expiry, nonce. GitLab is an OIDC provider and gets all of them. **GitHub is not** — its OAuth issues no ID token, so an identity from it can only be a `GET /user` call carrying an access token, which is a different trust argument wearing the same word. Shipping it as a "preset" would make two unlike things look alike in the config file, which is where that difference stops being visible. Generic OIDC ships in M5; GitHub gets its own implementation and its own review.

> **v1.18 amendments** — moves **accounts out of the config file and into the Store** (§13.1, §13.2, §15.1). v1.1's basic-auth stanza had `kanea user add` edit `kanea.hcl` and the daemon read accounts at start; that makes adding a user a config edit plus a reload, makes revoking one a race between the editor and the reader, and gives credentials a second home outside the single writer that already owns state — which then has to be reconciled during a restore (§15.3). Users now live in the `kv` bucket alongside tokens and sessions, are managed at runtime over the authenticated API (`kanea user add|list|delete`), and replicate and restore with everything else. What the config still decides is what config should decide: **where the API listens** (`bind.api_addr`) and **who the OIDC provider is** (§13.2) — settings, not identities. `kanea init` still creates the first admin, but by calling the same API rather than by writing a stanza. The §13.1 rule is unchanged and now enforced in the middleware rather than at startup: with no account configured, the only way in is the local unix socket, and a network listener is refused rather than opened unauthenticated.

> **v1.17 amendments** — records the **ACME delivery order** (§7.3, §20 M3/M5). **HTTP-01 ships in M3**; **DNS-01 and the wildcard-by-default policy move to M5**, because a DNS provider credential is a `secret:` reference (R3, R5) and the secrets store does not exist until then — implementing it earlier would mean inventing a second, unscoped way to hold a credential. **TLS-ALPN-01 moves with it**: it exists for a node that does not own port 80, and Kanea's edge does. The consequence is stated rather than hidden: until M5 a node past the ~20-service threshold keeps issuing per-service certificates and warns on every pass, instead of quietly walking into a Let's Encrypt rate limit.

> **v1.16 amendments** — settles **who runs ACME and how certificates reach the edge** (§5.2.6, §7.3). v1.15 put routes in a world-readable projection, which is right for a route table and wrong for a private key, so certificates go in a **sibling file with restricted permissions** (`/run/kanea-edge/certs.json`, 0640) rather than being squeezed into one file at one compromise permission. **`kanead` owns ACME**, not the edge: issuance writes to the `certs` bucket, renewal is a control-plane timer, and failures are events — all things the edge deliberately cannot do, since it holds no Store handle and no write access (that is the §5.2.6 property, not an accident to work around). The edge's part is serving what it is given: **HTTP-01** responses and the **TLS-ALPN-01** certificate arrive through the same projection. Because publication and the edge's poll are not synchronous, `kanead` **self-checks the challenge through the edge before asking the CA to validate** — a validation that fails because the edge had not reloaded yet burns a Let's Encrypt failed-validation slot, which is a rate limit that takes an hour to clear. Also fixes what the edge does for a host it has no certificate for: the HTTP→HTTPS redirect applies **only to hosts it can actually terminate TLS for**, because redirecting the others turns "no certificate yet" into "unreachable" and takes HTTP-01 down with it.

> **v1.15 amendments** — **specifies how `kanea-edge` reads state**, which §5.2.6 has described since v1.1 as "reads its route table + certs from the Store" without saying by what mechanism. It cannot read the Store: bbolt takes a whole-file lock, so a second process opening `state.db` — even read-only — blocks until `kanead` exits (measured: a read-only open times out rather than returning stale data). The Store remains the source of truth and `kanead` remains its only opener; it **projects** the routes, certificates and ACME challenge responses the edge needs into a node-local **edge snapshot** (`/run/kanea-edge/routes.json`, written temp-then-`rename(2)`, the same discipline as the Cilium file interfaces in §5.2.5), which the edge polls and serves from. It is deliberately **not** under `data_dir`: that directory is 0750 and holds the database, so an unprivileged edge user cannot even traverse into it, and widening it to hand over one file would be the wrong trade — this is derived state rebuilt from the Store on every start (constraint #9), which is what `/run` is for. The projection direction is what makes the §5.2.6 promise real: the edge holds no Store handle, needs no write access, and keeps serving the last snapshot for as long as `kanead` is absent — a control-plane outage cannot drop public traffic, and it also means the edge process needs nothing but read access to one file, which is what lets it run as its own unprivileged user. Also fixes what v1 host-based routing does when a service declares several ports (§7.2) and adds **R16**: the `expose` block is validated at `plan`, so the fail-closed promise in §7.2.1 has a rule to point at.

> **v1.14 amendments** — adds the **`host` storage driver** (§8, §15.1, §6.2 **R15**): a volume backed by a directory the operator already has, rather than one Kanea derives under `data_dir/volumes/`. It is deliberately a **separate driver rather than an option on `local`**, so it is visible in a spec review, and it is **inert unless the operator opts in**: the permitted parent directories are listed in the *server* config (`storage.allowed_host_paths`), never in a job spec, and the default is an empty list — no host path mounts at all. That split is the entire security argument. An unrestricted host mount is `privileged` by another name (`/`, `/etc`, the containerd socket) and would make the §14 A05 hardening defaults irrelevant, so the boundary is set by the person who owns the node and merely *referenced* by the person who writes the spec. Paths are resolved through symlinks before the allowlist is checked, because `/srv/data/link → /etc` would otherwise walk straight out of it, and a host directory must already exist — creating one on demand is how a typo becomes a silently empty volume.

> **v1.13 amendments** — **specifies `network { policy { … } }`**, which §7.1 has referenced since v1.0 without ever defining it (§6.1, §6.2 **R14**, §7.1). A service names the peers allowed to reach it as `allow_from = ["<project>/<service>"]`, and Kanea emits one additional CCNP per service alongside the project isolation policy — Cilium ingress rules are a union, so the effect is "intra-project, or the edge, or these named peers". This makes **cross-project traffic possible in v1** by explicit policy edge, which the default-deny project boundary otherwise forbids outright; cross-project *service references* (`${service.…}` interpolation and dependency ordering) remain v1.1 per R9 and §19.3, so the peer's name is written as the literal `<service>.<project>.kanea` that internal DNS already resolves. Least privilege is the default: entries are per-service, there is no whole-project wildcard, and an unknown peer is a parse error rather than a silently ineffective rule.

> **v1.12 amendments** — makes the §6.1 example self-contained by declaring the `local-ssd` and `s3-media` storage resources its volume blocks reference. §8 allows storage to be declared at server level *or* project level; until the server config lands (§15.1), project level is the only source, and a volume referencing an undeclared resource is now a parse error rather than a mount failure at alloc start.

> **v1.11 amendments** — adds the two `task` fields M1 showed were missing: **`command`** (argument array overriding the image entrypoint, R12) and **`capabilities`** (R13) — the explicit allowlist §14 A05 always promised but §6 had no field for. Without it the hardening defaults are unusable with stock images: nginx cannot `chown` its cache dir and redis cannot drop to its own user, so both crash-loop. Requests are bounded by a permitted set that excludes privilege-equivalent capabilities, so the allowlist cannot become the `privileged` escape hatch v1 refuses to have (§6.1, §6.2 R12–R13, §14 A05).

> **v1.10 amendments** — corrects the §6.1 example so it actually parses as HCL v2 (single-line blocks may hold at most one argument and no nested block, so `resources { cpu = 500  memory = 256 }`, `network { port "http" { … } }` and `expose { tls { … } }` were invalid) and adds the `spec_version = 1` that R6 requires. No semantic change; `internal/jobspec` now parses this example verbatim as a regression test, per AGENTS.md's "keep the PRD §6 examples valid".

> **v1.9 amendments** — **BuildKit is the only build driver** (buildah is no longer shipped as a fallback — one builder to pin and patch; the runner keeps an internal driver seam and R4 records buildah as a measured drop-in), and **`Containerfile` is accepted alongside `Dockerfile`**, taking precedence when both exist, with `build.dockerfile` now an optional override (§6.1, §10.2, §22 R4, §23.2). Both validated in M0 spike ④ (11/11 on the daemon path).

> **v1.8 amendments** — **BuildKit replaces kaniko as the build driver**, run as a **rootless `buildkitd` host service** (validated in M0 spike ④, 9/9): unprivileged and non-root end to end, 546 ms warm builds, at the cost of a fourth supervised daemon (~157 MiB in the §21 reserve), collective rather than per-build resource caps, and a second content store to GC. buildah becomes the no-daemon fallback driver; kaniko is removed (§5.2.4, §10.2, §21, §22 R4, §23.2).

> **v1.7 amendments** — records the **M0 spike ④ findings** (image builds as containerd tasks, [report](./spikes/kaniko-build/REPORT.md)): **buildah replaces kaniko as the default build driver** (kaniko's upstream is archived; it stays as a pinned fallback), **BuildKit is rejected** for v1 (requires a privileged container), and build tasks are recorded as an explicit exception to the workload hardening defaults — they run at containerd's default capability set, never privileged (§10.2, §22 R4, §23.2). M0 is complete: all four spikes GO.

> **v1.6 amendments** — records the **M0 spike ③ findings** (S3 FUSE drivers, [report](./spikes/s3-fuse/REPORT.md)): the `s3` volume driver is decided — **mountpoint-s3** by default (read-mostly) with **s3fs** as the opt-in read-write driver, **goofys dropped** (unmaintained, no arm64) and `rclone mount` rejected as a built-in (uploads land ~6 s after `close()`); adds the non-POSIX semantics caveats (no `truncate` anywhere — silently ignored by s3fs), the mandatory supervise-and-remount mount helper, `user_allow_other` as an `init` prerequisite, and the per-file round-trip cost of S3 volumes (§8, §21).

> **v1.5 amendments** — records the **M0 spike ① findings** (standalone Cilium, [report](./spikes/cilium-standalone/REPORT.md)) and corrects every interface assumption they invalidated: labels via `PATCH /v1/endpoint` before task start (CNI args cannot carry them), service LB via `--lb-state-file` and network policy via `--static-cnp-path` (both REST APIs removed in Cilium 1.18), `project` published as a k8s namespace label, malformed policy files fatal to the agent, `cilium-agent` floor raised to **≥ 1.18** and `github.com/cilium/cilium` dropped as a Go dependency (§5.2.5, §7.1, §15.1, §21, §22 R1, §23.2).

> **v1.4 amendments** — adds **node resource isolation** (§5.2.11): a kernel-guaranteed memory floor for the control plane (cgroups v2 `memory.min`, default 1 GiB) and a hard collective ceiling for workloads, mandatory per-alloc limits with defaults (§6.2 R11), OOM-killer policy, admission control against a workload budget (§15.1), and systemd process sandboxing for both units (§5.2.6, §5.2.11). Literal `mlock` is evaluated and explicitly rejected for the Go control plane (§5.2.11).

---

## 1. Executive Summary

**Kanea** is a lightweight, single-binary container orchestration platform written in **Go**. It combines the operational simplicity of HashiCorp Nomad with a modern eBPF networking and load-balancing layer powered by **Cilium**, running workloads on **containerd** — with **no Kubernetes dependency anywhere in the stack**.

Kanea targets the gap between "SSH into a box and run docker compose" and "operate a full Kubernetes cluster": a platform a single operator can install in minutes, understand end-to-end, and use to run **hundreds of services** with automatic TLS, service discovery, load balancing, autoscaling, GitOps-driven deployments, and a real-time web dashboard.

**One-liner:** *Nomad's simplicity, eBPF's power, one binary.*

### Positioning

| | Kubernetes | Nomad | **Kanea** |
|---|---|---|---|
| Operational complexity | Very high | Medium | **Low** |
| Networking | CNI sprawl | Bridge/CNI | **Cilium eBPF, built-in** |
| Binaries to run a node | ~7+ | 1 | **1** |
| K8s dependency | — | None | **None** |
| Dashboard | Add-on | Add-on (UI builtin, but heavy) | **Built-in, lightweight** |
| TLS automation | cert-manager + ingress | External (fabio/traefik) | **Built-in Let's Encrypt** |
| Clustering (v1) | Yes | Yes | **Single node (cluster-ready design)** |

---

## 2. Goals & Non-Goals

### 2.1 Goals (v1)

- **G1** — Single static Go binary (`kanea`) runs a complete node: control plane (`kanea agent`), runtime driver, networking driver, dashboard — plus ingress as a second supervised process from the same binary (`kanea edge`, §5.2.6).
- **G2** — Install-to-first-service in under 5 minutes on a fresh Linux host (`kanea init` → `kanea agent` → `kanea run app.hcl`).
- **G3** — Run hundreds of services on a single node with sub-second scheduling decisions.
- **G4** — Projects and services as first-class concepts; declarative HCL job specifications.
- **G5** — Zero-config networking: per-service IPs, internal DNS, eBPF load balancing, automatic external FQDNs.
- **G6** — Automatic Let's Encrypt certificates for every exposed service.
- **G7** — Real-time web dashboard: server stats, service stats, log streaming — built with shadcn/ui.
- **G8** — Authentication (basic auth and/or OAuth2/OIDC) configured at first install.
- **G9** — eBPF-metrics-driven autoscaling of services.
- **G10** — GitOps: load projects from Git (GitHub/GitLab/generic), build images with BuildKit (rootless), deploy on commit.
- **G11** — Notifications (webhooks, Telegram, Slack/Discord, SMTP, ntfy).
- **G12** — Durable state: continuous replication to S3-compatible storage, backup & restore, documented DR.
- **G13** — OWASP Top 10 adherence as a hard, reviewed requirement in every milestone.
- **G14** — Zero-friction deployment: a bare image reference is a valid service (no Git required); service-to-service wiring via first-class `${service.*}` references.

### 2.2 Non-Goals (v1)

- **NG1** — Multi-node clustering / multi-host scheduling (architecture must not preclude it; see §18).
- **NG2** — Kubernetes API compatibility, CRDs, Helm charts.
- **NG3** — CSI plugin ecosystem (storage covered by built-in S3/NFS/SMB drivers only).
- **NG4** — Batch/system scheduler types beyond simple `runonce` tasks (pipeline builds use these internally).
- **NG5** — Multi-tenant RBAC beyond admin/viewer roles.
- **NG6** — Windows or macOS hosts (Linux only; macOS CLI supported).
- **NG7** — Embedded container registry (external registries only in v1).

---

## 3. Personas & Use Cases

| Persona | Description | Key needs |
|---|---|---|
| **Solo operator / homelabber** | Runs 10–50 self-hosted services on 1–2 boxes | Simple install, auto TLS, dashboard, notifications |
| **Small team platform owner** | Provides internal platform for a dev team | GitOps flow, projects, OAuth login, audit log |
| **Agency / freelancer** | Hosts many client sites/services on one VPS | Low overhead per service, auto FQDNs, LE certs, backups |

**Canonical use cases:**

1. *UC-1:* Deploy a web service with a public HTTPS URL in one command.
2. *UC-2:* Push to GitHub → image built with BuildKit → rolling deploy → Telegram notification.
3. *UC-3:* Service autoscales 2→8 replicas under load, driven by eBPF request-rate metrics.
4. *UC-4:* Node dies; operator restores full platform state from S3 onto a fresh VPS in <15 min.
5. *UC-5:* Mount an S3 bucket / NFS export / SMB share into a service as a volume.

---

## 4. Core Concepts

Kanea borrows deliberately from Nomad and Kubernetes, keeping the smallest set of concepts that covers the use cases.

### 4.1 Concept map

| Kanea | Nomad analogue | K8s analogue | Description |
|---|---|---|---|
| **Node / Agent** | Client+Server agent | Node + control plane | One machine running `kanea agent` |
| **Project** | Namespace | Namespace | Named group of services; isolation & discovery boundary |
| **Service** | Job + Group | Deployment + Service | Declarative long-running workload, `count` replicas |
| **Task** | Task | Container | One container within a service (**v1: exactly one task per service**; multi-task/sidecars v1.1) |
| **Allocation (alloc)** | Allocation | Pod | A single running instance of a service |
| **Job spec** | Job spec (HCL) | Manifests | HCL file declaring projects/services |
| **Pipeline** | — | Tekton/CI job | Build run (BuildKit) producing an image |
| **Storage** | CSI volume | PV/PVC | Named volume backend (S3/NFS/SMB/local) |

### 4.2 Naming rules (hard requirement)

- Project and service **names MUST be DNS-1123 labels**: lowercase alphanumeric and `-`, start/end with alphanumeric, ≤ 63 chars.
- Enforced at parse/validation time (also an injection defense — see §14, A03).
- Rationale: names are composed into DNS names automatically (`service.project.kanea`, `service.project.<base_domain>`).
- **`description`** is a free-form string (≤ 512 chars) shown in the dashboard; carries the human-readable details the name cannot.

### 4.3 Lifecycle model

```
Job spec (HCL) ──parse/validate──▶ Desired state (Store)
                                        │
                                   Reconciler loop
                                        │
                        ┌───────────────┼────────────────┐
                        ▼               ▼                ▼
                    containerd      Cilium agent     Edge proxy
                   (tasks/imgs)  (endpoints/LB)    (routes/TLS)
                        │               │                │
                        └───────────────┴────────────────┘
                                        ▼
                            Actual state / events / metrics
```

- A **reconciler** continuously converges actual state to desired state (k8s controller-style), rather than one-shot placement. Crashed allocs are restarted per restart policy; drift (manual container deletion, Cilium endpoint loss) is corrected automatically.
- **Restart policies:** `always` (default), `on-failure` (with backoff), `never`.
- **Update strategies:** `rolling` (default, `max_parallel`, health-gated), `replace`, `canary` (manual promotion, v1.1+).
- **Storm control:** per-service restart rate caps plus a **global circuit breaker** (pause rollouts/scale actions when node-wide failure rates spike) protect against cascading restarts; breaker trips emit an event + notification.
- **Dependency order:** the reconciler starts services in topological order of their reference/`depends_on` edges — dependencies must be healthy before dependents start (§7.1.1).

---

## 5. System Architecture

### 5.1 High-level diagram

```
                            ┌───────────────────── kanead (control-plane binary) ─────────────────────┐
                            │                                                                        │
  Browser ──HTTPS──▶ ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌─────────────┐  │
  CLI ──────HTTPS──▶ │  API server  │   │  Dashboard    │   │  Reconciler /    │   │ Autoscaler  │  │
  Git webhooks ────▶ │  (REST + WS) │   │  (shadcn/ui   │   │  scheduler       │   │ (eBPF/L7    │  │
                     │  auth, audit │   │   SPA, embed) │   │                  │   │  metrics)   │  │
                     └──────┬───────┘   └───────────────┘   └────────┬─────────┘   └──────┬──────┘  │
                            │                                        │                    │         │
                     ┌──────┴────────────────────────────────────────┴────────────────────┴──────┐  │
                     │                     Store (BoltDB, Raft-ready interface)                   │  │
                     └──────┬─────────────────────────────────────────────────────────────────────┘  │
                            │                                                                        │
   ┌────────────────┬───────┴──────────┬────────────────────┬─────────────────────────────────────┐ │
   │ Runtime driver │ Network driver   │ GitOps syncer +    │ Notifier                            │ │
   │ (containerd)   │ (Cilium agent    │ pipeline runner    │ (webhooks/TG/Slack/SMTP/ntfy)       │ │
   │                │  API + CNI)      │ (Git + BuildKit)   │                                     │ │
   └───────┬────────┴────────┬─────────┴─────────┬──────────┴─────────────────────────────────────┘ │
           │                 │                   │                                                  │
           └─────────────────┴───────────────────┴──────────────────────────────────────────────────┘
                             │ State replicator / backup manager ──▶ S3-compatible storage

   ┌─── kanea-edge (separate supervised process; reads routes + certs from Store) ───┐
   │  Edge ingress proxy: L7 routing, TLS termination, LE certs, L7 metrics          │ ◀── public :80/:443
   └─────────────────────────────────────────────────────────────────────────────────┘

   External:   containerd daemon │ cilium-agent daemon │ Linux kernel (eBPF, cgroups v2, netfilter)
```

### 5.2 Components

#### 5.2.1 API server
- HTTPS REST + WebSocket (gorilla/websocket or coder/websocket), JSON.
- Serves: management API, dashboard static assets (`go:embed`), ACME HTTP-01 challenges, Git webhooks.
- Every route except `/login`, `/.well-known/acme-challenge/*`, and `/healthz` requires authentication (§13).
- Global and per-endpoint **rate limits** (strictest buckets on unauthenticated endpoints), request body-size limits, and per-user WS connection caps (§14, A07).
- Hosts the **MCP (Model Context Protocol) server** (§16.3) so AI agents operate the platform through the same auth/authorization/audit pipeline — no side channels.

#### 5.2.2 Reconciler / scheduler
- Single-node v1: placement is trivial (this node), so the reconciler focuses on **convergence**: desired count, health-gated rollouts, restart backoff, drift repair.
- Scheduling abstraction (`Scheduler` interface) keeps the door open to multi-node placement later (§18).
- Store reads are **bounded and paginated** (long bbolt read transactions block the single writer) and backed by an in-memory desired-state cache, keeping the reconcile loop within budget at target scale (§21).

#### 5.2.3 Store
- **BoltDB** (bbolt) embedded KV, buckets: `projects`, `services`, `allocs`, `events`, `certs`, `secrets`, `pipelines`, `audit`, `kv`.
- All access behind a `Store` interface with explicit transaction semantics — a Raft-backed implementation (hashicorp/raft + FSM) can replace it for clustering without touching call sites.
- Single-writer model: all mutations serialize — fine at v1 scale, but **metrics and logs never go through the Store** (in-memory TS + file pipelines only, §9/§17).
- bbolt files never shrink in place → **scheduled compaction** (copy-based) keeps the DB — and the backups derived from it — from growing monotonically.

#### 5.2.4 Runtime driver (containerd)
- Talks to containerd over its socket via the official Go client (`github.com/containerd/containerd/v2/client`).
- One containerd **namespace per project** (`kanea-<project>`) → free isolation of images/containers per project.
- Responsibilities: image pull (with auth from secrets store; digest pinning supported), container/task lifecycle, per-alloc network namespace setup (CNI call), cgroup metrics sampling, stdout/stderr capture (§17).
- Kanea requires containerd ≥ 1.7; `kanea init` can install/configure it.
- **Node disk hygiene:** image GC (keep-last-N in use), **build cache caps across both content stores** — containerd's and the rootless `buildkitd` user's `$HOME/.local/share/buildkit` (§10.2) — per-service log caps (§17); disk watermark alerts at 80%/90% (event + notification). One disk holds images, logs, state, and volumes — pressure must never surprise the control plane.

#### 5.2.5 Network driver (Cilium standalone)
- Cilium agent runs **without Kubernetes** (`--enable-k8s=false`), backed by an embedded/single-node etcd kvstore (`--identity-allocation-mode=kvstore`, `--ipv4-range=<node CIDR>`), CNI config at `/etc/cni/net.d/05-cilium.conflist`. `--kube-proxy-replacement=true` (socket LB, required for `kanea-edge` → service VIP) and `--policy-default-local-cluster=false` are mandatory.
- **Per-alloc attach order (M0-validated, order is load-bearing):** pre-create netns → CNI `ADD` → **`PATCH /v1/endpoint/container-id:<alloc>`** with the identity labels → task start. The Cilium CNI plugin cannot carry labels (it hardcodes an empty label set and forwards only `K8S_POD_*` args), and an endpoint without labels holds `reserved:init`, which is **policy-enforced deny in both directions** — so labels must land before the workload's first instruction. The label PATCH returns 5xx while the endpoint is regenerating and must be retried with bounded backoff.
- **Identity labels** are `kanea=true`, `project=<p>`, `service=<s>` **plus `k8s:io.kubernetes.pod.namespace=<project>`**: Cilium rewrites every peer selector to require that namespace label, so without it every policy rule matches nothing and silently denies. **Project ≡ namespace** in Cilium's policy semantics.
- Service LB: Kanea programs **Cilium services** through the agent's **`--lb-state-file`** (a watched JSON file of Kubernetes-*shaped* Service + EndpointSlice objects — schema only, no API server, no CRDs): frontend ClusterIP per service, backends = healthy alloc IPs → eBPF load balancing (Maglev), no userspace proxy in the data path. The writable service REST API was removed in Cilium 1.18.
- Network policies: default per-project isolation policy (allow intra-project + ingress from edge proxy + egress), delivered as CNP/CCNP YAML files in the agent's **`--static-cnp-path`** directory; opt-in custom rules per service. The policy REST API was removed in Cilium 1.18. **A malformed file in that directory is fatal to the agent (crash loop on restart)** — Kanea therefore validates every generated policy before writing, owns the directory exclusively, and never lets a bad policy reach it. Bad policy must never lock out the host endpoints.
- **Both file interfaces are written temp-then-`rename(2)`** (the agent watches them with fsnotify; a partially written file must never be observable). Temp names must not carry the watched extension.
- **Cilium state is derived state:** Kanea's Store is the source of truth — on restore, the kvstore is wiped and rebuilt from desired state. etcd files are never backed up or restored (§15.3).
- **Mass operations** (node reboot, restore): bounded-concurrency endpoint creation with tuned `--api-rate-limit endpoint-create`, exposed services prioritized; LB backend updates batched by rewriting the whole `--lb-state-file` (a full rewrite *is* the batching primitive; `--lb-state-file-interval` is the settle window).
- Hubble (opt-in) is configured via agent flags (`--hubble-metrics`, `--hubble-dynamic-metrics-config-path`) — no k8s ConfigMap required. `--hubble-metrics` takes a **space-separated list in a single value**; a comma-separated or repeated flag is silently ignored, leaving a metrics endpoint that serves 200 OK with no flow data (a `kanea doctor` check).
- **This was the #1 technical risk → validated in Milestone M0** ([spike ① report](./spikes/cilium-standalone/REPORT.md), 25/25 checks on Cilium 1.19.6): GO, with the interface corrections recorded above.

#### 5.2.6 Edge ingress proxy (`kanea-edge` — separate process)
- Lightweight L7 reverse proxy (Go `httputil.ReverseProxy` core) — standalone Cilium has no Gateway API without k8s, so Kanea owns north-south HTTP(S).
- **Runs as its own supervised process** (same binary, `kanea edge`; separate systemd unit, `Restart=always`): a `kanead` crash/restart/upgrade never interrupts public traffic, and an edge OOM never takes down the reconciler. The unit runs as a dedicated `kanea-edge` user with only `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, and sits in `kanea.slice` (§5.2.11).
- **How it gets its state — the edge snapshot.** The Store is the source of truth, but the edge does not open it: bbolt locks the whole file, so a second process opening `state.db` even read-only blocks until `kanead` exits rather than returning stale data. Instead `kanead` **projects** what the edge needs — routes (host → service frontend), certificates, and pending ACME challenge responses — into `/run/kanea-edge/routes.json`, written temp-then-`rename(2)` so a partially written file is never observable (§5.2.5's discipline). The edge polls that file and reloads on change; the projection carries the Store index it was built from, so a reload can be logged and a stale snapshot recognised.
  - **One direction only.** The edge never writes state. That is what lets it run as an unprivileged user with no Store access, and it means a compromised edge — the process that terminates untrusted public traffic — cannot mutate the platform (§14, A01). It is also why `kanead` and not the edge runs ACME (§7.3): obtaining a certificate means writing one.
  - **Two files, two permissions.** Routes (`routes.json`, 0644) carry nothing secret — the domains are in public DNS. Certificates (`certs.json`, 0640) carry private keys. They are separate files precisely so neither has to compromise: the route table stays readable by whatever user the edge runs as, and the key does not.
  - **A missing or stale snapshot is not an outage.** The edge keeps serving the last table it loaded for as long as `kanead` is absent, and starts with an empty table (every request 404) rather than refusing to start if the file does not exist yet. "The control plane is down" must never become "the site is down" (§21).
- Routes `Host: service.project.<base_domain>` → service's Cilium frontend IP; WebSocket and gRPC supported.
- Terminates TLS with Let's Encrypt certs (§7); redirects HTTP→HTTPS; security headers injected (§14, A05).
- **Hardening (required, not optional):** `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout`/`MaxHeaderBytes` (slowloris), per-route upstream timeouts, bounded connection pools, flush intervals for streaming, client-supplied `X-Forwarded-*` stripped, unknown `Host` → 404 (also DNS-rebinding defense for the co-hosted API), `GOMEMLIMIT` set.
- **Edge middleware chain (per service, from the `expose` block — §6.1, §7.2):** Host match → IP allow/deny → rate limit → header transforms → upstream proxy. Middleware config is validated at `kanea plan` time — fail-closed, never silently ignored at runtime.
- **Primary source of per-service L7 request metrics for exposed services** (rps, latency percentiles) — it's already in the request path at zero extra data-plane cost; Hubble/eBPF covers east-west (§9).

#### 5.2.7 GitOps syncer + pipeline runner — see §10
#### 5.2.8 Autoscaler — see §9
#### 5.2.9 Notifier — see §11
#### 5.2.10 State replicator / backup manager — see §15.3

#### 5.2.11 Resource isolation (cgroups v2)

The control plane must survive anything workloads do — a runaway container can never starve, OOM-kill, or fork-bomb `kanead`/`kanea-edge`. Enforcement is cgroups v2 (already a hard platform requirement, §21), arranged as two sibling slices:

```
/sys/fs/cgroup
├── kanea.slice                 # kanead + kanea-edge (+ systemd drop-ins for containerd, cilium-agent, etcd)
│     memory.min       = system_reserve_memory   # kernel-protected floor; reclaim never touches it (default 1 GiB, §15.1)
│     memory.swap.max  = 0                       # the floor is RAM, not swap
│     cpu.weight       = 10000                   # wins CPU contention (CPU is compressible; weight suffices)
│     OOMScoreAdjust   = -900                    # global OOM picks workload containers first, never kanea
└── kanea-workloads.slice       # every kanea-managed alloc lives under this single parent
      memory.max       = total RAM − system_reserve_memory   # workloads can never consume the reserve, collectively
      memory.swap.max  = 0
      cpu.weight       = 100
      └── per-alloc cgroups: memory.max / cpu.max / pids.max from the spec's resources {} block (§6.2 R11)
```

- **"Memory lock" = guarantee, not `mlock`.** Literal `mlockall` on the Go control plane is **rejected**: the GC grows the heap unpredictably and `RLIMIT_MEMLOCK` turns pin-overflow into hard allocation failure — the lock itself could crash `kanead`. The guarantee comes from `memory.min` (the kernel refuses to reclaim the floor under pressure), `OOMScoreAdjust=-900`, and no swap in the slice.
- **Per-alloc limits are mandatory** (§6.2 R11): `resources.cpu` (MHz) → `cpu.max` quota; `resources.memory` (MiB) → `memory.max` (hard; breach OOM-kills the alloc, the reconciler restarts it per policy, event emitted); a default `pids.max` caps fork-bombs. All are set via the containerd OCI spec at task creation, and every task's cgroup is placed under the workload parent.
- **Admission control:** workload budget = total RAM − reserve. `kanea plan` renders the budget; `apply` refuses Σ declared memory above the budget unless `resources.oversubscribe = true` in the server config (§15.1).
- **Setup:** `kanea init` installs the `kanea.slice` / `kanea-workloads.slice` systemd units plus drop-ins extending the same floor to containerd, cilium-agent and `buildkitd`. It also provisions the **rootless build daemon**: the `kanea-buildkit` system user with subuid/subgid ranges, the `uidmap` package, and the `buildkitd` unit (`rootlesskit --net=host`, socket in the daemon user's `$HOME` — *not* under a copy-up'd `/run`, where it would be invisible to clients — and root-reachable only). On non-systemd hosts `kanead` creates the hierarchy directly at startup (it runs as root anyway). `kanea doctor` verifies cgroup v2, hierarchy placement, the effective floor, and that the build socket answers.
- The cgroup hierarchy is **node-local runtime state** — never represented in the Store, never replicated (§18); it is rebuilt on every boot/agent start.
- **Process hardening complements the resource guarantees:** both Kanea units run with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `RestrictAddressFamilies`; `kanea-edge` additionally runs as its own unprivileged user (§5.2.6). Combined with the §14 workload hardening defaults and Cilium default-deny policies (§7.1), this gives three isolation layers: resource (cgroups), process (sandboxing), network (eBPF policy).

---

## 6. Job Specification (HCL)

Job specs use **HCL v2** (`github.com/hashicorp/hcl/v2`) — deliberately near-Nomad syntax.

- **The minimal service is just an image.** No Git, no `build` block, no ceremony — a three-line spec deploys (see `postgres`/`assets` in §6.1), or skip the file entirely: `kanea run --image=nginx:1.27-alpine --name web --project demo`. GitOps and pipelines (§10) are strictly optional layers on top.

### 6.1 Full annotated example

```hcl
# shop.hcl — everything for one project
spec_version = 1

project "shop" {
  description = "E-commerce storefront stack"

  # Optional: GitOps source for this project (see §10)
  git {
    url      = "https://github.com/example/shop-deploy.git"
    branch   = "main"
    path     = ".kanea/"
    auth_ref = "secret:shop/github-deploy-key"   # R5 scoping: own project or shared/
  }

  notifications {
    telegram {
      chat_id   = "-1001234567890"
      token_ref = "secret:shop/telegram-bot"
    }
    # A Slack/Discord incoming-webhook URL is a credential in path form —
    # referenced, never inlined (R3, R5).
    slack { url_ref = "secret:shop/slack-webhook" }
    on       = ["deploy.failed", "service.unhealthy", "scale.*"]
    severity = "warning"        # floor; composes with `on` as an AND
  }
}

# Storage resources may be declared here (project level) or in the server
# config (§8, §15.1). Volume blocks reference them by name.
storage "local-ssd" {
  type = "local"
}

storage "s3-media" {
  type     = "s3"
  bucket   = "shop-media"
  endpoint = "https://s3.eu-central-1.amazonaws.com"
  auth_ref = "secret:shop/s3-media"
  mode     = "ro"                           # mountpoint-s3; "rw" selects s3fs
}

service "web" {
  project     = "shop"
  description = "Storefront frontend (Next.js)"

  count = 3

  # Build from source instead of pulling (see §10)
  build {
    context    = "./web"
    # dockerfile = "Containerfile"        # optional override; auto-detected when
                                          # omitted (Containerfile, then Dockerfile)
    target     = "registry.example.com/shop/web"
    tag        = "${GIT_SHA_SHORT}"        # built-in variable
    cache_repo = "registry.example.com/shop/web-cache"
    # registry_auth_ref = "secret:shop/registry"   # push credential (R5-scoped);
                                                   # materialised as a config.json
                                                   # for the build, never in the context
  }

  task "app" {
    image = "registry.example.com/shop/web:latest"   # or from build

    env = {
      NODE_ENV     = "production"
      DATABASE_URL = "secret:shop/database-url"      # secrets store ref
    }

    resources {
      cpu    = 500    # MHz
      memory = 512    # MiB
    }
  }

  network {
    port "http" { container = 3000 }

    # Ingress beyond the default (§7.1): the project boundary is default-deny,
    # so a peer in another project is only reachable through an explicit edge.
    policy {
      allow_from = ["analytics/collector"]
    }
  }

  # North-south exposure: edge proxy + TLS + middleware
  expose {
    # domains optional — defaults to web.shop.<base_domain>
    domains = ["shop.example.com", "www.shop.example.com"]
    tls { letsencrypt = true }

    # Edge middleware (§7.2) — evaluated in order: IP restriction → rate limit → headers
    ip_restriction {
      allow = ["10.0.0.0/8", "203.0.113.0/24"]   # CIDRs; empty allow = world
      deny  = ["198.51.100.7/32"]                # deny wins over allow
    }

    rate_limit {
      requests = 100        # per window, token bucket
      window   = "1m"
      per      = "ip"       # ip | header:<name> | service
      burst    = 20
    }

    headers {
      # X-Forwarded-* is the edge's to set, and R16 rejects a spec that
      # touches it — those headers are the client identity everything else
      # is keyed on.
      request_set     = { X-Kanea-Tenant = "shop" }
      request_remove  = ["X-Internal-Debug"]
      response_set    = { Strict-Transport-Security = "max-age=63072000; includeSubDomains" }
      response_remove = ["Server", "X-Powered-By"]
    }
  }

  health_check "http" {
    type     = "http"
    path     = "/healthz"
    port     = "http"
    interval = "10s"
    timeout  = "2s"
    failures = 3
  }

  scaling {
    min = 2
    max = 10
    metric "cpu"        { target = 70 }     # percent of resources.cpu
    metric "rps"        { target = 500 }    # eBPF/L7 requests per sec
    metric "p95_latency_ms" { target = 800 }
    cooldown = "2m"
  }

  update {
    strategy     = "rolling"
    max_parallel = 1
    min_healthy  = "30s"
  }

  restart {
    attempts = 5
    backoff  = "10s,30s,1m,5m"
  }
}

service "api" {
  project     = "shop"
  description = "Storefront backend API"
  count       = 2

  task "api" {
    image = "registry.example.com/shop/api:0.9.1"   # image-only deploy — no git needed

    env = {
      # Service references (§7.1.1): interpolated to internal DNS names at
      # alloc start, validated at plan time; each implies a dependency edge.
      DATABASE_HOST = "${service.postgres.host}"        # → postgres.shop.kanea
      DATABASE_PORT = "${service.postgres.port.pg}"     # → 5432
      DATABASE_URL  = "secret:shop/database-url"
      ASSETS_ORIGIN = "http://${service.assets.host}"   # forward refs OK (order-independent)
    }

    resources {
      cpu    = 500
      memory = 256
    }
  }

  network {
    port "http" {
      container = 8080
    }
  }

  # Explicit start ordering on top of the implicit reference edges (§7.1.1)
  depends_on = ["postgres", "assets"]

  health_check "http" {
    type     = "http"
    path     = "/healthz"
    port     = "http"
    interval = "10s"
    timeout  = "2s"
    failures = 3
  }
}

service "postgres" {
  project     = "shop"
  description = "Primary database"
  count       = 1

  task "db" {
    image = "postgres:17@sha256:…"            # digest pinning recommended

    # Stock images routinely chown their data dir and drop to their own user at
    # startup. Workloads run with ALL capabilities dropped (§14, A05), so those
    # few must be requested explicitly — and only from the permitted set (R13).
    capabilities = ["CAP_CHOWN", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE"]

    resources {
      cpu    = 1000
      memory = 2048
    }
  }

  # internal only — no expose block
  network {
    port "pg" {
      container = 5432
    }
  }

  volume "data" {
    storage    = "local-ssd"                  # named storage resource (§8)
    mount_path = "/var/lib/postgresql/data"
  }
}

service "assets" {
  project = "shop"
  task "cdn" {
    image = "nginx:1.27-alpine"

    # Argument array, never a shell string (R12).
    command      = ["nginx", "-g", "daemon off;"]
    capabilities = ["CAP_CHOWN", "CAP_SETUID", "CAP_SETGID"]
  }
  volume "media" {
    storage    = "s3-media"                   # S3 bucket mounted via FUSE
    mount_path = "/usr/share/nginx/html/media"
    read_only  = true
  }
  network {
    port "http" { container = 80 }            # an exposed service must say where (R16)
  }
  # auto domain: assets.shop.<base_domain>
  expose {
    tls { letsencrypt = true }
  }
}
```

### 6.2 Spec rules

- **R1** — `project` and `service` names validated as DNS-1123 labels (§4.2); parse errors abort the run with line/column diagnostics.
- **R2** — Variables: `kanea run -var-file=env.hcl`, `${VAR}` interpolation from CLI-provided vars and built-ins (`GIT_SHA_SHORT`, `KANEA_PROJECT`, …).
- **R3** — Secrets are referenced (`secret:<path>`), never inlined; the reconciler resolves them at alloc start. **Primary injection mechanism is tmpfs files** (`/run/kanea/secrets/<alloc>/<name>`); env-var injection is supported but documented as weaker (visible via `/proc/<pid>/environ`, runtime inspect APIs, inherited by child processes).
- **R4** — `kanea plan` (dry-run) shows create/change/destroy diff before apply, Nomad-style.
- **R5** — **Secret references are project-scoped:** a service may only reference `secret:<own-project>/…` or `secret:shared/…`; validation rejects cross-project references (IDOR-class exfiltration defense — §14, A01). Git, registry, storage, and notification credentials follow the same scoping.
- **R6** — Job files declare `spec_version = 1`; future spec revisions are gated by this field (upgrade path, §15.4).
- **R7** — Health check types: `http`, `tcp`, `exec` (exec runs inside the task's container, argument array — never a shell string).
- **R8** — The minimal service is **image-only** (no Git, no `build` block): `task.image` alone deploys. At least one of `task.image` or `build` must be present; when both are, the pipeline-built image (digest-pinned, §10.2) wins and `task.image` serves as the pre-first-build value.
- **R9** — **Service references:** `${service.<name>.host}` and `${service.<name>.port.<port-name>}` interpolate to the referenced service's internal DNS name (`<name>.<project>.kanea`) and frontend port. References are **same-project only** in v1, validated at `plan` against the full applied spec set (referenced service and port must exist; file order is irrelevant), resolved at alloc start as **DNS names, never IPs** (LB reprogramming can't break them), and **cycles are rejected** with the cycle shown in the diagnostic.
- **R10** — **Dependencies:** `depends_on = [...]` declares start ordering; every reference (R9) also creates an implicit dependency edge. The reconciler starts dependencies first and health-gates dependents — a dependent never starts before its dependencies are healthy. If a dependency degrades *after* start, dependents keep running (no cascading stops); events are emitted.
- **R11** — **Resource limits are mandatory; the declaration is optional.** An omitted `resources` block yields defaults (`cpu = 100`, `memory = 256`); every alloc always runs with `cpu.max`, `memory.max`, and a default `pids.max` — no container is ever unlimited (§5.2.11). A `memory.max` breach OOM-kills the alloc (event emitted, restart policy applies). Declared `resources.cpu`/`memory` are also the admission units counted against the workload budget at `plan`/`apply` time (§15.1).
- **R12** — **`task.command` overrides the image entrypoint** and is an **argument array, never a shell string** (same rule as R7's `exec` health check — a shell string is an injection vector, §14 A03). Omitted, the image's own entrypoint runs. The first element (the program) must be non-empty; later arguments may be empty, because some programs use that meaningfully — `redis-server --save ""` is how you disable snapshots.
- **R13** — **`task.capabilities` is the explicit allowlist** promised by the §14 (A05) hardening defaults. Every alloc starts with **ALL capabilities dropped**; a service that needs one names it here (`["CAP_CHOWN"]`). Only capabilities in the **permitted set** may be requested — the set that stock images legitimately need (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID`, `SETUID`, `SETPCAP`, `SETFCAP`, `NET_BIND_SERVICE`, `NET_RAW`, `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`). Privilege-equivalent capabilities (`SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `SYS_RAWIO`, `SYS_BOOT`, `BPF`, `PERFMON`, `DAC_READ_SEARCH`, `MAC_ADMIN`, `MAC_OVERRIDE`, …) are **rejected at parse time**: granting them would be the `privileged` escape hatch v1 deliberately does not have. Requested capabilities go into the bounding, effective and permitted sets — never inheritable or ambient, so they are not passed to child processes that re-exec.

- **R14** — **`network.policy.allow_from` is the explicit ingress allowlist.** Each entry is a fully-qualified `"<project>/<service>"`; both halves are DNS-1123 labels, validated at parse time. Kanea emits one additional CiliumClusterwideNetworkPolicy per service that declares one, selecting that service and admitting the listed peers — Cilium ingress rules **union**, so an entry only ever *adds* reachability and can never weaken the project default-deny. There is **no whole-project wildcard**: naming the peer service is the point, and `"analytics/*"` is a parse error. Same-project entries are accepted and redundant (the default already permits them), so an operator may be explicit without changing behaviour. A cross-project peer is addressed by its literal internal DNS name (`<service>.<project>.kanea`) because `${service.…}` interpolation stays same-project until v1.1 (R9, §19.3).

- **R15** — **`host` volumes are operator-gated.** A `storage` block of type `host` names an absolute `path`, validated at parse time as absolute, clean and free of `..`. Whether it may actually be mounted is **not** decided by the job spec: `kanead` refuses any path that does not sit under a prefix in `storage.allowed_host_paths` (§15.1), whose default is **empty**, so the driver does nothing until an operator enables it. The check is applied to the path *after* symlink resolution — `/srv/data/link → /etc` is otherwise a trivial escape — and the directory must already exist and be a directory, because creating it on demand turns a typo into a silently empty volume. An alloc whose host volume fails this check does not start (§8's "mount failures fail the alloc loudly"). Host volumes are shared by every alloc of a service: the directory is the operator's, not Kanea's, and Kanea never deletes it.

- **R16** — **`expose` is validated at `plan`, fail-closed** (§7.2, §7.2.1). A service may only be exposed if it declares a port to expose (`expose` without `network { port … }` is an error, not a route to nowhere), and the upstream port must be unambiguous — named `http`, or the sole declared port. Every `domains` entry is validated as a hostname (labels, length, no scheme, no path, no port, no trailing dot) and **no two services may claim the same domain**, counting the auto-FQDNs that omitted `domains` blocks generate. Middleware is checked here too, because an ingress control that fails open is worse than one that is absent: `ip_restriction` entries must parse as CIDRs, `rate_limit` needs a positive `requests` and a valid `window` with `per` one of `ip` / `header:<name>` / `service`, and `headers` may not set or remove the hop-by-hop headers or the `X-Forwarded-*` set the edge owns (§5.2.6) — a spec that could rewrite `X-Forwarded-For` would be forging the identity every other control is keyed on.

---

## 7. Networking Model

### 7.1 East-west (service-to-service)

- Every alloc gets an IP from Cilium (per-node allocation CIDR).
- **Internal DNS** (embedded, lightweight): resolves `service.project.kanea` → service's Cilium frontend IP; `alloc-<id>.service.project.kanea` → alloc IPs. Listens on node-local address, injected into alloc resolv.conf. It is authoritative **only** for the internal zone — external queries are forwarded to the system resolver with strict timeouts and concurrency caps (or delegated to Cilium's standalone DNS proxy). DNS sits in the path of every service call: it must degrade gracefully, never stall.
- LB in eBPF via Cilium service map: kube-proxy-free, per-connection, Maglev-like consistent hashing.
- Default policy: project is an isolation boundary (default-deny inbound except intra-project + edge proxy identity); **`network { policy { allow_from = [...] } }`** (R14) adds explicit ingress edges on top — the only way cross-project traffic is permitted in v1. Kanea generates one CNP/CCNP YAML file per project into the agent's policy directory (§5.2.5); **`project` is also published as the endpoint's `k8s:io.kubernetes.pod.namespace` label**, because Cilium's selector translation requires it — without it a rule matches nothing and denies everything (M0 spike ①).

### 7.1.1 Service references & dependencies

- Job specs wire services together with `${service.<name>.host}` and `${service.<name>.port.<port-name>}` (§6.2, R9) — e.g. `DATABASE_HOST = "${service.postgres.host}"` → `postgres.shop.kanea`. **DNS names are injected, never IPs**, so eBPF LB reprogramming and alloc restarts never invalidate configuration.
- References create **dependency edges**; `depends_on` declares edges without env wiring. The reconciler performs a **topological, health-gated start**: dependencies reach *healthy* before dependents begin — during initial deploys, rolling updates, and crash recovery alike.
- **Degraded dependency after start:** dependents keep running (no cascading stops); events + notifications fire. Recovery re-gates only newly (re)starting dependents.
- **Cycles are rejected at `kanea plan`** (A → B → A is a spec error; the diagnostic prints the cycle).
- **Same-project only in v1.** Cross-project references (with explicit policy edges instead of the default intra-project allow) are v1.1 (§19.3).

### 7.2 North-south (public exposure)

- Only the edge proxy listens publicly (80/443).
- **Automatic FQDNs:** every service with an `expose` block gets `service.project.<base_domain>` (e.g., `web.shop.apps.example.com`) — `base_domain` set in server config. Custom `domains` override/extend.
- Operator sets one **wildcard DNS record** (`*.apps.example.com → node IP`) once; all services routable instantly.
- **Upstream selection:** a route points at the service's Cilium frontend (§7.1), not at an alloc — the eBPF LB does the balancing, so the edge holds one upstream address per service and never a backend list. The port is the one named **`http`**, or the service's only port if it declares exactly one. A service that exposes several ports without an `http` among them is a **`plan` error** (R16): v1 routes by Host alone, so there is no request attribute left to choose a port with, and picking one silently is how traffic ends up at the metrics listener.
- **A domain belongs to one service.** Two services claiming the same host — including two that default to the same auto-FQDN — is a `plan` error, not a last-writer-wins race in the edge (R16).
- Path prefixes and multiple ports per service: v1.1 (v1 = host-based routing only).

### 7.2.1 Edge middleware (ingress controls)

Per-service controls declared in the `expose` block (§6.1), enforced by `kanea-edge`:

| Middleware | Config | Behavior |
|---|---|---|
| **IP restriction** | `ip_restriction { allow, deny }` (CIDR lists) | Deny wins over allow; empty `allow` = world. 403 on reject |
| **Rate limiting** | `rate_limit { requests, window, per, burst }` | Token bucket keyed by `ip` / `header:<name>` / `service`; 429 + `Retry-After` on exceed |
| **Headers** | `headers { request_set/remove, response_set/remove }` | Applied after rate limiting; can't override edge-owned hop-by-hop or `X-Forwarded-*` integrity headers |

- **Evaluation order:** Host match → IP restriction → rate limit → header transforms → upstream proxy.
- **Defaults:** server-level `edge` config (§15.1) sets global defaults (e.g. default security headers, global per-IP rate limit); service `expose` settings override/extend them.
- **Fail-closed:** middleware config is schema-validated at `kanea plan` — invalid rules never reach the edge silently.
- **Roadmap (v1.1+):** path-prefix routing, edge basic-auth, CORS policies, per-route timeouts, Wasm middleware (§19.1).

### 7.3 TLS / Let's Encrypt

- ACME via `lego` (preferred; supports many DNS providers) or `autocert` fallback.
- Challenges: **HTTP-01** (via edge proxy), **TLS-ALPN-01**, **DNS-01** (needed for wildcards).
- **`kanead` runs the ACME client; the edge only serves what it is handed.** Issuance writes to the `certs` bucket, renewal is a control-plane timer, and a failure is an event — none of which the edge can do, because it holds no Store handle and no write access (§5.2.6). What the edge gets is a projection: the certificate bundle, and for HTTP-01 the `token → keyAuth` pairs it answers `/.well-known/acme-challenge/*` with. Since publishing and the edge's poll are not synchronous, **`kanead` fetches its own challenge URL through the edge and waits for the right answer before telling the CA to validate** — a validation that fails only because the edge had not reloaded yet costs a failed-validation slot, and that limit takes an hour to clear.
- **Certificates are projected separately from routes**, into `/run/kanea-edge/certs.json` at 0640 (group-readable by the edge user, set up by `kanea init`). The route table is world-readable because the edge runs as its own user and nothing in it is secret; a private key is neither of those things, so it gets its own file rather than dragging the route table's permissions down or pushing the key's up.
- **A host with no certificate still serves plaintext.** The HTTP→HTTPS redirect applies only to hosts the edge holds a certificate for; redirecting the rest would turn "not issued yet" into "unreachable" and break the HTTP-01 validation that would have fixed it. `/.well-known/acme-challenge/*` is never redirected. An unknown SNI is refused at the handshake rather than answered with some other host's certificate.
- **Delivery order (M3 → M5):** **HTTP-01 ships in M3** and is what the auto-FQDNs of §7.2 use — the edge owns port 80, so it is the challenge with no prerequisites. **DNS-01 and the wildcard default ship in M5**, once the secrets store exists to hold the update credential as a `secret:` reference (R3/R5). **TLS-ALPN-01 is deferred past M5** (v1.20): it is the alternative for a node that does *not* own port 80, which is not a situation Kanea is in.
- **DNS-01 is RFC 2136, TSIG-signed** (v1.20): dynamic updates against BIND, Knot or PowerDNS, spoken directly with `miekg/dns` rather than through a provider catalogue that would link every vendor SDK into the binary. An unsigned update is refused — one is a passing ACME challenge for every name in the zone. Hosted providers are a curated list, added individually.
- **ACME rate limits are a design input:** hundreds of per-service certs + frequent redeploys hit Let's Encrypt limits (50 certs/registered domain/week, duplicate-cert 5/week, failed-validation caps). Beyond ~20 exposed services, Kanea **defaults to a wildcard cert via DNS-01** — **per project**, `*.<project>.<base_domain>`, because a wildcard covers exactly one label and the generated names of §7.2 are `service.project.<base_domain>`. Per-service certs remain for custom domains, which are somebody else's zone and not Kanea's to ask a CA for `*.` of. Without a DNS-01 solver the threshold is a **loud warning** rather than a switch: a wildcard cannot be validated over HTTP. The LE staging endpoint is used in CI and during `init` testing.
- Certs stored in Store (`certs` bucket), replicated to S3 with the rest of state; renewed at 2/3 of lifetime; renewal events emitted (notification-able).
- Internal traffic (alloc↔alloc) plaintext within the node in v1; Cilium transparent encryption (WireGuard/IPsec) as a config flag, v1.1.

---

## 8. Storage

Named **storage resources** are defined at server level (config) or project level (job spec), then referenced by service `volume` blocks. Credentials always via secrets store.

| Driver | Mechanism | Notes |
|---|---|---|
| `local` | Host path under `data_dir/volumes/` | Default; per-alloc or shared |
| `host` | An existing operator-owned directory, named by `path` | **Off unless enabled:** the path must sit under a prefix in the server config's `storage.allowed_host_paths` (§15.1), which defaults to empty. Shared by every alloc of the service |
| `s3` | FUSE mount — **`mountpoint-s3` (default, read-mostly)** or **`s3fs` (opt-in read-write)**, selected by `mode` (M0 spike ③) | Any S3-compatible endpoint; read-only is the default; **not for latency-sensitive or many-small-files data** (one round trip per file op: 200 files ≈ 30 s at 30 ms RTT). `goofys` is rejected (unmaintained since 2020, no arm64 build); `rclone mount` is not a built-in driver (defers uploads ~6 s past `close()`) |
| `nfs` | Kernel NFS mount | `server`, `export`, mount options |
| `smb` | Kernel CIFS mount | `server`, `share`, credentials, `vers=3.0` default |

```hcl
storage "s3-media" {
  type     = "s3"
  bucket   = "shop-media"
  endpoint = "https://s3.eu-central-1.amazonaws.com"
  auth_ref = "secret:storage/s3-media"
}

storage "shared-nfs" {
  type   = "nfs"
  server = "10.0.0.5"
  export = "/exports/shop"
}

storage "app-config" {
  type = "host"                 # only mountable if an operator allowed the prefix
  path = "/srv/shop/config"
}
```

- **Lifecycle:** mounts are established before task start, health-checked, and cleaned up after the last referencing alloc stops. Mount failures fail the alloc loudly (event + notification), never silently.
- FUSE mounts run under a dedicated, unprivileged helper process per mount (validated in M0 spike ③ for all candidate drivers). This requires `user_allow_other` in `/etc/fuse.conf` — without it root-run containerd cannot traverse a helper-owned mount — and per-helper credential files (0600, owned by the helper uid), both established by `kanea init`.
- **The mount helper supervises:** periodic `stat` with a hard timeout, **remount on failure**, event on both. This is mandatory, not defensive: after an object-store outage s3fs errors for ~1–1.7 min and then keeps serving `ENOENT` for objects that are intact in the bucket until it is remounted (M0 spike ③). Every control-plane access to a volume mount carries a timeout — a FUSE call with a dead backend blocks for tens of seconds and is not interruptible.
- **S3 volume semantics are not POSIX** and are documented per driver: **no `truncate` on any driver** (s3fs *silently* no-ops it — returns success, size unchanged); the default driver additionally has no append, no write-at-offset, no `chmod`, no symlink. Explicit connect/read timeouts and retry budgets are always set on the mount command rather than inherited from driver defaults.

---

## 9. Autoscaling (eBPF-metrics-driven)

### 9.1 Metrics pipeline

```
Sources:                              Aggregation:                      Consumers:
- containerd /v1/metrics ──┐ (single Prometheus scrape — one call,
  (CPU, mem per alloc)     │  all cgroups; never per-task polling)   ┌─▶ Autoscaler
- Edge proxy L7 ───────────┼─▶ In-memory TS: 5s/1h → downsample 1m/6h ├─▶ Dashboard (WS)
  (rps, p50/p95/p99 —      │   (compressed) + optional /metrics      └─▶ Events
   PRIMARY for exposed)    │   (Prom) exporter
- Cilium/Hubble eBPF ──────┘
  (east-west rps, conns, drops —
   OPT-IN: CPU cost per request)
```

- **Edge-proxy metrics are the primary autoscaling signal for exposed services** — already in the request path, zero extra data-plane cost. Hubble L7 parsing is opt-in: it costs CPU per request and its ring buffer drops flows under load, i.e. eBPF L7 metrics lose fidelity exactly at peak traffic.
- cgroup metrics come from containerd's Prometheus endpoint in **one scrape for all containers** — 2 000 allocs at 5 s resolution would otherwise mean thousands of shim RPCs per minute.
- Hubble in standalone mode is configured via agent flags (`--hubble-metrics`, `--hubble-dynamic-metrics-config-path`) — no k8s ConfigMap needed (verified against the Cilium agent command reference); end-to-end validation stays in **M0**.

### 9.2 Scaling policy engine

- Per-service `scaling` block (§6.1): `min`, `max`, one or more metric rules, `cooldown`.
- Evaluator loop (every 10 s): computes desired replicas per rule = `ceil(current × value/target)` (HPA-style proportional), takes the max across rules, applies stabilization window (scale-up fast, scale-down cautious — separate windows configurable).
- Scale actions go through the reconciler (health-gated); every action emits an event + optional notification.
- **Guardrails**, each against a specific failure mode, with the defaults they ship with (v1.21):
  - **Tolerance, 10%** — a service at 71% against a 70% target needs no replica. Without a dead band every evaluation is a change and the count oscillates forever.
  - **Step caps, 2× up / 0.5× down** — one bad reading and a real surge look identical for one evaluation, so neither may take a service from 2 replicas to 200. The cap bounds a single evaluation, not the trend: sustained load still converges over several.
  - **Asymmetric stabilization** — scale-up is immediate; scale-down only to the highest count seen in a **5-minute** window. Scaling up late costs an outage now; scaling down early costs the same outage when the traffic returns.
  - **Cooldown, 2 minutes** — a rollout must finish and appear in the metrics before the next decision is based on them. The cooldown starts when a change is *applied*, so one the reconciler refused is retried rather than counted as done.
  - **No data is never zero** — a rule whose metric has no samples is skipped. Treating it as zero means a broken metrics pipeline scales every service to its minimum.
  - Plus hard min/max and the global circuit breaker (§4.3).

---

## 10. GitOps & Build Pipelines

### 10.1 Git-backed projects

- A project can declare a `git` source (§6.1): **GitHub, GitLab, or generic** Git over HTTPS/SSH.
- **Sync modes:** polling (default 60 s, configurable) and/or **push webhook** (`POST /api/v1/webhooks/git/<project>` with provider HMAC signature validation — GitHub `X-Hub-Signature-256`, GitLab `X-Gitlab-Token` — plus timestamp tolerance for replay protection and idempotent delivery keys).
- Repo layout convention: job specs in `.kanea/*.hcl` (or a single `kanea.hcl` at root).
- Flow: commit → sync → `plan` (diff) → auto-apply (or manual approval if `git { require_approval = true }`) → events + notifications.
- Git credentials in secrets store (deploy keys / PATs), never in job files or logs.
- **A repository speaks for its own project and no other.** A synced spec that declares a `project` or a service in a project other than the one whose `git` block pointed at it is refused, and the sync fails naming the project it would not accept. Without this, write access to one project's source is write access to every service on the node — the cross-project escalation R5 blocks for secrets, reached through a different door.

### 10.2 Build pipelines (BuildKit)

- Services with a `build` block are built **on the node**, with no Docker daemon and no privileged Docker socket. **Default driver: BuildKit, run as a rootless `buildkitd` host service** — an unprivileged, non-root system user (`kanea-buildkit`, subuid/subgid ranges, `rootlesskit`), supervised by systemd and driven by `buildctl` over its unix socket. Chosen in M0 spike ④: it is the only validated configuration requiring **no elevated privilege anywhere** — not a privileged container, not root on the host — and it is the fastest on rebuilds (warm build 546 ms vs 22.8 s cold).
- **BuildKit is the only build driver.** kaniko is removed (upstream archived since 2025-06; its layer cache measurably saves no time) and buildah is not shipped — one builder, one code path, one thing to pin and patch. The runner keeps a narrow internal driver seam so a second driver *could* be added, but v1 exposes no choice.
- **Either `Containerfile` or `Dockerfile` is accepted**, with **`Containerfile` taking precedence** when both are present (the Podman/buildah convention). BuildKit's frontend defaults to `Dockerfile`, so the runner detects the recipe and passes `--opt filename=` explicitly (M0 spike ④). `build.dockerfile` overrides the detection and may name either file.
- Pipeline runner: submits the build with the Git checkout as context; pushes to the configured registry (auth from a secret-materialised `config.json`, never in the context); supports layer caching (`cache_repo`).
- **Build isolation is collective, not per build:** the `buildkitd` unit carries one systemd memory/CPU cap and concurrency is bounded inside the daemon (`--oci-max-parallelism`, default 1), so builds cannot starve workloads.
- **No hardening exception is needed anywhere.** The daemon is unprivileged and non-root; nothing in the build path runs as a privileged container, and §14's workload defaults are untouched (M0 spike ④). This is the property that decided the driver: every *task-shaped* builder measured needed either elevated capabilities or full privilege.
- **The daemon owns its own content store** (`$HOME/.local/share/buildkit`, its own overlayfs snapshotter — it cannot use containerd's, being unprivileged). Image GC and disk watermarks (§5.2.4) must cover that path; containerd does not manage it.
- **Pipeline runs** are first-class objects: status, per-step logs (streamed to dashboard/CLI), duration, resulting image digest. The deploy pins the produced digest (integrity — §14, A08).
- Triggers: push to watched branch, manual (`kanea build web`), or `kanea run` when source newer than last build.
- **Build hygiene (§14):** `.git` never enters the build context; registry push credentials are scoped push-only; build-time secrets are mounted as files, never `--build-arg` (build args leak into image history).
- **Build isolation:** the `buildkitd` unit carries a systemd memory/CPU cap and bounds concurrency internally (default 1) so builds can't starve workloads. The layer cache is size-capped and garbage-collected in **both** content stores (§5.2.4).

---

## 11. Notifications

- **Channels:** generic **webhook** (JSON POST, HMAC-SHA256 signed, `X-Kanea-Signature`), **Telegram** (bot API), **Slack/Discord** (incoming-webhook compatible payload), **SMTP** email, **ntfy.sh**.
- **Events:** `deploy.started/succeeded/failed`, `service.unhealthy/healthy`, `service.crashed`, `scale.up/down`, `cert.issued/renewed/failed`, `build.started/succeeded/failed`, `backup.succeeded/failed`, `auth.login_failed`.
- Config at server level (defaults) and project level (overrides), with event filters (glob patterns, e.g. `on = ["deploy.*", "scale.up"]`).
- Delivery: at-least-once with retry/backoff; failures logged, never block the control plane.
- **Storm protection:** events are coalesced into digests under load ("42 allocs restarted in 5m" — one message, not 42), with per-channel rate limits and severity floors; a crash-looping fleet must never get the Telegram bot rate-limited or blocked.
- Outbound webhook targets: **https-only, RFC1918/link-local destinations blocked by default** (explicit opt-out for internal chat servers) — §14, A10. The address check runs at **dial time, on every resolved candidate**, not on the hostname: a name that resolves publicly when it is validated can resolve to 127.0.0.1 when it is connected to. Redirects are refused, since an allowed target answering 302 to the metadata service would walk past every check.
- **Channel credentials are `secret:` references and project-scoped** like every other credential (R3, R5): bot tokens, webhook signing keys, SMTP passwords, and Slack/Discord incoming-webhook URLs — the last because that URL *is* the credential.
- All channels also mirrored into the dashboard notification feed.

---

## 12. Dashboard

### 12.1 Stack

- **React + Vite + Tailwind CSS + shadcn/ui** (Radix primitives), TypeScript strict mode.
- Built to static assets, embedded in the binary via `go:embed`; served by the API server behind auth.
- Live data over a single multiplexed WebSocket (stats, logs, events); REST for CRUD/actions.
- **WebSocket hardening:** per-route authentication, **Origin allowlist validation on Upgrade** (CSWSH defense), per-user connection caps (§14, A01/A07).

### 12.2 Pages & features

| Page | Content |
|---|---|
| **Overview** | Node CPU/mem/disk/net (live charts), service health summary, recent events, active notifications |
| **Projects** | List (name, description, service count, health), create/edit, Git sync status |
| **Services** | Per project: name, description, image, count desired/actual, status chips |
| **Service detail** | Live CPU/mem/network graphs per alloc; **log stream** (follow, per-alloc or merged, search, download); events timeline; allocs table (restart count, uptime); scaling history; exposed domains + cert expiry + edge middleware; actions (restart, scale, redeploy, rollback-to-digest) |
| **Pipelines** | Build runs, per-step streamed logs, image digests, trigger source |
| **Storage** | Storage resources, mount health, usage where available |
| **Notifications** | Channel config, delivery log, test button |
| **Backups** | Snapshot list, verify/restore actions, replication lag |
| **Settings** | Auth config, ACME, base domain, API tokens, audit log viewer |

- Dark/light mode (shadcn theme), keyboard navigation, responsive to tablet.
- XSS-safe log rendering (escaped text, no `dangerouslySetInnerHTML` — §14, A03).

---

## 13. Authentication & Authorization

### 13.1 First-install flow

- Auth is set up **before the API is exposed** (`kanea init` interactively creates the first admin account and/or the OIDC block, runs dependency/kernel/NTP checks, and performs the **master-key escrow ceremony**, §15.3). Accounts live in the Store, not in the config file (v1.18), so `kanea init` creates the first one through the same API everything else uses — over the local unix socket, which is the only door open at that point.
- **With no account configured the API is reachable only over the local unix socket** (0600, owned by the daemon's user), and a configured network listener is refused rather than opened unauthenticated (§14, A05). The daemon says so loudly at startup instead of failing quietly.

### 13.2 Mechanisms (either or both)

- **Basic auth:** accounts in the **Store** with **bcrypt** (or argon2id) password hashes; `kanea user add` creates them at runtime over the authenticated API — no config edit, no reload, and one writer for both credentials and state (v1.18).
- **OAuth2/OIDC:** generic OIDC (Google, Keycloak, Authentik, GitLab, …) — authorization-code flow with **PKCE**, `state` + `nonce` validation, full ID-token verification (signature, issuer, audience, expiry), restricted redirect URIs, deny-by-default claim→role mapping. An account the provider authenticates but no claim maps is **refused**: authenticated is not authorized.
- **GitHub is a separate path, not a preset** (v1.19). GitHub's OAuth issues no ID token, so there is nothing signed to verify — an identity from it can only be a `GET /user` call carrying an access token. That is a different trust argument from the one above and gets its own implementation and its own review, rather than being hidden behind a config preset that makes two unlike things look alike.

### 13.3 Sessions, tokens, roles

- Dashboard: session cookie — `HttpOnly`, `Secure`, `SameSite=Lax`, 12 h absolute expiry, server-side revocation list. Cookie-authenticated mutations additionally require a **CSRF token** (SameSite=Lax is defense-in-depth, not a complete CSRF defense).
- CLI/API: bearer tokens (`kanea token create`), scoped (`admin`, `viewer`), expiry-bound, stored hashed in Store.
- Roles v1: `admin` (full), `viewer` (read-only dashboard/API). Per-project ACLs: v1.1+.
- Login rate-limited (per IP + per account), failures audited (§14, A07/A09).
- `kanea exec` / dashboard exec: **admin-only**, fully audited (user, alloc, command, duration), and can be disabled per project.
- **MCP access** (§16.3) uses the same bearer tokens and role scopes: `viewer` → read-only tools; `admin` → mutating tools; destructive tools additionally require an explicit confirmation parameter regardless of role.

---

## 14. Security — OWASP Top 10 Adherence

OWASP Top 10 (2021) compliance is a **release gate**: every milestone's definition-of-done includes the checks below, and CI enforces the automatable ones.

| # | Category | Kanea controls |
|---|---|---|
| **A01** | Broken Access Control | Auth middleware on **every** API/WS route (deny-by-default); project-scope checks on all object access (no IDOR — IDs resolved through project ownership); **secret references project-scoped at spec validation (§6.2, R5)**; role checks (`admin`/`viewer`) enforced server-side; CLI tokens scoped and revocable; WebSocket Origin allowlist (anti-CSWSH); CSRF tokens on cookie-auth mutations; `exec` admin-only + audited; **MCP tools pass through the same authz + audit pipeline, secrets are write-only via tools (§16.3)**; edge IP allow/deny middleware (§7.2.1) |
| **A02** | Cryptographic Failures | TLS 1.2+ everywhere (API, dashboard, edge); bcrypt/argon2id for passwords; secrets encrypted at rest in Store (XChaCha20-Poly1305, key from `data_dir/master.key` 0600 or external KMS later); cert/key material 0600; backups encrypted client-side before S3 upload; **master key escrowed at `init` via key ceremony (print-once + passphrase-derived KEK option) — without it, S3 backups are unrecoverable (§15.3)**; secrets injected via tmpfs files by default, not env vars (§6.2, R3) |
| **A03** | Injection | Strict HCL schema validation, no eval of user input; DNS-1123 name validation (§4.2); no shell invocation with user-controlled strings (buildctl/containerd called with arg arrays, never a shell); log output HTML-escaped in dashboard; SQL N/A (BoltDB); path-join sanitization for volume subpaths |
| **A04** | Insecure Design | Secure-by-default config (localhost-only if unauthenticated, HTTPS-only API); threat model maintained in `docs/THREAT_MODEL.md`; security review per milestone |
| **A05** | Security Misconfiguration | Hardened defaults; security headers on all responses: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`; no debug/pprof endpoints in release builds. **Workload hardening defaults:** drop `ALL` capabilities (the explicit allowlist is `task.capabilities`, bounded by a permitted set that excludes every privilege-equivalent capability — §6.2 R13), `no-new-privileges`, default seccomp profile, no `privileged` escape hatch in the v1 spec, per-alloc PID/IPC/cgroup namespaces, optional read-only rootfs — Kanea's own tasks get the same treatment |
| **A06** | Vulnerable Components | `govulncheck` + `npm audit` gates in CI; Dependabot/Renovate; SBOM (`syft`) attached to releases; pinned base images (buildkit, cilium) by digest |
| **A07** | Identification & Auth Failures | Rate-limited login (5/min/IP + exponential account backoff); session rotation on privilege change; token expiry; OIDC delegates MFA to IdP and uses PKCE + state/nonce + full ID-token validation with deny-by-default role mapping; global API rate limits and WS connection caps beyond login; **per-service edge rate limits via expose middleware (§7.2.1)**; no credentials in logs/audit (redaction filters) |
| **A08** | Software & Data Integrity Failures | Release binaries signed (cosign) + checksums; image digest pinning honored (`image@sha256:` enforced when given); TLS-only registries (no insecure registries); pipeline deploys pin built digests; backup archives carry SHA-256 manifest verified before restore; Git webhook HMAC validation + replay protection |
| **A09** | Logging & Monitoring Failures | Append-only **audit log** (all mutating API calls, auth events, restores) in Store, viewable in dashboard, with **signed periodic export for tamper evidence**; security events surfaced as notifications; log retention configurable |
| **A10** | SSRF | Containers blocked from cloud metadata (169.254.169.254) via default Cilium egress policy; Git sync URLs validated (scheme allowlist https/ssh, no local addresses unless `allow_insecure_git`); webhook delivery validates target URL against config, not user input at send-time; outbound notification webhooks https-only with RFC1918/link-local destinations blocked by default |

**Secure SDLC:** pre-commit secret scanning (gitleaks), CI SAST (gosec), container scans of released images (trivy).

---

## 15. Server Configuration & State Durability

### 15.1 Server config (`/etc/kanea/kanea.hcl`)

```hcl
datacenter  = "dc1"
data_dir    = "/var/lib/kanea"
log_level   = "info"
base_domain = "apps.example.com"        # enables service.project.apps.example.com

bind {
  api_addr   = "127.0.0.1:8600"         # before TLS/auth are set: localhost
  edge_http  = ":80"
  edge_https = ":443"
}

resources {                              # node resource isolation (§5.2.11)
  system_reserve_memory = "1GiB"         # protected floor: kanead, edge, containerd, cilium, etcd
  oversubscribe         = false          # refuse apply when Σ declared memory > (total RAM − reserve)
}

edge {                                   # defaults for all exposed services (§7.2.1)
  default_security_headers = true
  default_rate_limit { requests = 1000  window = "1m"  per = "ip" }
}

storage {                                # host-volume allowlist (§8, §6.2 R15)
  # Empty by default: no job spec can mount a host directory until an operator
  # names a permitted parent here. An unrestricted host mount is `privileged`
  # under another name, so this boundary belongs to whoever owns the node.
  allowed_host_paths = []                # e.g. ["/srv/kanea", "/opt/shared"]
}

containerd { socket = "/run/containerd/containerd.sock" }

cilium {
  enabled      = true
  kvstore      = "embedded-etcd"         # or external etcd endpoints
  cluster_cidr = "10.200.0.0/16"
  service_cidr = "10.201.0.0/16"         # service frontends (VIPs), outside cluster_cidr
  # File interfaces Kanea owns exclusively (§5.2.5); paths follow the agent's state dir.
  lb_state_file = "/var/run/cilium/lb-state.json"
  policy_dir    = "/var/run/cilium/policies"
}

acme {
  email     = "ops@example.com"
  # dns01 { provider = "cloudflare", auth_ref = "secret:acme/cloudflare" }
}

auth {
  basic {
    user "admin" { password_bcrypt = "$2y$10$…" }
  }
  oidc {
    issuer        = "https://auth.example.com/realms/kanea"
    client_id     = "kanea"
    client_secret = "secret:oidc/client-secret"
    role_claim    = "kanea_role"
  }
}

notifications {
  telegram { bot_token_ref = "secret:notify/telegram-bot" chat_id = "-100…" }
  on = ["deploy.failed", "backup.failed", "cert.failed"]
}

state {
  replication {
    s3 {
      bucket      = "kanea-state"
      endpoint    = "https://s3.eu-central-1.amazonaws.com"   # any S3-compatible
      prefix      = "prod/node-a"
      auth_ref    = "secret:s3/state-replicator"
      interval    = "5m"
    }
  }
}

backup {
  schedule  = "0 * * * *"                # hourly
  retention { hourly = 24  daily = 7  weekly = 4 }
}

storage "local-ssd" { type = "local" }
```

- **Resource guards:** `resources.system_reserve_memory` is the cgroup-protected floor for everything except workload containers (§5.2.11); the workload budget is total RAM − reserve. `kanea init` warns when the reserve exceeds 30% of total RAM (small hosts) or falls below 512 MiB (under-protection); `kanea doctor` verifies the cgroup hierarchy is in place. With `oversubscribe = false` (default), `apply` refuses specs whose Σ declared memory exceeds the workload budget.

### 15.2 State model

- All mutable platform state in BoltDB via the `Store` interface (§5.2.3).
- Writes are transactional; every mutation carries a monotonic index (Raft-log-compatible shape — the same field becomes the Raft index later, §18).

### 15.3 S3 state replication & backup/restore

- **Replication model — Store-level CDC, not Litestream:** bbolt has **no WAL** (it is a copy-on-write B+tree that rewrites pages in place), so Litestream-style log shipping is impossible. Instead, every `Store` mutation emits a **change record** (carrying its monotonic index, §15.2) that the replicator ships as change segments to the S3-compatible bucket continuously, with periodic full snapshots as segment bases. The DB file is compacted on a schedule (§5.2.3).
- **Encryption & key escrow (critical):** all segments/snapshots are client-side encrypted (§14, A02). The master key is **escrowed at `kanea init` via a key ceremony** (print-once + written confirmation, or passphrase-derived KEK) — *if the key dies with the node, every backup is unreadable.* The DR runbook starts with key recovery.
- **Backup:** scheduled (cron) + on-demand snapshots. Archive = state snapshot + certs + secrets (encrypted; SHA-256 manifest verified before restore).
- **Restore:** `kanea restore --from s3://bucket/prefix [--snapshot <id>]` on a stopped node; or **first-boot auto-restore** — if `state.replication.s3` is set and local state is empty, the agent offers pull-and-restore.
- **Recovery order:** master key → Store snapshot + segment replay → **Cilium kvstore wiped and rebuilt from desired state** (derived state; etcd files are never backed up/restored, §5.2.5) → images re-pulled (parallel queue, bounded concurrency) → endpoints recreated (bounded concurrency, exposed services first) → edge routes live.
- **Realistic targets:** **RPO ≤ 5 min** (change segments). **RTO: control plane ≤ 15 min; full workload convergence is best-effort** — a fresh node must re-pull every image, and registry bandwidth/rate limits dominate. A registry mirror is recommended; an optional image pre-seed flag exists for small fleets.
- **Not backed up:** container images (re-pulled; optional pre-seed), ephemeral logs (optional inclusion flag).

### 15.4 Upgrades & schema migration

- **State migrations:** BoltDB buckets carry schema versions; `kanea agent` runs forward-only migrations at startup (with a pre-migration local snapshot + automatic S3 snapshot when replication is configured). Job specs are versioned via `spec_version` (§6.2, R6).
- **Upgrade flow:** `kanea upgrade` (or package manager) → `kanea-edge` drains and restarts first (brief, connection-drained), then `kanead` restarts; running allocs and eBPF dataplane are untouched throughout.
- **Compatibility:** a version matrix pins supported containerd/Cilium versions per Kanea release; `kanea init` and `kanea doctor` enforce it.
- **Rollback:** previous binary + pre-upgrade snapshot restore; documented in the ops runbook.

---

## 16. API & CLI Surface

### 16.1 REST API (v1, abbreviated)

```
POST   /api/v1/auth/login | /auth/logout | /auth/oidc/callback
GET    /api/v1/overview                        # node + fleet summary
GET    /api/v1/node/stats                      # live node metrics (WS: /ws)
GET    /api/v1/projects                        # list
POST   /api/v1/projects                        # create from job spec
GET    /api/v1/projects/{p}                    # detail
DELETE /api/v1/projects/{p}
POST   /api/v1/projects/{p}/sync               # git sync now
GET    /api/v1/projects/{p}/services
GET    /api/v1/services/{p}/{s}                # detail incl. allocs
POST   /api/v1/services/{p}/{s}/scale          # manual scale
POST   /api/v1/services/{p}/{s}/restart
POST   /api/v1/services/{p}/{s}/deploy         # new spec / digest
GET    /api/v1/services/{p}/{s}/logs?alloc=…   # WS for follow
GET    /api/v1/services/{p}/{s}/stats
GET    /api/v1/pipelines | POST /api/v1/pipelines/{p}/{s}/run
GET    /api/v1/events?filter=…
GET    /api/v1/storage | POST /api/v1/storage
GET    /api/v1/backups | POST /api/v1/backups | POST /api/v1/backups/{id}/restore
GET    /api/v1/audit
POST   /api/v1/webhooks/git/{project}          # HMAC-validated
GET    /api/v1/notifications/channels | POST …/test
```

### 16.2 CLI (`kanea`)

```
kanea init                 # interactive first-install: config, auth, deps/kernel/NTP checks, key ceremony
kanea agent -config=…      # run the control-plane daemon (systemd-managed normally)
kanea edge -config=…       # run the edge ingress proxy (separate systemd unit)
kanea doctor               # verify node health: deps, versions, kvstore, disk, clock
kanea plan app.hcl         # dry-run diff
kanea run app.hcl          # apply job spec
kanea run --image=nginx:1.27-alpine --name web --project demo   # minimal image-only deploy, no spec file
kanea stop shop/web        # stop a service
kanea ps [-p shop]         # allocs table
kanea status [shop/web]    # health, events, scaling
kanea logs -f shop/web     # stream logs (merged or --alloc)
kanea exec shop/web -- sh  # debug shell into an alloc
kanea scale shop/web 5
kanea build shop/web       # trigger pipeline
kanea project sync shop
kanea backup create|list|verify
kanea restore --from s3://…
kanea token create --role viewer
kanea upgrade [--check]   # drain edge, restart services, run state migrations
kanea mcp                  # stdio MCP server for local AI agents (§16.3)
kanea ui                   # open dashboard URL
kanea version
```

### 16.3 MCP server (Model Context Protocol)

Kanea ships a first-class **MCP server** so AI assistants and agents (opencode, Claude Desktop, custom automations) can operate the platform — through the **same auth, authorization, rate-limit, and audit pipeline** as the CLI and dashboard. No side channels, no privileged backdoors.

- **Transports:** streamable HTTP at `https://<node>:8600/mcp` (Bearer-token authenticated) for remote agents; **stdio** via `kanea mcp` for local agent integration. The HTTP transport is **stateless** — one JSON-RPC message per POST, no session id, no server-initiated stream — and validates `Origin` against the same allowlist the websocket uses, because a browser page on any origin can otherwise POST to a loopback control plane (DNS rebinding). The stdio transport's credential is the unix socket, which §13.1 already treats as the local administrative path.
- **Tools — read (`viewer` role):** `list_projects`, `get_project`, `list_services`, `get_service`, `list_allocs`, `get_logs` (tail-limited), `get_events`, `get_node_stats`, `get_service_stats`, `list_pipelines`, `list_backups` (M10), `list_storage`, `get_audit` (admin-only).
- **Tools — mutate (`admin` role):** `plan_spec`, `apply_spec`, `scale_service`, `restart_service`, `stop_service`, `deploy_service`, `run_pipeline`, `create_backup` (M10), `test_notification`.
- **Tools — destructive (`admin` + `confirm=true`):** `delete_project`, `restore_backup` (M10).
- **Tool tiers are advertised, not just enforced.** `tools/list` returns only the tiers the caller's role permits, so a viewer is never offered `apply_spec`. That filter is a courtesy — the enforcement is the API route the tool calls, which refuses regardless — and it fails closed: a caller whose role cannot be determined is offered read tools only.
- **Refusals are tool results, not protocol errors.** A tool that ran and was denied returns `isError` with the reason, so the model sees it and stops; a tool that does not exist is a JSON-RPC error, because that is a client bug and not something to reason about.
- **No secret tools exist.** §16.3's tool list names none, and none are implemented — not even a write. The write-only secrets surface is reachable over the API and the CLI, where a human is holding the value. An agent that cannot reference the secrets store cannot leak from it.
- **Resources:** `kanea://projects`, `kanea://projects/{p}/services`, `kanea://services/{p}/{s}/status`, `kanea://services/{p}/{s}/logs`, `kanea://events`, `kanea://node/stats`.
- **Safety rules:** no tool ever returns secret values (secrets are write-only through the API — an agent can set a secret but never read one back); every tool call is audit-logged with the token identity (§14, A09); tools honor the same rate limits (§14, A07); destructive tools require the explicit `confirm` parameter; tool result payloads are size-capped (log tails default 500 lines).

---

## 17. Observability

- **Logs:** container stdout/stderr captured via containerd log pipes → per-alloc ring buffer (default 4 MiB) + optional on-disk persistence (`data_dir/logs/`, rotated, default 100 MiB/service cap, configurable). **Drains are non-blocking with an explicit drop policy and drop counters** — a stalled log pipeline must never backpressure a workload into a blocked `write()`. Streams to dashboard/CLI via WS. Log redaction hook for registered secrets (best-effort).
- **Metrics:** per-alloc CPU/mem (single containerd `/v1/metrics` scrape), per-service network + L7 (edge proxy primary for exposed services; Hubble opt-in for east-west), node stats (procfs). In-memory TS (5 s/1 h → 1 m/6 h downsampled, compressed) + optional Prometheus `/metrics` exporter.
- **Events:** everything state-changing emits a structured event (deploy, scale, crash, health, cert, backup, git) — dashboard feed, notification source, 7-day default retention.
- **Audit log:** separate append-only stream of all authenticated mutating actions, with signed periodic export (§14, A09).
- **Hubble:** optional flag to expose Hubble's flow visibility for the node (v1.1 — full Hubble UI integration is a later candidate).

---

## 18. Clustering-Ready Design Constraints

v1 is single-node, but these rules are **binding for all v1 code** so clustering is additive, not a rewrite:

1. All state mutations go through the `Store` interface with monotonic indexes (Raft FSM-compatible).
2. The reconciler reads desired state only from the Store, never from in-memory-only structures.
3. Placement goes through a `Scheduler` interface (v1 impl: `LocalScheduler`).
4. Agent internally separates `Server` and `Client` roles even though both run in one process (config: `server { enabled = true }`, `client { enabled = true }`).
5. No node-local paths in shared state — volumes referenced by named storage, alloc runtime data kept out of replicated buckets.
6. Node identity is a stable UUID in `data_dir/node-id`, not hostname-derived.
7. Cilium kvstore configured so a multi-node etcd topology is a config change, not a code change.
8. The edge proxy is a separate process (`kanea-edge`) from day one — north-south traffic survives control-plane restarts, crashes, and upgrades (§5.2.6).

---

## 19. Future Considerations (Post-v1)

Deliberately out of v1 scope, evaluated and parked. The architecture keeps the door open for both — revisit at the clustering-milestone review.

### 19.1 WebAssembly (Wasm) workloads

- **Fit:** containerd runs Wasm modules via **runwasi shims** (`containerd-shim-runwasi-v2` + wasmtime/wasmedge); Wasm packaged as OCI artifacts flows through the existing runtime driver (§5.2.4). The driver interface already abstracts runtime choice (§18).
- **Candidate spec shape:** `task { runtime = "wasm" }` — additive to the job spec, no breaking change.
- **Value:** ~1 ms cold starts (supercharges §9 autoscaling, enables scale-to-zero); KB-sized artifacts (thousands of services per node); deny-by-default capability sandbox (strengthens §14 posture).
- **Limits:** WASI maturity (wasi-http solid; raw sockets/filesystem limited); §8 volume drivers don't map into the sandbox. Containers remain the general-purpose default — Wasm complements, never replaces.
- **Also candidate:** user-supplied **edge-proxy middleware as Wasm plugins** (request transforms, auth hooks — à la Envoy/Traefik Wasm extensions).
- **Adoption trigger:** demonstrated demand for ultra-light HTTP handlers / glue / webhook-receiver services; revisit after v1.0.

### 19.2 SPIFFE / SPIRE workload identity

- **Value:** cryptographic per-workload identity (`spiffe://kanea/<project>/<service>`) → mTLS and identity-based authorization without per-service cert management; federation once multi-node exists.
- **Why deferred:** SPIRE is a second control plane (against G1's single-binary ethos); single-node traffic never leaves the kernel, and v1's proportionate controls already cover the threat model — Cilium default-deny policies (§7.1), edge TLS (§7.3), and the flagged v1.1 option of Cilium transparent encryption (WireGuard/IPsec, no app changes).
- **Adoption path:** evaluate at the **clustering phase**; prefer **Cilium's native SPIRE-based mutual authentication** over a bespoke SPIRE deployment. Interim option if internal mTLS is ever needed pre-clustering: an internal CA in the existing cert store issuing short-lived per-alloc certs ("SPIFFE-lite").

### 19.3 Longer-horizon parking lot

Multi-node clustering (per §18 constraints) · embedded OCI registry · canary auto-promotion · path-based edge routing · Hubble UI integration · per-project ACLs · multi-task services (sidecars) · **cross-project service references** (explicit policy edges) · gVisor/Kata runtime classes for hostile multi-tenant workloads. (Each is marked v1.1+ where first mentioned; listed here for consolidation.)

---

## 20. Milestones

| MS | Name | Scope | Exit criteria |
|---|---|---|---|
| **M0** ✅ | **Spikes** (timeboxed, complete) | ① Standalone Cilium: CNI from containerd, endpoint labels, service LB, network policy, **Hubble metrics w/o k8s** — **done, GO** ② containerd task lifecycle + CNI + cgroup metrics — **done, GO** ③ S3 FUSE mount choice — **done, GO** ④ image build task on containerd — **done, GO** | Written spike reports; go/no-go per component; fallbacks documented (CNI bridge / edge-proxy metrics) |
| **M1** | Runtime core | Store + reconciler + containerd driver + HCL parser + CLI (plan/run/stop/ps/logs) + local volumes + **image-only deploys** (no git) + workload-parent cgroup & per-alloc limits (cpu/memory/pids, §5.2.11) | `kanea run` starts N healthy containers **from a bare image reference**; crash → restart; logs stream in CLI |
| **M2** | Networking & storage | Cilium integration, internal DNS (authoritative-only + capped forwarding), eBPF service LB, default policies; **service references + dependency-ordered reconcile (§7.1.1)**; NFS/SMB/S3 volume drivers; batched LB updates | Two services talk via DNS name; LB spreads traffic; dependents start only after dependencies are healthy; volume mounts work |
| **M3** | Ingress & TLS | Edge proxy as separate `kanea-edge` process, hardening (timeouts, host validation, X-Forwarded stripping), **edge middleware (IP restriction, rate limits, headers)**, auto FQDNs, **ACME HTTP-01** (DNS-01, TLS-ALPN-01 and the wildcard default move to M5 with the secrets store — §7.3) | Service publicly reachable at `web.shop.<base_domain>` with valid LE cert; `kanead` restart doesn't drop public traffic; middleware blocks/limits/headers verified end-to-end |
| **M4** | Dashboard | shadcn/ui SPA: overview, projects, services, service detail (stats + logs), events, settings shell | Full dashboard parity with CLI read ops; live WS updates |
| **M5** | Auth & OWASP pass | **Secrets store**; Basic + OIDC (PKCE), sessions, CSRF tokens, WS Origin checks, tokens, roles; workload hardening defaults (drop caps, seccomp, no-new-privs); security headers; rate limiting; audit log; CI gates (govulncheck, gosec, gitleaks); **ACME DNS-01 + TLS-ALPN-01 + wildcard default** (deferred from M3: the DNS provider credential is a `secret:` reference, §7.3) | §14 checklist green; unauthenticated API impossible; default container spec passes hardening audit |
| **M6** | Metrics & autoscaling | TS store (containerd `/v1/metrics` scrape + edge-proxy metrics primary), scaling evaluator, Hubble opt-in wiring, circuit breaker, Prometheus exporter | Service scales 2→N→2 on synthetic load per policy; metrics cost measured at 2 000-alloc scale |
| **M7** | GitOps & pipelines | Git sync (poll + webhooks), BuildKit runner (rootless `buildkitd` unit + `buildctl` driver; `Containerfile`/`Dockerfile` detection), pipeline objects + dashboard page | Push to GitHub → build → rolling deploy → event |
| **M8** | Notifications | Channel dispatcher (webhook, Telegram, Slack/Discord, SMTP, ntfy), filters, storm coalescing/digests, SSRF egress rules, test action, dashboard page | Configured channels receive filtered events; digest mode verified under event storm |
| **M9** | MCP server | MCP streamable-HTTP + stdio transports, read/mutate/destructive tool tiers, resources, token scopes, audit integration | AI agent can plan/apply/scale/stream logs via MCP; viewer vs admin scoping and `confirm` gating verified |
| **M10** | Hardening & packaging | S3 state replication (CDC segments), backup/restore + **key escrow ceremony** + DR runbook, upgrade & schema-migration framework (§15.4), `kanea init`, systemd units (`kanead` + `kanea-edge` in `kanea.slice`, `kanea-workloads.slice`, containerd/cilium drop-ins, §5.2.11), install script, signed releases, docs site | Fresh-node restore from S3 verified in CI (incl. key ceremony); upgrade+rollback tested; v1.0 tagged |

**Definition of done (every milestone):** OWASP §14 checks reviewed, `govulncheck` clean, tests green, docs updated.

---

## 21. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Platform** | Linux amd64/arm64; kernel ≥ 5.10 (eBPF); cgroups v2; containerd ≥ 1.7; cilium-agent ≥ 1.18; NTP-synced clock (ACME/OIDC/HMAC validity) — checked at `init` |
| **Footprint** | kanea idle RSS ≤ 150 MiB, **total platform ≤ 1 GiB including cilium-agent, etcd, containerd, and kanea-edge** (Hubble off by default) — the 1 GiB budget is the default `system_reserve_memory` (§5.2.11); dashboard bundle ≤ 1.5 MiB gzipped. M0 measurement: cilium-agent 153 MiB (Hubble **on**, spike ①) + **rootless `buildkitd` 157 MiB (spike ④)** + containerd 42 MiB + etcd 23 MiB ≈ 375 MiB before Kanea's own processes — cilium-agent and buildkitd are the two largest resident components and the reserve must cover both |
| **Storage** | S3 volumes cost **one object-store round trip per file operation** (~30 ms typical): creating or listing a 200-file directory takes tens of seconds, and a FUSE call with a dead backend blocks for tens of seconds uninterruptibly — S3 volumes are for bulk/read-mostly data, never for hot paths or many small files (M0 spike ③) |
| **Scale** | ≥ 500 services / ≥ 2000 allocs per node; reconcile loop ≤ 1 s at that scale |
| **Performance** | API p95 ≤ 100 ms (local); log stream latency ≤ 500 ms; **scale decision ≤ 20 s from a sustained metric breach** (v1.21: a 15 s averaging window — three samples at the 5 s scrape resolution — plus one 5 s evaluation tick; a large spike decides sooner) |
| **Durability** | RPO ≤ 5 min (S3 change segments); RTO: **control plane ≤ 15 min**, workload convergence best-effort (image re-pull bound); backup verify = restore test in CI; master key escrowed at `init` |
| **Security** | §14 gates in CI; signed releases; SBOM published |
| **Reliability** | `kanead` restart disturbs neither running allocs **nor north-south traffic** (separate `kanea-edge` process); reconciler heals drift ≤ 30 s; log drains never backpressure workloads; workloads can never starve or OOM-kill the control plane (cgroup memory floor + OOM-killer policy, §5.2.11); disk watermark alerts at 80/90% |
| **UX** | `init`→first HTTPS service ≤ 5 min on a fresh VM; every CLI mutation has `--json` |
| **i18n/a11y** | Dashboard EN only v1; WCAG 2.1 AA contrast via shadcn theme |

---

## 22. Risks & Open Questions

| # | Risk / Question | Impact | Mitigation |
|---|---|---|---|
| R1 | **Standalone Cilium is a lightly-trodden path** (endpoint labels, service LB, policy import without k8s) | High → Medium | **De-risked in M0** ([spike ① report](./spikes/cilium-standalone/REPORT.md), 25/25 on Cilium 1.19.6): CNI ADD, kvstore identities, Maglev LB, per-project policy and Hubble metrics all work with `--enable-k8s=false`. **Residual risk: the non-k8s interfaces are file-based and were churned once** — the writable service and policy REST APIs were removed in 1.18 and replaced by `--lb-state-file` / `--static-cnp-path`. Mitigation: floor ≥ 1.18 (pin 1.19.x), version matrix enforced by `kanea init`/`doctor` (§15.4), interface checks in `doctor`. Fallback if churned again: standard CNI (bridge+host-local) + edge-proxy LB |
| R2 | Hubble L7 metrics: CPU cost + ring-buffer drops under load → fidelity loss at peak | Medium | Edge proxy is the primary L7 source for exposed services (in-path, zero extra cost); Hubble opt-in, east-west only |
| R3 | FUSE S3 mount performance/reliability | Medium | Spike-chosen driver; documented "not for hot data"; NFS/SMB as alternatives |
| R4 | BuildKit frontend edge cases (some Dockerfiles); **single-driver risk** | Medium | **De-risked in M0** ([spike ④ report](./spikes/kaniko-build/REPORT.md), 11/11 on the daemon path): rootless `buildkitd` verified for build+push, `Containerfile`/`Dockerfile`, digest reporting, cache reuse, resource caps and clean failure surfacing — with no privilege anywhere and 546 ms warm builds. Single-driver risk is accepted deliberately (one builder to pin and patch); the runner keeps an internal driver seam, and buildah was measured as a working drop-in (26/27, task-shaped) should it ever be needed |
| R5 | S3-compat consistency differences across vendors | Low | Verify on AWS + MinIO in CI; checksums on every object |
| R6 | Single-node = SPOF by design | Accepted | S3 replication + DR runbook; clustering on roadmap; blast radius limited by `kanea-edge` process split |
| R7 | Embedded etcd fsync sensitivity on cheap VPS disks → identity/endpoint stalls | Medium | Derived-state design (rebuilt, never restored); disk watermark alerts; documented recovery order (§15.3) |
| R8 | ACME rate limits with per-service certs at scale | Medium | Wildcard-via-DNS-01 default beyond ~20 exposed services; staging endpoint in CI |
| R9 | Master-key loss = total backup loss | High → mitigated | Key escrow ceremony at `init` (print-once / passphrase-derived KEK); DR runbook starts with key recovery (§15.3) |
| R10 | Log-pipeline backpressure blocks workloads | Medium | Non-blocking drains + drop policy + drop counters (§17) |
| R11 | AI agents (MCP) misused → destructive ops or secret exfiltration | Medium | Role-tiered tools, destructive ops require `confirm`, secrets write-only, full audit, rate limits, payload caps (§16.3) |
| R12 | Workload resource exhaustion (memory/CPU/PIDs) starving or OOM-killing the control plane | High → mitigated | cgroups v2 reservation (`memory.min` floor, default 1 GiB) + collective workload ceiling + mandatory per-alloc limits with defaults + admission control (§5.2.11, §6.2 R11, §15.1); `mlock` rejected for the Go control plane |
| Q1 | ~~Multi-task services (sidecars) in v1 or v1.1?~~ | **Resolved** | v1: exactly one task per service (spec shape keeps `task` blocks for v1.1 compatibility) |
| Q2 | Built-in DNS vs. CoreDNS binary? | Impl detail | M2 decision; built-in preferred (zero deps) |
| Q3 | ~~Log retention: how much disk by default?~~ | **Resolved** | Default 100 MiB/service cap, configurable (§17) |

---

## 23. Appendix

### 23.1 Full concept mapping

| Kanea | Nomad | Kubernetes |
|---|---|---|
| Agent (`kanea agent`) | Agent (server+client) | kubelet + control plane |
| Project | Namespace | Namespace |
| Service | Job (type=service) | Deployment + Service |
| Task | Task | Container |
| Allocation | Allocation | Pod |
| Job spec (`.hcl`) | Job spec (HCL) | YAML manifests |
| `expose` block | fabio/traefik tags | Ingress + cert-manager |
| `expose` middleware | traefik middlewares | Ingress annotations / Middleware CRDs |
| MCP server | — | — |
| `scaling` block | Autoscaler (external) | HPA |
| `storage` resource | CSI volume | PV + PVC |
| `build` block / pipeline | — (external CI) | Tekton / external CI |
| Edge proxy | fabio / traefik | Ingress controller |
| Notifier | — (external) | Alertmanager |
| State replication | Raft (builtin, multi-node) | etcd |

### 23.2 Key dependencies (candidate versions)

- `github.com/containerd/containerd/v2` — runtime client
- `cilium-agent` **≥ 1.18 on host (pin/test 1.19.x)** — driven over its REST API on `/var/run/cilium/cilium.sock` with a **hand-written client** (`net/http` + minimal structs). `github.com/cilium/cilium` is deliberately **not** a Go dependency: it pulls the Kubernetes client graph and ships `replace` directives consumers don't inherit (violates the no-kube-imports constraint and inflates the CVE surface)
- `github.com/hashicorp/hcl/v2` — job specs & config
- `go.etcd.io/bbolt` — state
- `github.com/go-acme/lego/v4` — ACME
- `github.com/go-git/go-git/v5` — Git-backed projects (§10.1), in-process rather than shelling out to `git`. The deciding property is that a deploy key never touches the filesystem and never enters a child process's environment: `git` would need an askpass script, a key file for `GIT_SSH_COMMAND -i`, or a token in the environment, and `/proc/<pid>/environ` is readable by the same user. Every other credential in Kanea is in-memory or materialised to 0600 only where a separate process forces it (§6.2 R3). It also removes `git` as a host prerequisite. The cost is a dependency tail, which §14 A06 gates on `govulncheck`
- `moby/buildkit` (digest-pinned image; `buildkitd`/`buildctl`/`rootlesskit` extracted to the host) — builds, run rootless as a host service (the only build driver)
- React 18+, Vite, Tailwind CSS, shadcn/ui, TanStack Query, zod

### 23.3 Glossary

- **Alloc** — one running instance of a service.
- **Base domain** — wildcard DNS domain under which service FQDNs are generated.
- **Edge proxy** — Kanea's built-in public HTTP(S) entrypoint (`kanea-edge` process).
- **Edge middleware** — per-service ingress controls (IP restriction, rate limits, header transforms) applied by `kanea-edge`.
- **MCP** — Model Context Protocol; Kanea's interface for AI agents (§16.3).
- **Project** — named group of services; isolation, discovery, and notification boundary.
- **Reconciler** — control loop converging actual state to desired state.
- **Spike** — timeboxed technical investigation producing a go/no-go report.

---

*End of PRD. This document is the project's north star: deviations require a PRD amendment with rationale.*
