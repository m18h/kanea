# Kanea — Product Requirements Document

| | |
|---|---|
| **Status** | Adopted v1.46 |
| **Author** | Michael K. Essandoh (<michael@essandoh.dev>) |
| **Last updated** | 2026-08-11 (v1.46) |
| **Document type** | Product Requirements Document (PRD) |

> **v1.1 amendments** — incorporates the engineering review (performance/reliability/security): edge proxy split into `kanea-edge` (§5.2.6), Store-level CDC replication + master-key escrow (§15.3), upgrade & migration framework (§15.4), workload hardening defaults + CSRF/CSWSH/OIDC hardening (§14), ACME wildcard-default policy (§7.3), metrics pipeline redesign (§9.1), storm controls (§4.3, §11), realistic RTO targets (§15.3, §21), total-platform footprint budget (§21).

> **v1.2 amendments** — adds the **MCP server** (first-class AI-agent interface: §5.2.1, §13.3, §16.3, M9→M10 renumbering) and **edge middleware** on the `expose` block — IP restriction, rate limiting, header manipulation (§5.2.6, §6.1, §7.2, M3).

> **v1.3 amendments** — **image-only deployment** is explicit as the minimal, first-class path (G14, §6.2 R8, CLI quick-run) and adds **service references & dependencies**: `${service.<name>.host}` / `${service.<name>.port.*}` interpolation, `depends_on`, topological health-gated starts, cycle rejection (§6.2 R9–R10, §7.1.1, §4.3).

> **v1.46 amendments** — **mutable node settings live in the Store, and the dashboard gets its Settings page** (§11, §12.2, §15.1, §15.3, §16.1). Two node-level decisions — the backup destination and the notification channel set — were startup-static: argv rendered into a unit and project HCL read once, so "change the backup bucket" meant editing a systemd file over SSH beside a dashboard that reports everything else about the machine, and §12.2 has promised a Settings page since v1.1 that was never built. The split is now explicit. **What stays flags** is what config should decide (the v1.18 line): where things listen, the CIDRs, the DNS, the edge port policy, the data directory — facts about the node the Settings page shows read-only. **What moves to the Store** is what changes while the node runs: `settings/backup` and `settings/notifications` records in the existing `kv` bucket (no new Kind, no migration, already replicated and restored), managed over new admin-only `GET /v1/settings` + `PUT/DELETE /v1/settings/{backup,notifications}` routes — every mutation CSRF-checked and audited, and every credential in a settings record a `secret:` reference under R3, refused by shape if a pasted literal arrives. **Precedence: flags are the seed; a Store record, once written, wins; deleting it reverts to the flags** — an upgraded node whose unit carries `--backup-s3` keeps replicating unchanged, first-boot auto-restore necessarily reads flags (there is no Store yet), and a corrupt settings record falls back to the flags loudly rather than silently stopping replication. **The backup destination hot-swaps through a validate-then-commit sequence**: the new sink is built and *probed* — a small object written, listed back and deleted, through the sink's real `Put` (the MinIO lesson: no fake can catch a reader-ownership bug) — before the settings record is written, before the old replicator is stopped; a destination that fails its probe is a 400 with the old replication untouched. The old replicator's shutdown final-ship lands in the old bucket; the new one derives its cursor from the new sink (the §15.3 rule, unchanged) and its startup snapshot gives the new destination a full base immediately. **Notification routes become change-driven rather than startup-static** (§11): the dispatcher's route set is swappable on its own goroutine (Publish untouched — constraint #8), pending digests of removed routes are force-flushed rather than discarded, and a fingerprint-gated reloader rebuilds routes when the Store changes — HCL apply, GitOps sync and the new API routes all converge on the same rebuild, so channels resolve credentials only when config actually changed (the v1.44 `Providers.Current()` rationale). §11's server-level defaults, promised since v1.1 and never built, become real as the `settings/notifications` record: routes with no project scope that see every project's events. A project's own channels stay on its project record — one config, three writers (HCL apply, GitOps sync, `PUT /v1/projects/{p}/notifications`), one reader — and the API response warns when the project has a git source, because the next sync wins (the spec-editor's banner, applied to channels). The Settings page (§12.2) composes it: node config read-only, backup destination with its effective source badge and live replication status, channels with the §11 test button, and the account/token/audit surfaces that were API-only since M5.

> **v1.45 amendments** — **`kanea init` finishes what it starts** (§13.1, §16.2). §13.1 has said since v1.18 that init "interactively creates the first admin account … through the same API everything else uses — over the local unix socket"; the code printed an instruction instead, and the operator it printed it for was left with a daemon that was not running, an account that did not exist, and a dashboard no `--listen` had ever been written for. Init now asks for the API/dashboard listen address (default `127.0.0.1:8600`; `none` keeps the daemon socket-only) and renders it into the `kanead` unit's ExecStart — the v1.33 reasoning again: kanead owns the listener, so the flag belongs on its argv rather than in the operator's shell history. After writing units it runs `systemctl daemon-reload && systemctl enable --now kanead`, waits on the unix socket, and creates the first admin through `PutUser` exactly as §13.1 promised — prompting for the username and reading the password the way `kanea user add` already does (terminal double-entry, or one line from a pipe, never argv). Because §13.1 refuses a network listener on a daemon that booted with no account, init then performs the one restart the daemon's own refusal message prescribes; a live listener re-open was considered and rejected — it is a second address-validation path and a PutUser→listener side channel, for a window that exists exactly once per node. Init ends with a summary of what was actually built: the dashboard URL (derived from the daemon's reported listener, never assumed), the admin account's name — the password is never rendered, structurally: the summary's input type has no field for it — the internal DNS address (the node CIDR's `.1`, absent under `netns`), and the CIDR layout including the v6 trio when configured. Idempotent throughout: an existing master key is left alone as before, an existing account skips the prompt and the restart, and a re-run whose only change is the listen address restarts once to pick it up (`enable --now` does not re-exec a running unit). A non-loopback listen address without `--listen-cert`/`--listen-key` is refused up front, before any check or install runs — the same refusal `listenNetwork` makes, moved in front of the person typing. On a non-systemd host, or under `--skip-units`/`--no-start`, the old manual next-steps print instead, so nothing new is required of environments the old flow served.

> **v1.44 amendments** — **external secret providers, synced into the store** (new §5.2.13; §11, §14 A02/A10, §15.1, §16.1/16.2, §22). An operator who already keeps credentials in Doppler, AWS Secrets Manager, Vault, Azure Key Vault or GCP Secret Manager has been hand-copying them in with `kanea secret put` and hand-copying them again on every rotation — a manual replication loop whose failure mode is a workload running on a revoked credential. `kanead` gains a **sync subsystem**: a loop that periodically pulls named external secrets and writes them into the existing encrypted store (§14 A02's XChaCha20 store, unchanged). **The job-spec surface does not move**: a spec still says `secret:<project>/<name>` and never names a provider, an endpoint or an external coordinate — R17's "a spec names a grant, never a path", applied to secret origin, which is also why there is no new R-rule: nothing spec-visible changed, so there is nothing for `plan` to validate. The mapping lives in a node config file (`--secrets-providers-config`, default: does not exist), each provider block carries a **required `allow` list** of local scopes its mappings may write into, and provider credentials are **0600-checked files on the node** — never inline (the config is fingerprint-hashed and quoted in diagnostics) and never `secret:` refs (a credential living in the store it fills would ship in every backup and be overwritable through the write-only API). Clients are **hand-written HTTP, no SDKs** — the §15.3 S3-sink decision for the same reason — with SigV4 extracted from the backup sink into one shared implementation; Azure and GCP authenticate by OAuth2 client credentials and service-account JWT-bearer respectively, tokens cached in memory only. Cloud **ambient identity is deliberately out of v1** (IMDS, managed identity, metadata servers): every variant means dialing the link-local metadata endpoint §14 A10 treats as hostile, and static scoped credentials in files are the honest v1. Sync discipline is where the store's own rules bite: an **unchanged value is never rewritten** (resolve-and-compare in process — a stored plaintext hash beside the ciphertext would be an offline dictionary oracle, and a rewrite per poll is CDC/S3 write amplification, §15.3); a synced secret carries a **`source` provenance marker** in its metadata; a mapping that disappears — from the config or from the provider — **never deletes the local value** (the v1.41 `lb/vip6` rule: stale beats gone, and `kanea secret rm` remains the one deletion path); and a manual `put` over a managed path holds only until the next pass reasserts the mapping, saying so in the log. Failures are visible, not fatal: one provider failing never stops another (§7.3's source isolation), passes surface `secret.synced`/`secret.sync_failed` in the §11 vocabulary, and a metadata-only `GET /v1/secrets/providers` + `kanea secret providers` answer "when did this last work" — the write-only property of §13.3/§16.3 is untouched, and MCP still has no secrets verb. Provider endpoints are operator-written node config, so the §14 A10 egress guard is deliberately not consulted (the §11 invoker precedent: the guard exists for attacker-influencable text, and Vault legitimately lives on RFC1918) — while redirects are refused (a 302 to the metadata service is the residual risk), response bodies are size-capped, and every dial carries a short timeout.

> **v1.43 amendments** — **node GPU VRAM visibility** (§9.1, §12.2, §17). v1.31 gave a spec a way to claim a GPU and stated why a transcoder silently running without one is the failure passthrough resolution guards against — yet once granted, the node's own numbers had nothing to say about the device: an operator sizing a second workload against an 8 GiB card was reading `nvidia-smi` over SSH beside a dashboard that reports everything else about the machine. The node reader grows a GPU half, and it reads what is already there rather than adding a protocol: **amdgpu comes from sysfs** (`/sys/class/drm/card*/device/mem_info_vram_{used,total}` — plain files, the procfs posture unchanged) and **NVIDIA through `nvidia-smi`**, because NVML is a C library and the single-static-binary constraint (§18) rules cgo out. The exec is timeout-bounded, skipped entirely when the binary is absent, and readings are cached for a short interval so a burst of `GET /v1/stats` requests cannot become a process storm — an exec is not a file read, and the reader must not let a polling client fork one per request. Per-GPU readings (name, VRAM used/total/percent) ride `GET /v1/stats` in the existing `node` object; one aggregate — used summed over total across every GPU reporting both — is the **third node series** recorded into the TS as `node_gpu_vram_percent` (v1.38's rule: a name §9.1's exporter never publishes, so the Prometheus surface is unchanged) and served as `gpu_vram` in `GET /v1/stats/history`'s node view. Every field is a pointer and every miss is an absence: a node with no GPU, an unreadable sysfs, a card whose driver reports no VRAM files and an `nvidia-smi` answering `[N/A]` all serve gaps, never zeros — the dashboard renders a GPU panel only when a GPU is visible, because a broken reader must not draw as an idle card (§9.2). Deliberately out of scope, with mechanisms named: per-GPU series in the TS (one aggregate answers the Overview page's question; per-card history is a read of the same sysfs files away if a real need appears), per-*process* VRAM attribution (needs the driver's per-PID accounting — a second protocol per vendor, fbdev/procfs for amdgpu and NVML sessions for NVIDIA — for a number no current consumer reads), and a scaling signal on VRAM (the evaluator's vocabulary is untouched; adding a metric nobody can act on invites a rule that thrashes on a cache that never shrinks).

> **v1.42 amendments** — **UDP published ports** (§5.2.5, §6.2 R21, §7.2.2, §19.3): game servers, plain DNS and syslog become publishable, which is the half of the homelab port story v1.33 left out. (WireGuard fits the block's shape but not the v1 sandbox — it needs `CAP_NET_ADMIN`, which R13 forbids.) A `network { port }` block gains `protocol = "tcp" | "udp"` (default `tcp`), and `publish` gains `mode = "udp"`. The scope is deliberate and asymmetric: **north–south only**. The connect-time LB rewrites `connect(2)` and an unconnected UDP `sendto(2)` never calls it, so a UDP service VIP would need `sendmsg4`/`recvmsg4` programs the datapath does not have and spike ⑤ never exercised — **a UDP port therefore never enters the LB and never gets a frontend**: it is excluded from the VIP's port set, from `expose` (R16's port selection skips it), from `${service.*.port}` references and from `http`/`tcp` health checks, each refused at `plan` by name rather than silently unreachable (R21's dropped-control rule, again). What *is* built is the edge's half, and it is honest about being different machinery: a UDP listener is a **session relay** — the edge binds the node port, and each new client source address opens a session (a connected socket to one backend) that lives until an idle expiry sweeps it. Because there is no VIP to dial, **the routes projection carries the backend alloc addresses for UDP listeners only** — the one place the backend list the VIP design exists to avoid (§7.1) reappears, bounded to this feature, and a backend-set change republishes `routes.json` exactly as a CIDR edit does (`snapshotIsPublished` compares it, per the v1.33 listener lesson). The backend for a session is chosen by **rendezvous hash of the client address over the live backend set** — affinity that survives an edge restart and a session expiry, so a stateful UDP conversation does not silently migrate backends; a backend's departure moves only its own sessions. Policy needs nothing: the edge is a host process and the host identity already passes the tc programs whatever the protocol (§5.2.5) — datagrams to an alloc address are permitted exactly as the edge's TCP dials are. **`ip_restriction` is checked on the datagram that would create a session** — the accept-time hook a datagram socket lacks, recovered at session-create time — and is, as on `tcp`, the entire ingress control: `rate_limit` and `headers` on a `udp` publish are `plan` errors verbatim from the `tcp` rule, and `max_conns` bounds live **sessions** (default 256 per listener, sharing `--max-published-conns`), refused-not-queued as everything else is. A refused or expired session is not silent: refusals and expiries are counted into a new `kanea_edge_udp_*` exposition family beside the `_tcp_` one, because a session cap nobody can see is indistinguishable from packet loss. One host port may now carry one `tcp`-family listener **and** one `udp` listener (53 over both is the DNS shape); the collision maps are keyed per L4 family, within a spec and across the applied set. The §19.3 parking-lot entry narrows accordingly: what remains deferred is **east-west UDP** (the `sendmsg4`/`recvmsg4` rewrite, gated on a spike ⑤ extension), PROXY protocol, and a `bind` address. `Desired.Port` gains the protocol as an `omitempty` field inside the SpecHash material — a declared-`tcp` port normalizes to the empty string before it is stored, so **every existing record hashes exactly as it did** (R23's lesson, pinned by test), while flipping a port's protocol *does* roll the alloc, which is right: what the process binds inside the container is baked into it.

> **v1.41 amendments** — **dual-stack internal IPv6 (opt-in), gRPC to upstreams, and WebSocket support made demonstrable** (§5.2.5, §5.2.6, new §6.2 **R28**, §7.1, §7.2, §9.1.1, §19.3, §23.2). **IPv6 is internal and opt-in**: `kanead` (and `kanea install`/`init`) take `--node-cidr6`, `--cluster-cidr6` and `--service-cidr6` — all three or none, refused by name, because a v6 alloc address without a v6 VIP pool is a half-configured stack whose failures are silent. Set, every alloc gets a v4 **and** a v6 address, every VIP gets a v6 twin (a new `lb/vip6/<project>/<service>` key space; the `lb/vip/` records stay byte-identical, pinned by test), and internal DNS answers AAAA beside A — the deliberate NODATA it has served since v1 remains the answer for any name with no v6 address. The datapath grows **separate v6 maps and a `connect6` program rather than widening the v4 maps**: widening a pinned map's key changes its ABI, and `ErrMapIncompatible` would wipe and recreate every node's pins at upgrade — v4-only nodes included — where new maps cost existing pins nothing. `connect6` also rewrites v4-mapped destinations (`::ffff:a.b.c.d`), because a dual-stack client dialling a v4 VIP through an `AF_INET6` socket bypasses the `connect4` hook and would meet the blackhole route. The policy and allow layers are service-id-keyed and carry over unchanged. SYN gating applies only when the TCP header follows the fixed IPv6 header directly — **there is no extension-header walk**: both endpoints are Linux stacks `kanead` configured, extension headers do not legitimately occur there, and the restriction fails deny-closed; recorded here so the missing walk reads as a decision, not an oversight. The egress guard drops link-local and multicast destinations (`fe80::/10`, `ff00::/8`, a new drop reason), the AWS metadata ULA `fd00:ec2::254` (§14 A10's v6 half), and service-CIDR6 leaks. Allocs get **no v6 default route** — a cluster-CIDR6 route only, so external v6 is ENETUNREACH immediately and Happy Eyeballs falls back to v4 — which is also why there is **no NAT66 and no nftables change**; migrating the `kanea` table to the `inet` family belongs to a future public-IPv6 feature and must not be done early. Addressing guidance is ULA (`fd00::/8`). One deliberate behavior change applies **even with v6 unset**: the tc programs, which have passed non-IPv4 ethertypes untouched since v1.36, now **drop IPv6 unless it is configured** — the kernel puts a link-local on every container interface regardless, so a host service bound to `::` was reachable from any alloc past both policy and the egress guard; an unpoliced side channel is a hole, not compatibility. (Belt and braces: the alloc netns gets `disable_ipv6=1` when v6 is off, and NODAD static-neighbor plumbing with `accept_ra=0` when it is on.) The ifalias — the durable record IPAM rebuilds from — becomes `kanea/<alloc>/<v4>,<v6>`; the v4-only form stays parseable, and a live upgrade **adopts** a v4-only attachment rather than re-plumbing a running workload's veth: the alloc gains v6 at its next replacement, and the v6 backend set simply omits it until then. Kernel behaviour rides spike ⑤'s existing checklist (connect6 under systemd, the v6 tc branches and 20-byte map keys on the 5.10 floor) — the datapath's gate, not a new one. **gRPC is host-routed :443's job** (§5.2.6's claim, now made true): inbound TLS+HTTP/2 was already negotiated (Go's automatic ALPN — now test-pinned rather than accidental), and the missing half was the upstream dial. A new `protocol = "grpc"` on `expose` (**R28**) makes the edge dial that route's VIP over **h2c** — plaintext HTTP/2, a second shared transport beside the HTTP/1.1 one, selected per route — named for the operator's intent rather than the wire detail, and a plain-h2c REST upstream works under it too. R28 refuses at plan what cannot work: `protocol = "grpc"` with a declared `tls { mode = "plaintext" }` (the :80 path is HTTP/1.1 cleartext — no inbound h2c is served — so the route could never carry a real gRPC client), and a `publish` of the same port in `http` mode (an h1 LAN listener on a gRPC port is R21's silently dropped control; `mode = "tcp"` is the correct spelling). An undeclared TLS mode resolving to a `--tls-default plaintext` node is a logged warning, not a plan error — R20 makes that resolution node-side, and plan cannot see it. Functions take no `protocol` — structurally: `trigger "http"` has no such field, and wasi-http is HTTP/1.1. The edge still makes no outbound TLS and no outbound calls; the h2c path's liveness is the HTTP/2 ping (there is no response-header timeout on that path — x/net exposes one only through the wrapped h1 transport — and the limit is stated rather than papered over). A failed upstream answers a gRPC request with the trailers-only refusal (`Grpc-Status: 14` UNAVAILABLE), because a raw 502 renders as garbage in a gRPC client; everything else keeps the anonymous 502. §9.1.1's `protocol` label set grows to `http`/`https`/`websocket`/`grpc` — `grpc` only when the route marker **and** the wire agree (negotiated HTTP/2 plus the `application/grpc` content type as a bounded boolean; nothing is read from `r.Proto`). `Expose.Protocol` is not SpecHash material: changing it republishes routes and must never roll an alloc. **WebSockets were already carried** by the reverse proxy's native upgrade handling; what v1.41 adds is proof and the two fixes an audit found. The per-request body deadline, already cleared for Upgrade requests, is now also cleared for gRPC streams on a marked route — a client-stream held open past five minutes was being killed mid-call. And hijacked connections no longer enter the latency histograms: a three-hour WebSocket session is not a latency, and one of them dominates the `p95_latency_ms` the autoscaler reads; the request counters and the `websocket` label stay. WebSocket-over-HTTP/2 (RFC 8441 extended CONNECT — the edge rejects CONNECT outright), grpc-web translation, TLS re-encryption to upstreams and h2c on published `http` ports go to §19.3 with mechanisms named. `golang.org/x/net` becomes a direct dependency (§23.2) — it was already in the graph.

> **v1.40 amendments** — **request authentication: edge auth middleware and signed invocations** (new §6.2 **R27**, §7.2.1, §11). v1.39 gave functions network-level authorization — the datapath's project boundary, `ip_restriction` — and nothing that authenticates a *request*: anyone who could reach an edge route could invoke the function behind it, and a function could not tell a genuine kanead invocation from a curl by a neighbouring service. Two features close that, each built on a precedent that already exists. **The edge gains an `auth` middleware** (the §7.2.1 roadmap's "edge basic-auth", graduated and widened): an `auth` block on `expose` and on a function's `trigger "http"` names one of three modes — `basic_ref` (htpasswd-format bcrypt lines), `bearer_ref` (a token list), or a `jwt` block (HS256 via `secret_ref`, or RS256/ES256 via `public_key_ref`, with optional `issuer`/`audience`; **keys are static references — the edge fetches no JWKS**, because the process terminating untrusted traffic makes no outbound calls, and an algorithm is *configured*, never read from the token, which retires the alg-confusion class by construction). Every field is a `secret:` reference under R3/R5 — the spec never holds a credential — and **the §5.2.6 boundary decides the delivery**: the edge resolves no secrets and the route table is world-readable, so `routes.json` carries only a fail-closed `auth` marker while the *verifier material* travels in the restricted bundle the edge already polls for certificates (0640, group-read, index-on-change): bcrypt lines pass through as the verifier material they are, bearer tokens are **reduced to SHA-256 hashes before publication** so the file never holds a usable credential, and only a JWT HS256 key crosses as a secret because MAC verification cannot be done with less. A route marked `auth` whose entry is missing or unresolvable answers **503, never open** — the same fail-closed rule a missing certificate gets, because middleware that fails open is R16's original sin. Auth runs **after the rate limit** in the chain, so a credential brute force meets 429 before it meets bcrypt — and bcrypt's per-request cost is bounded by a small success cache keyed by credential hash, which turns a hot path's 100 ms into one comparison without weakening the failure path. Published ports deliberately do **not** take the block in v1 (they are LAN-convenience listeners with `ip_restriction`; one auth config per service keyed by name is the simpler invariant, revisit on demand). **The invoker signs what it sends** (§11): a function block may name a `signing_ref`, and every event and cron POST then carries `X-Kanea-Timestamp` and `X-Kanea-Signature` computed by the *same* `Sign` the outbound webhook channel uses — one MAC implementation, one wire format, and the function verifies before acting, which closes the intra-project spoofing gap. The reference is declared rather than auto-minted: minting a key at apply would mutate a spec the operator wrote (an env var nobody typed, a spec hash moved by the server), and a declared `secret:` reference is one line that composes with rotation the way every other credential already does.

> **v1.39 amendments** — **functions: Wasm workloads as services** (§19.1 promoted out of the parking lot; new §6.2 **R25**/**R26**, §7.2.3, §12.2, §16.1/§16.2, §20 M11). A `function` block declares a WebAssembly module the platform runs for you — Nomad's Java driver, for wasm — and the load-bearing decision is that **it lowers at parse time to an ordinary service** with `runtime = "wasm"`: one Store kind, one reconcile path, so deploys, generation and pin carry-over, the autoscaler, the spec editor and the websocket topics are all inherited rather than reimplemented, and the alternative — a second desired-state kind — would have forfeited exactly the property that makes §19.1's "flows through the existing runtime driver" true. The runtime is **wasmtime via its runwasi shim** (`io.containerd.wasmtime.v1`), not the §19.1 sketch's "wasmtime/wasmedge" either-or: wasmtime is the reference WASI implementation with wasi-http mature and the strongest security process of the candidates evaluated, while WasmEdge remains a CNCF Sandbox project whose component-model support sits on a development branch — and because both install as one static shim binary resolved by name, the choice stays one manifest entry wide to revisit. The shim is a §5.2.12 host component, pinned by SHA-256 per arch like everything else; the generated containerd unit gains the `Environment=PATH=` line its shim lookup always technically needed and never exercised. **Every function is a long-running wasi-http server, and its three triggers are three ways of reaching one endpoint**: `http` lowers to the `expose` machinery (auto-FQDN when the node has a base domain — or, on a node with none, a dedicated **functions port** the edge binds and dispatches by path, §7.2.3, built as a mode of §7.2.2's listener machinery rather than as the parked path-prefix routing); `event` and `cron` are `kanead`-side invokers that POST to the function's own VIP — the event invoker tees off the notification dispatcher's live feed and validates its patterns against the same §11 vocabulary with the same matcher, and cron is a hand-written five-field UTC schedule with missed ticks skipped on restart (the v1.37 shape: no per-sample durable state). **The invoker is deliberately not behind §14 A10's egress guard and does not weaken it**: its targets are private by construction and *derived* — the spec has no URL field anywhere, so reaching an address requires writing the VIP allocator, and the threat model records the argument. R25 refuses by name what the sandbox cannot honour — volumes, devices, sockets, capabilities, `user`, exec probes (the shim has no `task.Exec`) — because a control silently dropped is worse than one the spec never claimed (R21's rule, third application); R26 refuses `function.*` in a function's own event filter, because a function invoked by its own failure event is a feedback loop with no damping. **Invocation metrics come from the datapath's existing per-VIP connect counters** (§9.1), not from edge rps: a connect to a function's VIP *is* an invocation whether it came through the edge, east-west from another service, or from an invoker, and the counters are already on by default with nothing new in the kernel. Deferred with mechanisms named (§19.1 residue): scale-to-zero (the datapath's per-destination drop counters make "connect against zero backends" observable, which is the wake signal an activation path needs), edge-middleware wasm plugins, custom application event names, OCI wasm-artifact packaging, and `scaling` on functions. The dashboard's redesign (§12.2) needs three things the API never served, each small and each stated here before it is built. `GET /v1/healthz` reports `pid`, `started_at` and `uptime_seconds` — facts a header needs before and after login, on the route that already carries the version and listener. **`GET /v1/stats/history`** (§9.1, §16.1) serves the in-memory time series' range read over the API for the first time: per-service `cpu`/`memory`/`rps`/`p95` and a node view, as sparse `{at, value}` points where **a gap is an absent point, never a zero** — the same rule the evaluator, exporter and websocket already obey, enforced at a fourth surface by construction (the ring's unwritten slots are simply not serialised). Two node series (`node_cpu_percent`, `node_memory_percent`, ≈9 KiB) now enter the TS, amending §17's "node stats (procfs)" read-on-demand posture — a sparkline needs the history procfs does not keep — under metric names §9.1's exporter never publishes, so the Prometheus surface is unchanged; node `rps` is summed across services at read time, and node `p95` is an rps-weighted mean, stated as the approximation it is. **The spec editor** (§12.2, §16.1) adds `POST /v1/spec/render` (HCL in; §6.2 diagnostics with file/line, or the converted services — no side effects), `POST /v1/spec/apply` (render, then the *same* apply path `PUT /v1/services` uses — generation carry-over, pinned-image carry-over and the R22 port check are shared by construction, not replicated), and `GET /v1/spec/source` (best-effort HCL generated from the running desired state, marked generated: comments and interpolations from the original file are not preserved, and the round-trip is test-pinned — a spec that cannot round-trip is refused by name, never emitted wrong). Conversion runs on the node through the same seam GitOps sync uses (§10's in-process parse is the precedent), with the node's own base domain, and a render scoped to a project refuses a spec declaring any other — §10's repository boundary and R5's secret boundary, applied to the editor. Render is admin-only; apply is a mutation like any other: admin, CSRF, audited. The dashboard warns before applying over a git-synced project rather than refusing: the next sync wins, and the banner says so.

> **v1.37 amendments** — **restart-durable safety state.** A review of what `kanead` holds only in memory found that the losses that matter on a restart are not the documented ones (metrics rings, IPAM, edge counters — all deliberate and stated) but four pieces of *protective* state whose loss re-enables exactly what they exist to prevent. Each becomes durable at its **transitions**, never at its sampling rate, in the existing `kv` bucket — no new database, no new buckets, and no write path hot enough to matter to §15.3 replication. The circuit breaker's trip survives (§4.3 — `kv:reconciler/breaker`, written on trip and on operator reset; the failure window is deliberately rebuilt live, because a node still faulting refills it within one window and a node that recovered should not inherit stale samples). The autoscaler's per-service cooldown survives (§9.2 — `kv:scaling/cooldown/<project>/<service>`, written **in the same `Apply` batch as the scale action itself**, so it costs no extra replication traffic; the scale-down stabilization *history* is not persisted — that would be a metric stream through the Store, which §18 rule 2 forbids — instead the evaluator refuses to shrink a service until it has *observed* a full stabilization window, which closes the same gap and closes it for newly tracked services too). Account login lockouts survive (§13.3 — `kv:auth/lockout/<account>`, written only on the transition into locked and deleted on the next successful login; **per-source lockouts are deliberately memory-only**, because the source key space is attacker-chosen and persisting it would convert a brute-force attempt into CDC/S3 write amplification — the durable half is the account-centric one, which is the half §13.3's defence is about). Pipeline runs stranded by a crash are swept at startup (§10.2 — no new state: `queued` runs are cancelled with the same vocabulary the graceful drain uses, `running` runs are failed with an honest message, in one `Apply` batch; a queued run is *not* re-enqueued, because its request is derived from the project config and re-deriving it later could build something other than what was queued). Replication's last-segment/last-snapshot times are now **derived from the sink at startup exactly like the cursor** (§15.3) — a stored timestamp would emit a change that needs shipping, which updates the timestamp. Three resets are recorded as decisions rather than fixed: mount backoff (§8 — one honest attempt per mount after a restart, then the existing schedule; a restart is legitimately a moment the operator may have fixed the server), the webhook replay cache (§10.3 — persisting attacker-chosen delivery ids is its own amplification vector, and a replayed delivery re-syncs a commit `LastCommit` already records, which is idempotent), and the notification rate windows (§11 — a restart loop is a node-level incident where suppressed notifications are the wrong failure mode). §5.2.2's claim of an "in-memory desired-state cache" is struck: it was never built, the loop meets §21's budget without it, and §18 rule 1 is safer for its absence.

> **v1.36 amendments** — **Kanea owns its datapath.** Standalone Cilium — and the etcd kvstore that existed only to serve it — is removed, replaced by an internal eBPF datapath (§5.2.5, `internal/datapath`): three programs, seven pinned maps, netlink plumbing and one nftables rule, gated on a spike like everything with kernel behaviour in it ([spike ⑤](./spikes/ebpf-datapath/REPORT.md)). The integration being replaced was thin by design — four REST calls and two watched files — and the platform around it already owned the hard parts: VIP allocation is durable in the Store, DNS is first-party, policy intent is computed at the spec layer. What Cilium supplied was a datapath, at the cost of 176 MiB of the §21 reserve (cilium-agent 153 + etcd 23, measured), a label-PATCH identity race retried against 5xx, a policy-file interface where one malformed file is an agent crash loop, and §22 R1's standing residual: the non-k8s file interfaces had churned once already. The controlling simplification is that **`kanead` allocates every address, so IP is identity** — no identity protocol, no kvstore, no label race. The deny-by-default guarantee moves from a temporal property (the `reserved:init` window, held closed by attach order and retries) to a structural one: policy is attached and identity written before the interface can carry a packet, and an identity miss is a drop. Service LB moves to connect-time socket rewrite at the root cgroup, which preserves the one property the edge depends on — a host process dials a VIP with a plain dialer, §5.2.6 unchanged byte for byte — and adds one Cilium never had: **established connections consult no map**, so `kanead` can restart, or recreate the entire map set, without touching a live flow. Policy enforcement is SYN-gated and stateless rather than conntrack-backed, which is deliberately weaker (an in-node ACK probe passes) and is stated in the threat model rather than hidden; the upgrade to a conntrack map is additive. §14 A10's metadata-endpoint block — which this document claimed and the code never contained — is now an egress program that actually exists. East-west metrics come from the same maps the datapath already writes and are **on by default**; Hubble, which shipped unreachable (no generated unit ever enabled it) and unconsumed, leaves with the agent, and the metric names stay so no scaling spec changes meaning. The v1.1 Cilium transparent-encryption flag (§7.3) is dropped rather than re-scoped: single-node traffic never leaves the kernel, and inter-node encryption is the clustering milestone's question to answer. Nothing has been released, so this is a replacement, not a migration — there is no compatibility mode and no `--network cilium`; the dev/CI mode `--network netns` remains.

> **v1.35 amendments** — gives the edge an **observability surface rather than an autoscaler input** (§9.1, new §9.1.1, §21). The four series `kanea-edge` published were designed for exactly one reader, the evaluator, and they answer exactly its question: is this service busy. They cannot answer any question an operator asks while something is broken — *which* status codes, how much data moved, how many connections are open, when the projection last reloaded, when the certificate expires. Traefik answers all of those and people arriving from it reasonably expect them. Three surfaces were at **zero** coverage: **published TCP ports** (§7.2.2) had no counters at all, and `ErrTooManyConns` carried a comment saying it existed "so the refusal is countable" while nothing counted it; **certificate expiry** was unmeasured across all three §7.3 sources, which for a self-hosted platform is the single most valuable number there is; and **projection reloads** had no signal, so "the route never went live" and "the route is wrong" looked identical. The load-bearing decision is that **the labelled series never enter the metrics store**. `internal/scaling`'s in-memory ring is the autoscaler's input — §18 rule 2, a 20 000-series cap and a measured ~27 MiB at target scale — and pushing `{service,code,method,protocol}` through it would break the cap and the footprint together *and* corrupt the evaluator, which wants one `rps` per service and not forty. So there are two paths: the existing scrape differences five low-cardinality gauges into rings exactly as before, and a second retains the labelled counters **verbatim** for the exporter. Passing them through unaltered is also what makes counter semantics correct — an edge restart is a real counter reset and `rate()` handles that natively, where the differencing path has to detect it and discard the interval. **Cardinality is bounded by construction, not by hope.** `method` is a token an attacker chooses, so it is allowlisted to the nine RFC methods and everything else folds to `OTHER`; `protocol` is derived from the connection rather than read from `r.Proto`; and a hard per-service ceiling folds further combinations into one overflow series and increments a visible drop counter, the discipline the metrics store already uses. **`server_up` is emitted only where a `check` block exists**, because `AllocRecord.Healthy` is written solely by a probe and a check-free service reads false for every alloc forever — that is §9.2's "no data is never zero" applied to health, where reporting a missing probe and a dead backend as the same number is the whole failure. `kanea_edge_up` exists so that a gap is explainable: `kanead` does not supervise the edge (§5.2.6) and must keep answering when it is down.

> **v1.34 amendments** — lets a spec say **who a container runs as** (§6.2 **R23**) and **who owns its data** (§6.2 **R24**), which v1 could express neither of. This is a §14 A05 change before it is an ergonomic one, and the evidence was already in this document: §6.1's postgres task granted `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID` and `CAP_DAC_OVERRIDE` — the last of which bypasses file permission checks outright — for one reason, that its data directory was root-owned and the container had to fix that itself before it could drop privileges. **The platform handed a workload the power to escalate because it could not state the one fact that made escalating unnecessary.** With `user { uid = 999, gid = 999 }` and a volume owned to match, that task now starts with **no capabilities at all**, and §6.1 has been rewritten to show it. The two rules ship together because each is inert alone: a non-root user with no writable volume cannot start, and a volume owned by a uid nothing runs as is decoration. **IDs are numeric, never names.** Resolving `user = "postgres"` means reading `/etc/passwd` out of the image's own rootfs, which is a container-controlled file deciding which uid the control plane runs a process as — `kanea exec --user` already refused exactly this, and the job spec does not get a weaker rule than the debug command. A name is also not stable across a rebuild, so under R19 auto-update it would silently come to mean a different uid than the one that was reviewed. **A volume inherits the task's user unless it overrides it**, because the failure mode of not inheriting is a permission denial at startup — precisely what this exists to remove — and the defaulting is spec-internal rather than node-dependent, so unlike `expose.tls` it is resolved at conversion and `kanea plan` shows what will actually happen. **Ownership is refused wherever the driver cannot enforce it**: on `host`, because R15's directory belongs to the operator and chowning it is the same trespass as creating it, and on `nfs`, because the kernel client has no `uid=` and ownership is the server's to decide. That is R21's rule about a control the layer below silently drops, applied to storage — `smb`, `s3fs` and `mountpoint-s3` all take ownership at mount time and get it, and the two that cannot are a `plan` error rather than a field that reads as enforced and is not. **Inheritance stops at those two**, so only a *declared* field is ever refused: a default that became a hard error would mean adding `user` to a task broke every NFS volume that service happened to have, and there would be no field to opt out of something nobody wrote. The chown is the volume's top-level directory only, at each alloc start: bounded and idempotent, where `chown -R` would put O(files) in the alloc start path and would overwrite ownership a workload set deliberately.

> **v1.33 amendments** — makes a node with no public name usable, which is the shape most single-node installs actually have. Three things, and they are one story: a homelabber points a wildcard record at a box on their LAN, has no inbound port 80 for HTTP-01 and no DNS provider for DNS-01, wants Jellyfin on `:8096` and Postgres on `:5432`, and already uses `10.244/16` for something else. **The certificate bundle becomes a merge of three sources** (§7.3) — ACME, a per-node self-signed CA, and certificates the operator put on the node — and `kanea-edge` is unchanged by that, which is the test of whether the seam is in the right place: it polls one file and does not know what signed anything in it. **`kanead` still owns every source**, because issuance is *writing*, and the edge not writing is the property §5.2.6 exists to preserve; a CA private key living in the process that terminates untrusted public traffic is precisely what this design refuses. **A spec names a certificate source, never a path** — R17's rule applied to TLS: `mode = "provided"` names a grant an operator defined in the node's own config, the certificate's own SANs decide what it covers, so a wildcard needs no filename convention and a declared domain list that could disagree with the certificate does not exist. **Plaintext becomes declarable** (§6.2 **R20**): it was already reachable and nobody could say so, since a service with no certificate silently served HTTP; a declared-plaintext route is now never redirected and never receives HSTS — the one header a mistake in which the browser remembers for two years. The **self-signed CA is deliberately not a §15.4 key-ceremony artefact**, and the reason it is not is the reason the master key is one: the master key is unrecoverable and every backup dies with it, while the CA lives in the Store, travels in the archive, and costs a re-trust rather than the platform. **`--acme-directory` stops defaulting to Let's Encrypt staging** — staging existed to absorb a first-attempt misconfiguration, and `--tls-default self-signed` does that better, with a certificate that actually works instead of one every browser rejects. Second, **services can be published on node ports** (§6.2 **R21**/**R22**, new §7.2.2), which v1 could not express at all. **It lives in the edge, not in netfilter**: a DNAT rule can only target an alloc address, which reintroduces the backend list the service-VIP design exists to avoid and makes the data path depend on `kanead` having run recently, while Cilium's own hostPort is fed by a Kubernetes watcher that does not exist here. **The two listener kinds are named separately because they guarantee different things** — an alternate-port HTTP listener keeps the whole §7.2.1 chain, a raw TCP listener keeps only `ip_restriction`, and a spec declaring middleware a TCP listener cannot honour is a `plan` error rather than a silently dropped control: R16's "an ingress control that fails open is worse than one that is absent", inverted. **On a TCP listener the upstream sees the edge's address, not the client's**, so `pg_hba.conf` host rules and address-based bans become meaningless behind a published port; `ip_restriction` is enforced at accept time, before a byte is forwarded, and that is the entire mitigation. **The permitted port range is the node's decision**, like `storage.allowed_host_paths` and the passthrough grants, because a spec is not a trusted document and a GitOps push that could claim `:22` would be deciding something that belongs to whoever owns the machine. Third, **the container subnet is an install-time flag** (§5.2.5): it was compiled in, the flags that existed on `kanea supervise cilium` were never passed by anything, and neither CIDR was validated or checked for overlap against the service CIDR.

> **v1.32 amendments** — adds **image auto-update** (§6.2 **R19**, §6.1 `update`), the feature people reach for watchtower to get, and adds it as *policy* rather than as a container holding the runtime socket. v1.31 made that container possible; this makes it unnecessary, which is the better answer for the same request. The mechanism is already built: §10.2's pipeline pins a built digest onto a service and the reconciler converges, so an updater is that seam with a different trigger — **it is not a second deployer any more than the autoscaler is a second scheduler** (§9.2). It resolves the tag a service already declares, and when the digest behind it moves, pins the new one; `SpecHash` changes, and the *existing* rolling update runs with the `max_parallel`, `min_healthy` and health checks that every other deploy gets. Three things follow from that and are worth stating. **It deliberately follows a moving tag**, which is the one thing §14 A08 otherwise refuses — so it is opt-in per service, off by default, refused on a service whose image is already a digest (there is nothing to follow) and refused on a service with a `build` block (the pipeline owns that image, and two writers pinning one field would fight). **The declared tag stays in the spec and the resolved digest lives beside it**: `image` remains `jellyfin/jellyfin:10.9` and a separate pinned digest is what actually runs, because pinning over the tag would destroy the thing the next poll has to re-resolve. That digest is server-owned state, so an apply preserves it exactly as it already preserves the restart generation and the sync loop's last commit — an apply that reset it would redeploy the service on every `kanea apply`. **A failed update reverts.** Unattended is the case where nobody is watching, so the previous digest is kept and re-pinned if the new one does not converge within a deadline; convergence means healthy where a `check` block exists and not crash-looping where it does not, because `AllocRecord.Healthy` is written only by a probe and a service with no check would otherwise look permanently failed. Also adds **registry credentials to the pull path** (`task.registry_auth_ref`), which did not exist at all: `EnsureImage` pulled anonymously, so private images never worked and an updater that could not read a private registry would have been a feature for public images only.

> **v1.31 amendments** — adds **host device and socket passthrough** (§6.2 **R17**/**R18**, §15.1, §14 A05), the two things a single-node platform is asked for that v1 could not express at all: a transcoder that needs `/dev/dri`, a dongle on `/dev/bus/usb`, and the watchtower-shaped container that expects the runtime socket at `/var/run/docker.sock`. Both are holes in the §14 A05 hardening defaults, and the honest way to add them is to say so rather than to find a phrasing under which they are not. The model is **R15's, extended twice**. R15 already separates *shape* from *permission* — a spec says what it wants, the server config says what is allowed, and the default allows nothing — and that split survives here unchanged, because it is the only part of this that is load-bearing. What R15 does not do, and this does: **a spec names a grant, never a path.** An operator defines `device "gpu"` or `socket "containerd"` in the node's own config and a spec asks for it by name; the node resolves the name locally, so no host path ever enters the Store, the API or a git repository. That is §18 rule 5 applied to a case that would otherwise violate it quietly — `handleApply` round-trips a desired record verbatim, so a path *field* on that record is an input surface whether or not the HCL parser is the thing that filled it. And **grants are project-scoped**, which `storage.allowed_host_paths` is not: a prefix allowlist is proportionate for a shared data directory and is not proportionate for a socket, so each grant names the projects that may claim it and a grant naming none is a config error rather than a permissive default. **A socket grant confers node-level control on the container that receives it, and this document does not claim otherwise.** A container holding the runtime socket can start another container without the hardening defaults; there is no containment story, and the alternative that would have one — a filtering proxy exposing a narrowed verb set — is a second protocol to implement, keep current with containerd, and be wrong about in exactly the cases that matter. The control is that an operator, on the node, in a file no spec author can write, decided which project gets it. That is the same control R15 has, applied to a larger consequence and therefore named more precisely.

> **v1.30 amendments** — **Kanea installs, pins and supervises the node's runtime layer** (new **§5.2.12**), which the document had assigned to the operator in §5.1 and half-assigned to `kanea init` everywhere else. §5.2.4 already said init *can* install containerd and §5.2.11 already made it responsible for the entire rootless build daemon; neither was built, and three code comments claimed setup work init had never done. The honest reading is that Kanea had already chosen these versions — §5.2.5 dictates a mandatory cilium-agent flag set, §15.4 requires a version matrix, and M0 found behaviour that moves between releases in both directions (the writable service REST API **removed** in Cilium 1.18; BuildKit's `filename=` default) — so the prerequisite list was making an operator type out a decision Kanea had made for them, and owning it badly. **Components are pinned by version and SHA-256 in a manifest compiled into the binary**, which *is* the §15.4 version matrix rather than a second copy of it to drift: a hash fetched from beside the artefact proves only that the two agree, so bumping a component is now a code change with a review. **They install under Kanea's own prefix, on Kanea's own sockets** — a node that ran Docker yesterday still runs it tomorrow, and an install that breaks other software is not a property a single-binary platform gets to have; adopting an existing containerd stays available on request and is the one case §5.2.11's drop-in language still describes, because **you do not need a drop-in for a unit you wrote**. **Cilium runs as a containerd task while BuildKit's binaries are extracted to the host** — an asymmetry with a reason: buildkitd is self-contained, whereas cilium-agent needs its bundled helpers, its iptables and its BPF templates, and unpacking that image onto a host is unsupported upstream and a large surface to get quietly wrong; M0 spike ① validated the task form 25/25 and that is the form that ships. **The offline bundle is in the first cut rather than deferred**: install code that is *handed* bytes instead of fetching them costs almost nothing to build now and cannot be retrofitted without producing a second install path that nobody exercises — and an installer that assumes egress excludes precisely the environments most likely to want a single-node platform with no Kubernetes in it. A bundle is verified against the hashes in the binary and never against a manifest of its own, since a bundle that supplied its own hashes would be a bundle that authenticates itself. §21's platform prerequisites accordingly narrow to what no installer can supply: a kernel, cgroups v2, systemd and a clock.

> **v1.29 amendments** — covers **publication**, which the document had been silent on. Kanea is released under **Apache-2.0** and that is now a requirement in §21 rather than a file nobody specified: the patent grant is the reason, and for a platform whose whole premise is that you can run it yourself, the terms on which you may are part of the product. The **repository is deliberately not named here** — a URL is packaging, it changes when an org does, and a document that hard-codes one acquires a class of edit that teaches nobody anything. **§20 M10's exit criterion moves from "v1.0 tagged" to "v0.1.0 tagged"**: §14 A06 and §21 both require an SBOM attached to releases and the release workflow publishes none, so a v1.0 cut today would fail its own non-functional requirements on the one artefact that runs as root. What v1.0 additionally needs is now stated where the criterion is, instead of being inferred from two other sections. The **status moves from Draft to Adopted** — the document is public, the site presents it as the specification, and "Draft" on a specification that has driven ten milestones describes the process that produced it rather than its standing. Finally: the landing page's job-spec example is checked against `internal/jobspec`'s own parser and validator rather than written from memory, for the reason v1.10 records — a §6.1 example that does not parse is worse than no example, and single-line HCL blocks are exactly where that goes wrong.

> **v1.28 amendments** — records the **exec protocol** (§16.2). A debug shell is the most privileged thing the API does, so it is the one route marked mutating purely for its consequences: admin-only, and audited *whether or not the session establishes*, with the requested command in the entry — "someone tried to open a shell on production" is worth keeping either way. The command crosses the wire as **repeated query parameters rather than one joined string**: joining means the server has to split, and every splitting rule is wrong for some argument someone will eventually pass. The CLI requires `--` before the command for the same reason at the other end. Data travels as binary frames prefixed with a stream byte and control as JSON text frames, so a shell echoing a build log does not pay for a JSON parse per keystroke; with a TTY there is one stream, because that is what a pseudo-terminal is. `--user` takes a **numeric uid only** — resolving a name would mean reading the container's own `/etc/passwd`, and a container-controlled file deciding which uid the control plane runs a process as is not a thing to build. Also closes §17's **node stats** (procfs CPU, memory and load, every field a pointer so "no reading" and "idle" stay distinguishable), ships **`kanea upgrade`** as orchestration only, and adds **keyless release signing**.

> **v1.27 amendments** — records what **M10's state replication** settled that §15.3 left open. **Archives use chunked AEAD, and the last chunk is sealed under different additional data** — without that, anyone with write access to the bucket could truncate a snapshot and a restore would decrypt cleanly to a shorter-but-valid plaintext, bringing back half a platform. **Archive keys are HKDF-derived from the master key** rather than being it, and the manifest carries a derived *fingerprint*, so restoring with the wrong key says so instead of failing as an authentication error indistinguishable from corruption. **Manifests are unencrypted and hashes are over the ciphertext**, so someone holding the bucket and no key can still find out what is there and whether it is intact — which is the question asked *before* going to look for the escrowed key. **The S3 client is hand-written against the REST API** (SigV4, four verbs), on the reasoning v1.20 already applied to lego's provider catalogue. **The replication cursor is derived from the sink**, not stored: in the Store it would emit a change that needs shipping, which writes the cursor again. **A replay that meets an unreadable segment stops** rather than skipping it — a delete in the missing segment would never happen and the record it removed would come back to be started by the reconciler; `--skip-replay` is the deliberate escape hatch. Adds **staged restore**: §15.3's "on a stopped node" is right, but "stopped node" and "shell access" are not the same requirement, so a restore can be requested over the API and is performed at the next start, before anything opens the Store — the same path first-boot auto-restore uses. Three tools §16.3 named against a subsystem that did not exist (`list_backups`, `create_backup`, `restore_backup`) are now registered. **`backup.succeeded` and `backup.failed` fire on transitions only.** Also: §15.4's migration framework ships with no migrations, because the ordering it establishes — copy, then migrate, with each step's data change and version bump in one transaction — has to be right before the first schema change, not after; and the **key-escrow ceremony** is `kanea init`, which prints the key once and requires it typed back, discarding it if that fails.

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

**Kanea** is a lightweight, single-binary container orchestration platform written in **Go**. It combines the operational simplicity of HashiCorp Nomad with **its own eBPF networking and load-balancing layer** (§5.2.5), running workloads on **containerd** — with **no Kubernetes dependency anywhere in the stack**.

Kanea targets the gap between "SSH into a box and run docker compose" and "operate a full Kubernetes cluster": a platform a single operator can install in minutes, understand end-to-end, and use to run **hundreds of services** with automatic TLS, service discovery, load balancing, autoscaling, GitOps-driven deployments, and a real-time web dashboard.

**One-liner:** *Nomad's simplicity, eBPF's power, one binary.*

### Positioning

| | Kubernetes | Nomad | **Kanea** |
|---|---|---|---|
| Operational complexity | Very high | Medium | **Low** |
| Networking | CNI sprawl | Bridge/CNI | **First-party eBPF, built-in** |
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
                    containerd     eBPF datapath     Edge proxy
                   (tasks/imgs)  (veth/LB/policy)  (routes/TLS)
                        │               │                │
                        └───────────────┴────────────────┘
                                        ▼
                            Actual state / events / metrics
```

- A **reconciler** continuously converges actual state to desired state (k8s controller-style), rather than one-shot placement. Crashed allocs are restarted per restart policy; drift (manual container deletion, a torn-down attachment) is corrected automatically.
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
   │ (containerd)   │ (eBPF datapath:  │ pipeline runner    │ (webhooks/TG/Slack/SMTP/ntfy)       │ │
   │                │  maps + netlink) │ (Git + BuildKit)   │                                     │ │
   └───────┬────────┴────────┬─────────┴─────────┬──────────┴─────────────────────────────────────┘ │
           │                 │                   │                                                  │
           └─────────────────┴───────────────────┴──────────────────────────────────────────────────┘
                             │ State replicator / backup manager ──▶ S3-compatible storage

   ┌─── kanea-edge (separate supervised process; reads routes + certs from Store) ───┐
   │  Edge ingress proxy: L7 routing, TLS termination, LE certs, L7 metrics          │ ◀── public :80/:443
   └─────────────────────────────────────────────────────────────────────────────────┘

   Host components (Kanea installs, pins and supervises them — §5.2.12):
               containerd + runc │ rootless buildkitd

   External:   Linux kernel (eBPF, cgroups v2, netfilter, bpffs) │ systemd
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
- Store reads are **bounded and paginated** (long bbolt read transactions block the single writer), keeping the reconcile loop within budget at target scale (§21). *(v1.37: an earlier revision claimed an in-memory desired-state cache backing these reads; none was ever built, the loop meets the budget without it, and the reconciler reading the Store directly is the safer shape under §18 rule 1.)*

#### 5.2.3 Store
- **BoltDB** (bbolt) embedded KV, buckets: `projects`, `services`, `allocs`, `events`, `certs`, `secrets`, `pipelines`, `audit`, `kv`.
- All access behind a `Store` interface with explicit transaction semantics — a Raft-backed implementation (hashicorp/raft + FSM) can replace it for clustering without touching call sites.
- Single-writer model: all mutations serialize — fine at v1 scale, but **metrics and logs never go through the Store** (in-memory TS + file pipelines only, §9/§17).
- bbolt files never shrink in place → **scheduled compaction** (copy-based) keeps the DB — and the backups derived from it — from growing monotonically.

#### 5.2.4 Runtime driver (containerd)
- Talks to containerd over its socket via the official Go client (`github.com/containerd/containerd/v2/client`).
- One containerd **namespace per project** (`kanea-<project>`) → free isolation of images/containers per project.
- Responsibilities: image pull (with auth from secrets store; digest pinning supported), container/task lifecycle, per-alloc network namespace setup (attached by the datapath, §5.2.5), cgroup metrics sampling, stdout/stderr capture (§17).
- **Kanea installs containerd itself** at the version its manifest pins (§5.2.12), under its own prefix and on its own socket, and supervises it with a unit it wrote. A containerd already on the node is left alone — it is another program's, and replacing its socket would make installing Kanea an act that breaks other software. `--containerd external` adopts an existing daemon instead, for the operator who wants one runtime on the box; that is the only configuration in which Kanea depends on a containerd whose version it did not choose, so it is the only one that has to be asked for.
- **Node disk hygiene:** image GC (keep-last-N in use), **build cache caps across both content stores** — containerd's and the rootless `buildkitd` user's `$HOME/.local/share/buildkit` (§10.2) — per-service log caps (§17); disk watermark alerts at 80%/90% (event + notification). One disk holds images, logs, state, and volumes — pressure must never surprise the control plane.

#### 5.2.5 Network driver (internal eBPF datapath)
- The datapath is Kanea's own (v1.36): three small eBPF programs, a handful of pinned maps and plain netlink plumbing, all loaded and written by `kanead` from one compiled-in object (`internal/datapath`). There is no network agent, no kvstore and no CNI — the platform that allocates every address is the program that writes the kernel's maps with them. The Cilium integration this replaces is recorded in the v1.5–v1.35 amendments and in [spike ① report](./spikes/cilium-standalone/REPORT.md), which stays as the history of why those versions look the way they do.
- **IP is identity.** `kanead` allocates every alloc IP from the node CIDR and every service VIP from the service CIDR (durably, in the Store — §7.1), so the identity map (`pod IP → {project, service, flags}`) is written by the allocator itself: no identity-allocation protocol, no label race, no settle window. The numeric project/service ids behind the maps are Store-allocated, monotonic and never reused, which is what keeps pinned map contents meaningful across a `kanead` restart.
- **The subnet is the operator's, and it is set at install time** (v1.33). `kanea install` and `kanea init` take `--node-cidr` (this node's alloc allocation range) and `--cluster-cidr` (the routed, masqueraded range), and write them into the `kanead` unit they generate — `kanead` is the IPAM, so the flags belong on its argv. Both are validated as IPv4 prefixes, the node CIDR must sit inside the cluster CIDR, and **neither may overlap the service CIDR** (§7.1). Changing the node CIDR also moves the internal resolver, which binds the first address of the node CIDR on the `kanea0` host interface — the address every alloc's `resolv.conf` points at and the identity host-originated traffic carries. **Dual-stack is the same trio, suffixed** (v1.41): `--node-cidr6`, `--cluster-cidr6` and `--service-cidr6` — all three or none, with the same containment and non-overlap rules, ULA (`fd00::/8`) recommended. Set, they add a v6 address to every alloc, a v6 twin to every VIP, and AAAA answers to internal DNS; unset, nothing changes except that the tc programs now **drop** IPv6 instead of passing it unpoliced (see below).
- **Attach is synchronous and deny-closed.** Per alloc, in order: netns → identity map write → veth pair created with the host side **down** (`kn` name prefix + an ifalias recording `<alloc>/<ip>` — the ownership mark that makes reaping safe) → policy programs attached at tc on the host side → addresses and static neighbors → link up → the host `/32` route **last**. The first moment a packet can reach or leave the alloc, policy is already enforcing with identity already resolved; a skipped step fails closed, because an identity miss is a drop. The deny window this replaces was temporal (Cilium's `reserved:init`, held shut by attach order and bounded retries); this one is structural. Attach has no wait loop and completes in milliseconds.
- **Service LB is connect-time socket rewrite.** One cgroup `connect4` program at the root cgroup (`BPF_F_ALLOW_MULTI`, held by a pinned link) rewrites `VIP:port → backend` at `connect(2)` — for host processes and containers alike, which is the one property `kanea-edge` depends on: it dials a VIP with a plain dialer (§5.2.6, unchanged). Backends update by **generation flip**: the new set is written under the next generation, one atomic map update of the service entry commits it, the old generation is deleted — a concurrent `connect()` sees a complete old set or a complete new set, never a torn one. There is no per-packet NAT and no conntrack entry per flow, and **an established connection never consults a map**: `kanead` can restart, or recreate every map, without touching live traffic. A VIP with no backends refuses at `connect()` (EPERM) rather than black-holing into a timeout. **Service ports are TCP-only in v1**: a `protocol = "udp"` port (v1.42) never enters the LB and never gets a frontend — it exists only to be published (§7.2.2), and everything that would rely on a frontend (`expose`, `${service.*.port}` references, `http`/`tcp` health checks) refuses it at `plan` by name, because a UDP port the LB silently did not balance would be R21's dropped control. East-west UDP needs `sendmsg4`/`recvmsg4` programs and stays in §19.3.
- **Policy is ingress at the veth, SYN-gated, union-only.** The tc program on each host-side veth admits: a source with the host flag (`kanead`'s DNS replies and probes, the edge's upstream dials), a source in the same project, or a source named by an `allow_from` edge (R14) — and **drops everything else, including any source the identity map does not know**. Enforcement is per connection attempt: TCP that is not a SYN passes, which is what lets cross-project replies flow without a conntrack. That is deliberately weaker than stateful tracking — an in-node ACK probe passes the filter and is stopped only by the stack's RST — and is stated in `docs/THREAT_MODEL.md` rather than hidden; the upgrade to an LRU conntrack map is additive. Rules only ever union: an `allow_from` entry adds reachability and can never weaken the project default-deny.
- **The egress program is small and load-bearing:** it drops the metadata range `169.254.0.0/16` (§14 A10 — enforced in the kernel with a per-alloc drop counter, not claimed in a policy file) and any service-CIDR destination that escaped connect-time rewrite, and it counts per-endpoint traffic. With v6 enabled it also drops link-local and multicast destinations (`fe80::/10`, `ff00::/8`), the AWS metadata ULA `fd00:ec2::254`, and service-CIDR6 leaks.
- **Dual-stack is separate v6 maps beside the v4 ones, never widened v4 maps** (v1.41): `svc_v6`/`svc_backends6`/`identity_v6` and v6 stats twins, plus a `connect6` program under its own pinned link, attached only when v6 is configured. Widening a pinned map's key changes its ABI and would wipe every node's pins at upgrade; new maps cost existing pins nothing. `connect6` also rewrites v4-mapped destinations (`::ffff:a.b.c.d`) — a dual-stack client dialling a v4 VIP through an `AF_INET6` socket bypasses `connect4` and would otherwise meet the blackhole route. The policy layer is service-id-keyed and needs no v6 half; SYN gating requires the TCP header at the fixed offset (no extension-header walk — deny-closed, recorded in v1.41). **When v6 is not configured, the tc programs drop `ETH_P_IPV6` outright**: the kernel assigns link-locals regardless, and unpoliced IPv6 between a container and a host service bound to `::` was a policy bypass, not compatibility. Allocs get a cluster-CIDR6 route and **no v6 default route** — external v6 fails fast to Happy Eyeballs, which is why there is no NAT66 and the nftables masquerade rule is untouched. The ifalias grows to `kanea/<alloc>/<v4>,<v6>` with the v4-only form still parseable; a live upgrade adopts a v4-only attachment rather than re-plumbing a running veth, and the alloc gains v6 at its next replacement.
- **Masquerade is one nftables rule**, in an owned `kanea` table (kernel conntrack does the NAT — a BPF SNAT would be reimplementing netfilter to avoid a rule netfilter already has). A FORWARD-drop policy installed by another tool (docker, ufw) can eat routed pod traffic across tables; `kanea doctor` detects and names it.
- **Datapath state is derived state, and it survives restarts.** Programs, maps and the cgroup link are pinned under `/sys/fs/bpf/kanea` with a schema stamp; a `kanead` restart leaves the dataplane untouched (§15.4), and a stamp mismatch recreates and repopulates the maps inside the first reconcile pass — safe precisely because established flows bypass them. IPAM is rebuilt from the marked veths at startup; everything else from the Store. Nothing under the pin root is ever backed up (§15.3).
- **East-west counters come from the programs that are already there** — per-service connects, per-endpoint bytes, drops by reason, in per-CPU maps read at scrape time (§9.1). On by default, because they cost map increments rather than per-request parsing.
- **The build is committed, and the node needs no toolchain.** Programs are compiled at development time (bpf2go under a digest-pinned LLVM container) and the generated loader and object are committed; `go build` needs no clang, CI verifies the artifacts match the source, and the target node needs no BTF — the programs read only UAPI context types, so there is no CO-RE and no `vmlinux.h`.
- **Kernel behaviour is spike-gated** ([spike ⑤](./spikes/ebpf-datapath/REPORT.md)): connect-time LB from host and alloc under systemd, pinned-link and tc-filter survival across loader exit, the generation flip under load, netfilter interplay, and the 5.10 floor — validated on real kernels before the driver ships, the way spike ① gated the driver this replaces.

#### 5.2.6 Edge ingress proxy (`kanea-edge` — separate process)
- Lightweight L7 reverse proxy (Go `httputil.ReverseProxy` core) — the datapath is deliberately L3/L4 (§5.2.5), so Kanea owns north-south HTTP(S) here.
- **Runs as its own supervised process** (same binary, `kanea edge`; separate systemd unit, `Restart=always`): a `kanead` crash/restart/upgrade never interrupts public traffic, and an edge OOM never takes down the reconciler. The unit runs as a dedicated `kanea-edge` user with only `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, and sits in `kanea.slice` (§5.2.11).
- **How it gets its state — the edge snapshot.** The Store is the source of truth, but the edge does not open it: bbolt locks the whole file, so a second process opening `state.db` even read-only blocks until `kanead` exits rather than returning stale data. Instead `kanead` **projects** what the edge needs — routes (host → service frontend), certificates, and pending ACME challenge responses — into `/run/kanea-edge/routes.json`, written temp-then-`rename(2)` so a partially written file is never observable. The edge polls that file and reloads on change; the projection carries the Store index it was built from, so a reload can be logged and a stale snapshot recognised.
  - **One direction only.** The edge never writes state. That is what lets it run as an unprivileged user with no Store access, and it means a compromised edge — the process that terminates untrusted public traffic — cannot mutate the platform (§14, A01). It is also why `kanead` and not the edge runs ACME (§7.3): obtaining a certificate means writing one.
  - **Two files, two permissions.** Routes (`routes.json`, 0644) carry nothing secret — the domains are in public DNS. Certificates (`certs.json`, 0640) carry private keys. They are separate files precisely so neither has to compromise: the route table stays readable by whatever user the edge runs as, and the key does not.
  - **The certificate bundle is a merge, and the edge is not told what merged it** (v1.33, §7.3). `kanead` publishes one file holding certificates from every configured source; the edge selects on SNI and has no notion of ACME, of a local CA, or of a file an operator dropped on the node. That is the test of whether the seam is in the right place — adding a fourth source should not be an edge change, and it is not.
  - **A missing or stale snapshot is not an outage.** The edge keeps serving the last table it loaded for as long as `kanead` is absent, and starts with an empty table (every request 404) rather than refusing to start if the file does not exist yet. "The control plane is down" must never become "the site is down" (§21).
- Routes `Host: service.project.<base_domain>` → the service's VIP (§7.1). **WebSocket and gRPC are supported, and the mechanics are stated** (v1.41): WebSockets ride the reverse proxy's native Upgrade handling — HTTP/1.1 inbound only (an HTTP/2 client does not upgrade; RFC 8441 extended CONNECT is not supported, §19.3), the per-request body deadline is cleared on upgrade, and a hijacked connection is counted but never timed (§9.1.1). gRPC is TLS+HTTP/2 inbound on :443 (Go's automatic ALPN, pinned by test so a `tls.Config` edit cannot silently kill it) and **h2c to the upstream when the route's `expose` block declares `protocol = "grpc"`** (R28) — a second shared plaintext-HTTP/2 transport beside the HTTP/1.1 one, selected per route. The edge still makes no outbound TLS and no outbound calls; h2c-path liveness is the HTTP/2 ping, and there is no response-header timeout on that path (stated, not hidden). A dead upstream answers a gRPC request with the trailers-only `Grpc-Status: 14` rather than a 502 a gRPC client renders as garbage.
- **The edge also binds the node ports services publish** (v1.33, §7.2.2), from the same projection and the same poll. Adding, removing or reconfiguring one is a live operation: an upstream, address restriction or connection-cap change is swapped behind the socket, so redeploying one service never drops a live session on another port or on its own, and only a change of listener *kind* rebinds. **A bind that fails is a recorded failure, not an outage** — a port held by something else on the node must not freeze the whole route table, so the rest of the snapshot takes effect, the reason is reported on the status listener, and the next poll retries. An accept loop dying on a published port can never take down 443.
- Terminates TLS with certificates `kanead` published (§7.3); redirects HTTP→HTTPS **except for a route the operator declared plaintext** (R20), which is also the one route that never receives HSTS even when the request arrived over TLS — a certificate this node happens to hold for other services is not the operator saying they want this one redirected, and HSTS is the single header a mistake in which cannot be taken back. Security headers otherwise injected (§14, A05).
- **Hardening (required, not optional):** `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout`/`MaxHeaderBytes` (slowloris), per-route upstream timeouts, bounded connection pools, flush intervals for streaming, client-supplied `X-Forwarded-*` stripped, unknown `Host` → 404 (also DNS-rebinding defense for the co-hosted API), `GOMEMLIMIT` set.
- **Edge middleware chain (per service, from the `expose` block — §6.1, §7.2):** Host match → IP allow/deny → rate limit → header transforms → upstream proxy. Middleware config is validated at `kanea plan` time — fail-closed, never silently ignored at runtime.
- **Primary source of per-service L7 request metrics for exposed services** (rps, latency percentiles) — it's already in the request path at zero extra data-plane cost; the datapath's map counters cover east-west (§9).

#### 5.2.7 GitOps syncer + pipeline runner — see §10
#### 5.2.8 Autoscaler — see §9
#### 5.2.9 Notifier — see §11
#### 5.2.10 State replicator / backup manager — see §15.3

#### 5.2.11 Resource isolation (cgroups v2)

The control plane must survive anything workloads do — a runaway container can never starve, OOM-kill, or fork-bomb `kanead`/`kanea-edge`. Enforcement is cgroups v2 (already a hard platform requirement, §21), arranged as two sibling slices:

```
/sys/fs/cgroup
├── kanea.slice                 # kanead + kanea-edge (+ containerd and buildkitd, via their own units)
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
- **Setup:** `kanea init` installs the `kanea.slice` / `kanea-workloads.slice` systemd units. Since v1.30 the host components' units are Kanea's own (§5.2.12), so each simply declares `Slice=kanea.slice` — **you do not need a drop-in for a unit you wrote**. Drop-ins remain for exactly one case: an adopted external containerd (`--containerd external`), whose unit belongs to the distribution and must be extended rather than replaced. Init also provisions the **rootless build daemon**: the `kanea-buildkit` system user with subuid/subgid ranges, the `uidmap` package, and the `buildkitd` unit (`rootlesskit --net=host`, socket in the daemon user's `$HOME` — *not* under a copy-up'd `/run`, where it would be invisible to clients — and root-reachable only). On non-systemd hosts `kanead` creates the hierarchy directly at startup (it runs as root anyway) and `kanea install` places binaries without writing units, naming what has to be supervised by hand. `kanea doctor` verifies cgroup v2, hierarchy placement, the effective floor, and that the build socket answers.
- The cgroup hierarchy is **node-local runtime state** — never represented in the Store, never replicated (§18); it is rebuilt on every boot/agent start.
- **Process hardening complements the resource guarantees:** both Kanea units run with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `RestrictAddressFamilies`; `kanea-edge` additionally runs as its own unprivileged user (§5.2.6). Combined with the §14 workload hardening defaults and the datapath's default-deny policy (§7.1), this gives three isolation layers: resource (cgroups), process (sandboxing), network (eBPF policy).

#### 5.2.12 Host components

Kanea runs on a kernel, cgroups v2, systemd and a clock. Everything else it needs — containerd, `runc` and rootless `buildkitd` — **Kanea installs, pins and supervises itself**. `curl | bash` then `kanea init` produces a working node; the §21 UX requirement is five minutes from `init` to a first HTTPS service, and a prerequisite list is not a way to spend them. (The datapath needs no component at all: its programs are compiled into the binary — §5.2.5.)

- **The manifest is the version matrix.** One embedded table gives, per component and architecture, the pinned version and either a **SHA-256** (release artefacts) or an **image digest** (OCI images). §15.4's version matrix and §22 R1's `init`/`doctor` enforcement read this table rather than a second copy of it. **Hashes are compiled into the binary and never fetched**: a checksum retrieved from beside the artefact proves only that the two agree. The consequence is deliberate — bumping a component is a code change that goes through review and the §14 gates.
- **Two acquisition kinds.** Release artefacts (containerd, `runc`) are downloaded and verified. OCI images (BuildKit) are pulled **by digest**, never by tag, because a tag is a mutable pointer to a root filesystem.
- **BuildKit's binaries are extracted to the host from its image.** `buildkitd`, `buildctl` and `rootlesskit` are self-contained and extract cleanly (§23.2), by walking image layers newest-first — no mount, no snapshotter dependency, and the same code serves an OCI archive out of an offline bundle.
- **Install order is load-bearing.** containerd + `runc` first, then containerd starts, and only then is the BuildKit image pulled — through Kanea's own runtime. The platform bootstraps itself in one direction and there is no other.
- **Own prefix, own sockets.** Binaries land under `/usr/local/lib/kanea`, configuration under `/etc/kanea`, state under `/var/lib/kanea`, sockets under `/run/kanea`. Nothing at a distribution's paths is read, written or restarted. `--containerd external` opts into adopting an existing daemon (§5.2.4); `--buildkit off` skips the build daemon.
- **Air-gapped installation is first-class, not a workaround.** The installer is *handed* artefact bytes rather than fetching them, so the same code path serves both: `kanea bundle create` writes a per-architecture bundle on a connected machine, and `kanea install --bundle` consumes it with no network access at all. Bundle contents are verified against the hashes **in the binary**, never against a manifest inside the bundle — a bundle that supplied its own hashes would be a bundle that authenticates itself. Selecting a bundle disables network fetching entirely: an air-gapped install that silently falls back for one missing component fails later, on a node nobody can reach. Releases publish the bundle as a signed asset covered by the same `checksums.txt`. This covers **Kanea's own components**; workload images still come from a registry the node can reach (§10.2).
- **`kanea doctor` verifies what `kanea install` established**, offline when asked, and enforces the matrix: a component present at a version the manifest does not pin is a finding, not a shrug. Since v1.36 it also verifies what the datapath needs from the node itself: bpffs mounted, cgroup2 unified, the kernel floor, and no foreign FORWARD-drop policy (§5.2.5).

#### 5.2.13 Secret sync (external providers) — v1.44

`kanead` can mirror named secrets **from** external managers **into** its own encrypted store: **Doppler** (service-token REST), **AWS Secrets Manager** (SigV4-signed `GetSecretValue`), **HashiCorp Vault** (KV v2 over token auth), **Azure Key Vault** (OAuth2 client credentials), and **GCP Secret Manager** (service-account JWT-bearer). The direction is the design: values land in the store the rest of the platform already reads, so every consumer — reconciler, notifier, GitOps, storage, edge-auth projection — is untouched, the node keeps working through a provider outage on whatever the last pass wrote, and a rotation propagates on the next poll instead of on the next human.

- **The spec never sees a provider.** A workload references `secret:<project>/<name>` exactly as before; which of those paths are provider-backed is declared in a node config file named by `--secrets-providers-config` (default `""`: no file, no providers). Each `provider "<kind>" "<name>"` block maps external coordinates to local paths via `sync` blocks, and carries a **required, non-empty `allow`** list of local scopes those mappings may write into — writing into `shared/` must be stated, not implied. Two mappings targeting one local path are refused by name, anywhere in the file: two writers on one path is a fight, not a merge.
- **Config semantics are the §7.3 `provided` certificate file's, not the passthrough file's**: re-read via a content fingerprint (SHA-256 over the config *and every credential file it names* — a renamed-into-place token changes no mtime worth trusting), parse failure keeps the last good config and warns once, and a fingerprint change triggers an immediate pass. A device grant is a decision; a credential is a thing a rotation tool rewrites behind Kanea's back.
- **Provider credentials are files on the node**, 0600-checked with `master.key`'s exact rule, re-read every pass. Never inline in the config, and never `secret:` references — a credential stored in the store it fills would ride every CDC segment and backup, and be replaceable through the write-only API by any admin token. Azure and GCP exchange theirs for short-lived access tokens, **cached in memory** until near expiry — never stored, never in status output, never logged. **Ambient cloud identity (IMDS, managed identity, metadata servers) is deliberately not supported**: every variant dials the link-local range the platform's own egress posture (§14 A10) treats as hostile, and Kanea nodes are typically not cloud instances. Vault AppRole and JWKS-style dynamic auth are likewise deferred — token file only.
- **A pass is quiet unless something changed.** The syncer resolves the current local value and compares in process; an unchanged value produces **no Store write** — a rewrite per poll would be a metric stream through the Store in everything but name (constraint: §15.3's CDC ships every mutation). A stored plaintext hash was rejected for the comparison: beside the ciphertext it is an offline dictionary oracle against a stolen `state.db` that the AEAD exists to deny.
- **Provenance, and who wins.** A synced secret's metadata carries `source` (`doppler/ci`) — visible in `kanea secret ls` and `GET /v1/secrets`, which stay metadata-only. The mapping is declarative intent and the sync always reasserts it: a manual `kanea secret put` over a managed path holds until the next pass, which overwrites, restamps, and warns once per path. The reverse never happens silently: a mapping removed from the config, or an external secret that stops existing, **leaves the local value in place** with its provenance stamp. Deleting on a config edit would turn a typo into a mass secret deletion that fails every referencing alloc with no local undo; `kanea secret rm` is the one deletion path (the v1.41 `lb/vip6` rule).
- **Failure is per-mapping, isolation is per-provider.** A mapping the provider cannot serve is a named failure that never suppresses its siblings; a provider that fails entirely never stops the others (§7.3's rule for certificate sources). Passes emit `secret.synced` / `secret.sync_failed` (§11), status is served metadata-only at `GET /v1/secrets/providers` and `kanea secret providers`, and a failed pass retries on a doubling backoff capped at the configured interval (default 5 m, floor 30 s — a poll is a request against someone else's rate limit).
- **Transport hygiene without the egress guard.** The §14 A10 guard exists because notification URLs are attacker-influencable spec text; a provider endpoint is operator-written node config, the same trust class as the replication S3 endpoint, and Vault legitimately answers on RFC1918 — so the guard is not consulted (the §11 invoker's argument, recorded in the threat model). Kept regardless: **redirects refused** (a 302 to the metadata service is the classic residual), response bodies read under a hard size cap, short per-dial timeouts, and error bodies decoded into typed shapes or truncated — an error string must never be able to carry a value.
- **Clients are hand-written HTTP, no SDKs** — the §15.3 S3-sink decision, for the same reasons: five fixed-verb clients are auditable, the dependency tree the §14 gates chase does not grow, and the one hard part (SigV4) is shared with the backup sink through a single extracted implementation.

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

    # Also reachable at <node address>:8080, with or without a domain (R21,
    # §7.2.2). The label names the port above — there is no field here for a
    # container port number, so this cannot forward somewhere undeclared.
    publish "http" {
      host = 8080
      mode = "http"                              # "http" (default) | "tcp"
      ip_restriction { allow = ["192.168.0.0/16"] }
    }

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

    # Where the certificate comes from (R20, §7.3). Omit the block entirely and
    # the node's --tls-default decides; there is no field here for a path.
    tls { mode = "acme" }                        # acme | self-signed | provided | plaintext

    # Upstream protocol (R28, v1.41). Omit for HTTP/1.1 upstreams. "grpc" makes
    # the edge dial this service over plaintext HTTP/2 (h2c) — gRPC needs h2
    # end-to-end. Declaring it beside tls { mode = "plaintext" } is a plan error.
    # protocol = "grpc"

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

    # Numeric only (R23): a username would be read from the image's own
    # /etc/passwd, and it would mean a different uid after a rebuild.
    #
    # No `capabilities` line. Stock images ask for CAP_CHOWN, CAP_SETUID and
    # CAP_SETGID so they can chown a root-owned data directory and drop to
    # their own user at startup — this says both facts up front instead, so
    # there is nothing left to do at startup and nothing to grant.
    user {
      uid = 999
      gid = 999
    }

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
    # uid/gid inherit task.user, and the mode defaults to 0700 (R24) — which is
    # also the only mode postgres will start on. Declare `uid`, `gid` or `mode`
    # here to override; `uid = 0` is how you ask for root explicitly.
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
    tls { mode = "acme" }
  }
}

# A function is a wasm module run as a service (R25) — it lowers to a service
# with runtime = "wasm", so deploys, scaling by count, and the update policy
# are the ordinary ones. What it refuses, it refuses by name: no volume,
# device, socket, capabilities or user block, and no exec health check.
function "resize-avatar" {
  project     = "shop"
  description = "avatar thumbnailer"

  # An OCI image whose entrypoint is the wasm module (FROM scratch + module).
  # R8 applies: a `build` block with no module is legal and waits for its
  # first build to pin a digest.
  module = "registry.example.com/shop/resize-avatar:v3"

  port  = 8080                  # the wasi-http server's listen port (default 8080)
  count = 1

  resources { memory = 64 }     # function defaults: cpu = 100, memory = 64

  # Event/cron POSTs are MACed with this secret (v1.40): X-Kanea-Timestamp +
  # X-Kanea-Signature, the webhook channel's wire format. The function holds
  # the same reference to verify with.
  signing_ref = "secret:shop/resize-signing"

  # At least one trigger (R26). Every trigger reaches the same server: http
  # through the edge, event and cron as kanead-side POSTs to the function's
  # own VIP — there is no field for a target URL anywhere.
  trigger "http" {
    # domains optional — resize-avatar.shop.<base_domain> when the node has a
    # base domain; on a node with none, the edge's functions port (§7.2.3).

    # Request authentication (R27): exactly one mode; the spec carries a
    # reference, the edge is handed hashes.
    auth { bearer_ref = "secret:shop/resize-tokens" }
  }

  trigger "event" {
    on   = ["deploy.failed", "service.unhealthy"]   # §11 vocabulary, glob (R26)
    path = "/kanea/event"                           # default "/"
  }

  trigger "cron" {
    schedule = "0 3 * * *"      # five-field cron, UTC (R26)
    path     = "/nightly"
  }

  health_check "http" {
    type = "http"
    path = "/healthz"
  }
}
```

### 6.2 Spec rules

- **R1** — `project` and `service` names validated as DNS-1123 labels (§4.2); parse errors abort the run with line/column diagnostics.
- **R2** — Variables: `kanea run -var-file=env.hcl`, `${VAR}` interpolation from CLI-provided vars and built-ins (`GIT_SHA_SHORT`, `KANEA_PROJECT`, …).
- **R3** — Secrets are referenced (`secret:<path>`), never inlined; the reconciler resolves them at alloc start. **Primary injection mechanism is tmpfs files** (`/run/kanea/secrets/<alloc>/<name>`); env-var injection is supported but documented as weaker (visible via `/proc/<pid>/environ`, runtime inspect APIs, inherited by child processes).
- **R4** — `kanea plan` (dry-run) shows create/change/destroy diff before apply, Nomad-style.
- **R5** — **Secret references are project-scoped:** a service may only reference `secret:<own-project>/…` or `secret:shared/…`; validation rejects cross-project references (IDOR-class exfiltration defense — §14, A01). Git, registry, storage, and notification credentials follow the same scoping. *Where* a secret's value comes from is invisible at this layer by design: a path may be operator-written or synced from an external provider (§5.2.13, v1.44), and the spec cannot tell — which is why v1.44 adds no R-rule.
- **R6** — Job files declare `spec_version = 1`; future spec revisions are gated by this field (upgrade path, §15.4).
- **R7** — Health check types: `http`, `tcp`, `exec` (exec runs inside the task's container, argument array — never a shell string).
- **R8** — The minimal service is **image-only** (no Git, no `build` block): `task.image` alone deploys. At least one of `task.image` or `build` must be present; when both are, the pipeline-built image (digest-pinned, §10.2) wins and `task.image` serves as the pre-first-build value.
- **R9** — **Service references:** `${service.<name>.host}` and `${service.<name>.port.<port-name>}` interpolate to the referenced service's internal DNS name (`<name>.<project>.kanea`) and frontend port. References are **same-project only** in v1, validated at `plan` against the full applied spec set (referenced service and port must exist; file order is irrelevant), resolved at alloc start as **DNS names, never IPs** (LB reprogramming can't break them), and **cycles are rejected** with the cycle shown in the diagnostic.
- **R10** — **Dependencies:** `depends_on = [...]` declares start ordering; every reference (R9) also creates an implicit dependency edge. The reconciler starts dependencies first and health-gates dependents — a dependent never starts before its dependencies are healthy. If a dependency degrades *after* start, dependents keep running (no cascading stops); events are emitted.
- **R11** — **Resource limits are mandatory; the declaration is optional.** An omitted `resources` block yields defaults (`cpu = 100`, `memory = 256`); every alloc always runs with `cpu.max`, `memory.max`, and a default `pids.max` — no container is ever unlimited (§5.2.11). A `memory.max` breach OOM-kills the alloc (event emitted, restart policy applies). Declared `resources.cpu`/`memory` are also the admission units counted against the workload budget at `plan`/`apply` time (§15.1).
- **R12** — **`task.command` overrides the image entrypoint** and is an **argument array, never a shell string** (same rule as R7's `exec` health check — a shell string is an injection vector, §14 A03). Omitted, the image's own entrypoint runs. The first element (the program) must be non-empty; later arguments may be empty, because some programs use that meaningfully — `redis-server --save ""` is how you disable snapshots.
- **R13** — **`task.capabilities` is the explicit allowlist** promised by the §14 (A05) hardening defaults. Every alloc starts with **ALL capabilities dropped**; a service that needs one names it here (`["CAP_CHOWN"]`). Only capabilities in the **permitted set** may be requested — the set that stock images legitimately need (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID`, `SETUID`, `SETPCAP`, `SETFCAP`, `NET_BIND_SERVICE`, `NET_RAW`, `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`). Privilege-equivalent capabilities (`SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `SYS_RAWIO`, `SYS_BOOT`, `BPF`, `PERFMON`, `DAC_READ_SEARCH`, `MAC_ADMIN`, `MAC_OVERRIDE`, …) are **rejected at parse time**: granting them would be the `privileged` escape hatch v1 deliberately does not have. Requested capabilities go into the bounding, effective and permitted sets — never inheritable or ambient, so they are not passed to child processes that re-exec.

- **R14** — **`network.policy.allow_from` is the explicit ingress allowlist.** Each entry is a fully-qualified `"<project>/<service>"`; both halves are DNS-1123 labels, validated at parse time. Kanea programs one additional ingress allow edge per listed peer into the datapath's policy map (§5.2.5) — ingress rules **union**, so an entry only ever *adds* reachability and can never weaken the project default-deny. There is **no whole-project wildcard**: naming the peer service is the point, and `"analytics/*"` is a parse error. Same-project entries are accepted and redundant (the default already permits them), so an operator may be explicit without changing behaviour. A cross-project peer is addressed by its literal internal DNS name (`<service>.<project>.kanea`) because `${service.…}` interpolation stays same-project until v1.1 (R9, §19.3).

- **R15** — **`host` volumes are operator-gated.** A `storage` block of type `host` names an absolute `path`, validated at parse time as absolute, clean and free of `..`. Whether it may actually be mounted is **not** decided by the job spec: `kanead` refuses any path that does not sit under a prefix in `storage.allowed_host_paths` (§15.1), whose default is **empty**, so the driver does nothing until an operator enables it. The check is applied to the path *after* symlink resolution — `/srv/data/link → /etc` is otherwise a trivial escape — and the directory must already exist and be a directory, because creating it on demand turns a typo into a silently empty volume. An alloc whose host volume fails this check does not start (§8's "mount failures fail the alloc loudly"). Host volumes are shared by every alloc of a service: the directory is the operator's, not Kanea's, and Kanea never deletes it.

- **R16** — **`expose` is validated at `plan`, fail-closed** (§7.2, §7.2.1). A service may only be exposed if it declares a port to expose (`expose` without `network { port … }` is an error, not a route to nowhere), and the upstream port must be unambiguous — named `http`, or the sole declared port. Every `domains` entry is validated as a hostname (labels, length, no scheme, no path, no port, no trailing dot) and **no two services may claim the same domain**, counting the auto-FQDNs that omitted `domains` blocks generate. Middleware is checked here too, because an ingress control that fails open is worse than one that is absent: `ip_restriction` entries must parse as CIDRs, `rate_limit` needs a positive `requests` and a valid `window` with `per` one of `ip` / `header:<name>` / `service`, and `headers` may not set or remove the hop-by-hop headers or the `X-Forwarded-*` set the edge owns (§5.2.6) — a spec that could rewrite `X-Forwarded-For` would be forging the identity every other control is keyed on.

- **R17** — **`task.device` names an operator grant, not a device.** A `device` block carries a label (local to the task) and a `grant` naming an entry in the node's passthrough config (§15.1). The job spec has no field for a device path, which is the point: a spec author cannot request `/dev/mem` because there is nowhere to write it. Parse time validates only shape — the grant name is a DNS-1123 label, and labels are unique within a task. Everything else is the node's: `kanead` refuses a grant it does not have, a grant whose `allow` list does not name the requesting project, and a path that is not a character or block device when it is resolved. Resolution happens **after** symlink evaluation and at every alloc start, not once at load, because a path that was a device when the daemon booted and is a regular file now is the swap the check exists to catch. The device appears inside the container at its host path, and the grant carries the cgroup permissions (`rw` by default, never `m` unless the operator writes it) — a `Linux.Devices` node without a matching allow rule in the device cgroup is a node the container can see and cannot open. An alloc whose device grant fails does not start (§8's "mount failures fail the alloc loudly"); it never starts without the device it asked for.

- **R18** — **`task.socket` is R17 for unix sockets, and is acknowledged as privilege delegation.** A `socket` block names a `grant` and the absolute `mount_path` it should appear at inside the container (`/var/run/docker.sock` for the docker-compatible tooling this exists to serve). `mount_path` is validated at parse time as absolute, clean and free of `..`, may not sit under `/dev`, `/proc` or `/sys`, and may not collide with another socket or a declared volume — two things on one path means one of them silently wins. The bind carries `nosuid`, `noexec` and `nodev`. **None of that makes it safe, and it is not intended to**: a container given the container runtime's socket can create containers that do not have the §14 A05 defaults, so the grant is equivalent to root on the node and §15.1's config is the only control over it. It is therefore project-scoped, empty by default, and readable in one file by whoever owns the machine. The reasoning is R15's, at a consequence R15's prefix allowlist would understate — which is why this is a separate grant kind with its own name rather than a relaxation of the `host` volume driver's "must be a directory" check.

- **R19** — **`update.auto` follows the tag the service already declares.** Off by default. When on, `kanead` re-resolves `task.image`'s tag against its registry every `update.interval` (default 6 h, minimum 5 min — a poll loop is a request to someone else's registry), and when the digest behind the tag has moved it pins the new one and lets the reconciler converge through the ordinary rolling update. It is **refused at parse time on a service whose image is already a digest** (a digest does not move, so the request is a contradiction) and **on a service with a `build` block** (§10.2's pipeline pins that image; two writers on one field is a fight, not a feature). The declared tag is never overwritten — the resolved digest is separate state, and it is preserved across `kanea apply` like the restart generation (§16.1). **A failed update reverts:** the digest that was running is kept, and if the new one has not converged within `update.deadline` (default 10 min) it is re-pinned and the service returns to what worked. Converged means *healthy* for a service with a `check` block and *running without crash-looping* for one without, because `Healthy` is only ever written by a probe (§6.2 R7). Both outcomes emit events (§11): `image.updated`, `image.update_failed`. Private registries are read with `task.registry_auth_ref`, a `secret:` reference under the same project scoping as every other credential (R5).

- **R20** — **`expose.tls.mode` names a certificate source, never a path.** One of `acme`, `self-signed`, `provided` or `plaintext` (§7.3); an unknown value is an error rather than a fallback, because a mode nobody recognises would otherwise decide how the service is served by accident. **An absent `tls` block is not "no TLS"** — it means "the node decides", resolved against `--tls-default` when `kanead` reads desired state rather than when the CLI converts the spec, so the same spec cannot mean different things on two machines. `mode = "provided"` may carry a `name` selecting one of the certificates an operator configured on this node (§15.1), validated at parse time only as a DNS-1123 label — everything else is the node's, which is R17's split exactly: **the spec has no field for a certificate path, a filename or PEM bytes**, because GitOps deploys specs automatically and `handleApply` round-trips a desired record verbatim, so a path *field* is an input surface whether or not the HCL parser is what filled it. `name` on any other mode is an error, since there is nothing for it to select. The pre-v1 spelling `tls { letsencrypt = true }` still parses as `mode = "acme"` and warns; `letsencrypt = false` warns more loudly, because it used to be indistinguishable from an absent field and now is not.

- **R21** — **`network { publish }` binds a node port, and declares what that port can enforce** (§7.2.2). The block's label names the `network { port }` it forwards to — there is deliberately **no field for a container port number**, so a published port cannot name a port the service never declared. `host` is the node port, 1–65535. `mode` is `http` (default), `tcp`, or `udp` (v1.42). It is a sibling of `expose`, not a field of it: `expose` is host-routing-shaped — its `domains` default to an auto-FQDN and its `tls` requests a certificate *for those domains* — and nesting a portless, certificate-less listener inside it would make every one of those fields conditionally meaningful and force R16's unambiguous-port rule to weaken. **A `tcp` or `udp` listener that declares `rate_limit` or `headers` is an error**, because a raw stream carries no requests to count and no headers to rewrite, and a control the edge would silently drop is worse than one the spec never claimed — R16's fail-closed rule, inverted. `max_conns` is `tcp` and `udp` only (on `udp` it bounds live sessions). **A port's `protocol` and a publish's `mode` must agree** (v1.42): `mode = "udp"` may name only a `protocol = "udp"` port and vice versa — a datagram relay in front of a TCP socket, or the reverse, is a listener that black-holes by construction, refused at `plan`. A `protocol = "udp"` port is declarable **only to be published**: it gets no VIP frontend (§5.2.5), no `expose`, no `${service.*.port}` reference and no `http`/`tcp` health check, each refused by name; an unpublished UDP port earns a warning, because it is reachable by nothing. Within a service, one container port publishes on one host port and one host port serves one container port **per L4 family** — one host port may carry one `http`/`tcp` listener and one `udp` listener at once (DNS's shape); **across the applied set, no two services may claim the same host port in the same family**, counted the same way R16 counts domains, because each spec is individually fine and the collision is between them.

- **R22** — **the permitted port range belongs to the node.** 80, 443 and the control-plane API and status ports are reserved at `plan` time, because they are constants of the platform. Everything else is gated by `kanead`'s `--publish-ports` (default `1024-65535`, `off` to disable publishing entirely) and enforced at **apply**, not only at `plan` — GitOps never goes through the CLI, so a check that lived only in the CLI would not be a check. Ports below 1024 are therefore refused by default: a spec able to claim 22, 25 or 53 on this node's address would be deciding something that belongs to whoever owns the machine. The node publishes its own range so `kanea plan` can report the refusal in front of the person who typed it, but the range is the daemon's answer and the daemon is where it is enforced. This is R15's and R17's split for the third time: the spec says what it wants, the node says what is allowed, and the default is restrictive.

- **R23** — **`task.user` is the workload's identity, and it is numeric.** An optional `user` block carries `uid`, `gid` and an optional `groups` list of supplementary GIDs; each is a non-negative integer below 2³²−1, `groups` holds no duplicates and is bounded in length. **There is no field for a username**, and the omission is the same one R17 makes for device paths: resolving `"postgres"` means reading `/etc/passwd` out of the container's own rootfs, which lets a container-controlled file decide which uid the control plane runs a process as. `kanea exec --user` already refused that, and the job spec does not get the weaker rule. A name is also not stable — it resolves to whatever the next base-image rebuild says — so under R19 auto-update it would come to mean a different uid than the one anybody reviewed. **An absent block is not "root"**: it means the image's own `USER` directive stands, which is what every spec written before this rule already meant, so adding the rule changes no running service. When the block is present it overrides the image, and it is applied alongside the other §14 A05 defaults rather than through the runtime's user-resolution helpers, which read the rootfs. `kanea exec` and an `exec` health check both inherit it, because both derive from the task's own process spec — a probe running as root against a workload running as 999 would create files the workload cannot read. **A non-root user is not a substitute for R13**: capabilities are still dropped to nothing and still granted only from the permitted set. It is, in practice, what makes most of those grants unnecessary.

- **R24** — **volume ownership is declared where it can be enforced, and refused where it cannot.** A `volume` block may carry `uid`, `gid` and `mode` (an octal string, `"0700"` — HCL has no octal literal). **Omitted, they inherit `task.user`**, and a volume that ends up owned takes mode `0700` if it declared none; a volume of a task with no `user` block is left exactly as it is today, root-owned `0750`. Inheritance is resolved when the spec is converted, not on the node — unlike R20's TLS mode this defaulting is spec-internal and means the same thing on every machine, so resolving it early is what lets `kanea plan` show the ownership that will actually be applied. Declaring the fields explicitly overrides the inheritance, and `uid = 0` is how root is asked for on purpose. **Which of the §8 drivers can honour this differs, and a spec that asks the ones that cannot is a `plan` error**, not a silently dropped field — R21's rule about a control the layer below discards, applied to storage. A `local` volume is chowned and chmodded; `smb` takes `uid`/`gid`/`file_mode`/`dir_mode`, `s3fs` takes `uid`/`gid`/`umask`, and `mountpoint-s3` takes `--uid`/`--gid`/`--file-mode`/`--dir-mode`, all at mount time. **`host` is refused** because the directory is the operator's — R15 says Kanea never creates it and never deletes it, and chowning it is the same trespass by a smaller name. **`nfs` is refused** because the kernel client has no `uid=` option at all: ownership is the server's and idmapd's, and a field that looked enforced here would be a lie told at the layer least able to detect it. **Inheritance stops at those two, and only a declared field is refused.** A `host` or `nfs` volume in a service whose task names a user is simply left unowned — because a default that became a hard error would mean adding `user` to a task broke every NFS volume that service happened to have, with no field to opt out of something nobody typed. The task's user block is a statement about the process; it is not a claim about what an NFS server does with its files. The chown covers the volume's **top-level directory only**, reapplied at each alloc start — bounded and idempotent, where a recursive one would put O(files) in the alloc start path and would overwrite ownership a workload set deliberately. A chown that fails fails the alloc, like a mount that fails (§8): a workload started against a directory it cannot write looks healthy and does the wrong thing.

- **R25** — **a `function` is a service the platform runs for you, and it refuses what the sandbox cannot hold.** A `function` block lowers, at parse time, to an ordinary service with `runtime = "wasm"` — one Store record, one reconcile path, one deploy semantics; `kanea plan` shows the lowered service and `GET /v1/spec/source` regenerates the block. The `function` block is the **only** way a spec obtains `runtime = "wasm"` in v1 — there is no `task.runtime` field (the §19.1 sketch is superseded by this rule). `module` names an OCI image whose entrypoint is the wasm module; **R8 applies unchanged**, so a function with a `build` block and no `module` is legal and waits for its first build. `port` (default 8080) is the wasi-http server's listen port and becomes the sole declared port, named `http`. Resources default to `cpu = 100`, `memory = 64` and are enforced by cgroups on the shim's sandbox exactly as R11 requires — the memory cap is real, not advisory. **Refused at parse time, by name, because the wasmtime sandbox cannot honour them and a control that is silently dropped is worse than one the spec never claimed (R21's rule):** `volume` (§8's drivers do not map into the sandbox — §19.1's own limit), `device` and `socket` (R17/R18's grant kinds presuppose a Linux container), `capabilities` (there is no capable container process to grant to; the drop-ALL default stands on the host-side shim), `user`, `scaling` (there is no activation path to make a zero-instance function wake, so offering the block would promise what `count` alone delivers), and `health_check { type = "exec" }` (the wasmtime shim has no exec; `http` and `tcp` probes work and are encouraged). A wasm module sees only what the runtime hands it; what exists is task-level WASI configuration, and the docs claim nothing finer-grained.

- **R26** — **a trigger is validated where its vocabulary lives, and a function must have at least one.** `trigger "http"` carries the `expose` sub-schema and lowers to it — R16 and R20 apply verbatim (domains default to the auto-FQDN, duplicate domains are a plan error, `tls` names a certificate source). `trigger "event"` carries `on`, glob patterns validated against the §11 notification vocabulary by the same matcher the `notifications` block uses — one table, one matcher, so a pattern that passes `plan` cannot match nothing at runtime; patterns matching `function.*` are refused, because a function invoked by its own failure event is a feedback loop with no damping. `trigger "cron"` carries a five-field cron `schedule` (minute, hour, day-of-month, month, day-of-week; `*`, lists, ranges, steps; **evaluated in UTC**), validated at parse. `path` on event and cron triggers is a normalized absolute path with no `..` (default `/`). A function with no `trigger` block is an error, not a service nothing calls — §6.2's silent-channel rule (v1.24), applied to compute. **There is no field for a target URL anywhere**: `kanead` derives every invocation target from the function's own VIP, which is why the event invoker is not a hole in §14 A10's egress guard (§11). A function may name a **`signing_ref`** (v1.40): an R5-scoped secret the invoker then MACs every event and cron POST with — `X-Kanea-Timestamp` and `X-Kanea-Signature`, the outbound webhook channel's exact wire format (§11) — so the function can verify an invocation genuinely came from `kanead` rather than from anything else that can reach its VIP. The same reference is the function's to inject into its own env, which is what makes rotation one secret update.

- **R27** — **`auth` names how a request proves itself, and every field is a reference** (v1.40). An `auth` block on `expose` or on a function's `trigger "http"` declares exactly one mode — two modes in one block is an error, not a fallback chain. `basic_ref` names a secret holding htpasswd-format lines (`user:$2y$…`); **bcrypt hashes only** — a line that is not a bcrypt hash is refused when the projection is built, because a plaintext password in a "hash" file is a credential pretending to be verifier material. `bearer_ref` names a secret holding accepted tokens, one per line; the edge is published **SHA-256 hashes of them, never the tokens**, so the restricted file cannot authenticate anyone. A `jwt` block carries `algorithm` (one of `HS256`, `RS256`, `ES256` — configured, never read from the token), exactly one of `secret_ref` (HS256) or `public_key_ref` (RS256/ES256, PEM), and optional `issuer` and `audience` claims to require. **There is no JWKS URL and no field for one**: the edge makes no outbound calls, so keys are static references rotated like any credential. All references are R3/R5-scoped. The spec never carries a path, a key or a password — R17's split, applied to authentication. The route table carries only a fail-closed marker; verifier material travels in the restricted bundle (§7.3's file, 0640). A route whose auth entry cannot be resolved or published serves **503, never open**; auth runs after the rate limit (brute force meets 429 before bcrypt) and before header transforms (§7.2.1). Published ports do not take the block in v1 — deliberate, recorded here rather than silently absent.

- **R28** — **`protocol` names how the edge dials the upstream, and it is refused where it cannot work** (v1.41). `expose.protocol` is one of: absent, `"http"` (the default, normalized away), or `"grpc"` — the marker means "dial this route's VIP over plaintext HTTP/2 (h2c)"; it is named for the operator's intent, and a plain-h2c REST upstream works under it too (documented, not policed). Anything else is a parse error. With `protocol = "grpc"`, the exposed port is the one named **`grpc`** if the service declares it, then R16's rule as before (named `http`, else the sole port) — deterministic when both exist, `grpc` wins because the spec said so. **Refused at `plan`, fail-closed:** `protocol = "grpc"` beside a declared `tls { mode = "plaintext" }` (the plaintext path is HTTP/1.1 cleartext on :80 — the edge serves no inbound h2c — so the route could never carry a real gRPC client; a declared contradiction is a plan error, not a warning), and `protocol = "grpc"` beside a `publish` of the same port in `http` mode, including the defaulted mode (that listener would serve HTTP/1.1 on the LAN — R21's silently dropped control; `mode = "tcp"` is the correct spelling and the diagnostic says so). An **undeclared** TLS mode that resolves to plaintext on a `--tls-default plaintext` node is an agent-side warning at resolution time, never a plan error — R20 makes that resolution node-side, and plan cannot see it. **Functions cannot declare it, structurally**: `trigger "http"` has no `protocol` field and must not gain one (wasi-http is HTTP/1.1) — R25's pattern, where the absence of the field is the refusal. `Expose.Protocol` is not SpecHash material: nothing about the upstream dial is baked into a container, so changing it republishes routes and never rolls an alloc.

---

## 7. Networking Model

### 7.1 East-west (service-to-service)

- Every alloc gets an IP from `kanead` (the per-node allocation CIDR), and every service with ports gets a **VIP** from the service CIDR — allocated durably in the Store, because the VIP is what DNS answers with and what clients cache, so it has to outlive the maps that are programmed with it (§5.2.5). With dual-stack configured (v1.41) each alloc additionally gets a v6 address and each VIP a v6 twin, allocated durably under its own `lb/vip6/<project>/<service>` key — the `lb/vip/` records stay byte-identical, so a rollback or a replicated Store from a v4-only node reads unchanged. Stale `lb/vip6/*` records on a node whose v6 was turned off are released only when it is turned on again, never silently deleted.
- **Internal DNS** (embedded, lightweight): resolves `service.project.kanea` → the service's VIP; `alloc-<id>.service.project.kanea` → alloc IPs. AAAA is answered beside A when the name has a v6 address (v1.41); a name without one keeps the deliberate NODATA. Listens on the node-local `kanea0` address, injected into alloc resolv.conf. It is authoritative **only** for the internal zone — external queries are forwarded to the system resolver with strict timeouts and concurrency caps. DNS sits in the path of every service call: it must degrade gracefully, never stall.
- LB in eBPF at connect time, via the datapath's service maps (§5.2.5): kube-proxy-free, per-connection, no userspace proxy in the data path, and no per-packet translation at all — the destination is rewritten once, at `connect(2)`.
- Default policy: project is an isolation boundary (default-deny inbound except intra-project + the host identity the edge and `kanead` carry); **`network { policy { allow_from = [...] } }`** (R14) adds explicit ingress edges on top — the only way cross-project traffic is permitted in v1. Policy is map entries the datapath enforces directly (§5.2.5): there is no policy file, no selector language, and no translation step to make a rule silently match nothing.

### 7.1.1 Service references & dependencies

- Job specs wire services together with `${service.<name>.host}` and `${service.<name>.port.<port-name>}` (§6.2, R9) — e.g. `DATABASE_HOST = "${service.postgres.host}"` → `postgres.shop.kanea`. **DNS names are injected, never IPs**, so eBPF LB reprogramming and alloc restarts never invalidate configuration.
- References create **dependency edges**; `depends_on` declares edges without env wiring. The reconciler performs a **topological, health-gated start**: dependencies reach *healthy* before dependents begin — during initial deploys, rolling updates, and crash recovery alike.
- **Degraded dependency after start:** dependents keep running (no cascading stops); events + notifications fire. Recovery re-gates only newly (re)starting dependents.
- **Cycles are rejected at `kanea plan`** (A → B → A is a spec error; the diagnostic prints the cycle).
- **Same-project only in v1.** Cross-project references (with explicit policy edges instead of the default intra-project allow) are v1.1 (§19.3).

### 7.2 North-south (public exposure)

- Only the edge proxy listens publicly — on 80/443, and on the node ports services publish (§7.2.2).
- **Automatic FQDNs:** every service with an `expose` block gets `service.project.<base_domain>` (e.g., `web.shop.apps.example.com`) — `base_domain` set in server config. Custom `domains` override/extend.
- Operator sets one **wildcard DNS record** (`*.apps.example.com → node IP`) once; all services routable instantly.
- **Upstream selection:** a route points at the service's VIP (§7.1), not at an alloc — the eBPF LB does the balancing, so the edge holds one upstream address per service and never a backend list. The port is the one named **`http`**, or the service's only port if it declares exactly one. A service that exposes several ports without an `http` among them is a **`plan` error** (R16): v1 routes by Host alone, so there is no request attribute left to choose a port with, and picking one silently is how traffic ends up at the metrics listener.
- **A domain belongs to one service.** Two services claiming the same host — including two that default to the same auto-FQDN — is a `plan` error, not a last-writer-wins race in the edge (R16).
- Path prefixes are v1.1 — **host-based routing is host-based only**. Several ports per service are reachable from v1.33, but by publishing each on its own node port (§7.2.2), not by multiplexing them onto one Host-routed listener; that is still v1.1.

**Upstream protocol (v1.41).** By default the edge dials every upstream over HTTP/1.1. `expose.protocol = "grpc"` (R28) switches that route to **h2c** — plaintext HTTP/2 to the VIP — which is what a gRPC server needs end-to-end; inbound, the :443 listener already negotiates HTTP/2 by ALPN. This is not middleware: it does not observe or transform a request, it selects which of two shared transports carries it, so it lives here rather than in §7.2.1's table. WebSockets need no marker — the Upgrade path is HTTP/1.1 and handled natively.

### 7.2.1 Edge middleware (ingress controls)

Per-service controls declared in the `expose` block (§6.1), enforced by `kanea-edge`:

| Middleware | Config | Behavior |
|---|---|---|
| **IP restriction** | `ip_restriction { allow, deny }` (CIDR lists) | Deny wins over allow; empty `allow` = world. 403 on reject |
| **Rate limiting** | `rate_limit { requests, window, per, burst }` | Token bucket keyed by `ip` / `header:<name>` / `service`; 429 + `Retry-After` on exceed |
| **Auth** (v1.40) | `auth { basic_ref \| bearer_ref \| jwt { … } }` (R27) | Basic (bcrypt htpasswd), bearer tokens (edge holds hashes only), or JWT (HS256/RS256/ES256, static keys, optional issuer/audience). 401 + `WWW-Authenticate` on reject; **503 when the route is marked and the material is missing — never open** |
| **Headers** | `headers { request_set/remove, response_set/remove }` | Applied after auth; can't override edge-owned hop-by-hop or `X-Forwarded-*` integrity headers |

- **Evaluation order:** Host match → IP restriction → rate limit → **auth** → header transforms → upstream proxy. Auth after the rate limit on purpose: a credential brute force meets 429 before it meets bcrypt.
- **Defaults:** server-level `edge` config (§15.1) sets global defaults (e.g. default security headers, global per-IP rate limit); service `expose` settings override/extend them.
- **Fail-closed:** middleware config is schema-validated at `kanea plan` — invalid rules never reach the edge silently.
- **Roadmap (v1.1+):** path-prefix routing, CORS policies, per-route timeouts, Wasm middleware (§19.1). *(Edge auth shipped in v1.40 — R27 — wider than the basic-auth this line used to promise.)*

### 7.2.2 Published ports (node ports)

Host routing needs a name, and a single-node install often has none — or has one and still wants the thing on a port anyway. A `network { publish "<port>" { host = N } }` block (R21) makes a service reachable at `<node address>:N`, with or without any `expose` block at all. The two compose: a service can be world-facing on its domain with a rate limit and LAN-only on its port without one.

- **The listener lives in `kanea-edge`, not in netfilter.** The alternatives were considered and do not work here. A DNAT rule can only target a live alloc address — a service VIP is not an address on any interface, and the connect-time LB (§5.2.5) translates `connect(2)` calls made *on this node*, not packets arriving from outside it — so netfilter would have to be reprogrammed on every alloc create, stop and scale, reintroducing the backend list the VIP design exists to avoid (§7.1) and making the *data path* depend on `kanead` having run recently. The edge already is a host process whose dials the LB translates: it accepts the connection, applies §7.2.1's controls, and dials the VIP like any other client.
- **Two kinds, named separately, because they guarantee different things.**

| `mode` | Reaches | Keeps | Loses |
|---|---|---|---|
| `http` (default) | Any HTTP service | The whole §7.2.1 chain — IP restriction, rate limit, header transforms, security headers, `X-Forwarded-*`, WebSocket upgrade, per-service L7 metrics | The unknown-`Host` 404, which was a DNS-rebinding defence and buys nothing on a port that maps to exactly one service |
| `tcp` | Anything — Postgres, a game server, a mail relay | `ip_restriction`, a per-listener connection cap, drain on shutdown | Everything else. There is no request to count and no header to rewrite |
| `udp` (v1.42) | Game servers, plain DNS, syslog | `ip_restriction` (checked on the datagram that would create a session), a per-listener session cap, session-affinity by client address | Everything a `tcp` listener loses, plus the VIP itself — see below |

- **The route is fixed when the listener binds, not looked up per request.** A published port is reached by address, so the `Host` header is an IP literal that would never match a domain in the table.
- **A spec that declares middleware a TCP listener cannot honour is a `plan` error** (R21), not a control the edge quietly drops. This is §7.2.1's fail-closed rule inverted: a rate limit that is *ignored* is worse than one that is *absent*, because the spec says the service is protected and it is not.
- **The upstream sees the edge's address, not the client's.** There is no `X-Forwarded-For` for a raw stream, so `pg_hba.conf` host rules, address-based bans and anything else that authenticates by source address stop meaning anything behind a published TCP port. `ip_restriction` is checked at accept time, before the upstream is dialled and before a byte is forwarded, and that is the entire mitigation. PROXY protocol would restore the address and is deliberately not built (§19.3): most services do not speak it, and a misconfiguration prepends garbage to the stream and presents as protocol corruption rather than as a config error.
- **The permitted range is the node's decision, not the spec's.** `kanead` takes `--publish-ports` (default `1024-65535`; `off` disables publishing entirely) and refuses anything outside it at apply, not only at `plan` — GitOps never goes through the CLI. 80, 443 and the control-plane API and status ports are reserved outright. Ports below 1024 are refused by default because a spec that could claim 22, 25 or 53 on this node's address would be deciding something that belongs to whoever owns the machine — the same split as `storage.allowed_host_paths` (R15) and the passthrough grants (R17–R18): the spec says what it wants, the node says whether it is allowed, and the default is restrictive.
- **The connection ceiling is bounded and stated.** Per-listener `max_conns` (default 256) and a process-wide `--max-published-conns` (default 1024) are refusals, never queues — the discipline §10.2 uses for builds. A queued TCP connection is a client holding a socket open until it times out anyway.
- **Datapath policy needs nothing.** The per-project isolation policy already admits the host identity without a port restriction, and the edge is a host process — edge→VIP:5432 is permitted exactly as edge→VIP:8080 already is. Adding per-port rules as "hardening" would turn a permissive union into one that must enumerate every port every service ever declares, and getting it wrong denies traffic silently.
- **A `udp` listener is a session relay, and it dials backends, not the VIP** (v1.42). The connect-time LB translates `connect(2)`; an unconnected datagram never makes that call, so there is no UDP frontend to dial (§5.2.5) — the routes projection carries the backend alloc addresses for UDP listeners alone, and a backend-set change republishes the snapshot like any other edit to it. Each new client source address opens a **session**: one connected socket to one backend, chosen by **rendezvous hash of the client address over the live backend set**, so a client keeps its backend across an edge restart, a session expiry and other backends' churn — a stateful UDP protocol (a game session, a DTLS handshake) must not migrate backends mid-conversation. Sessions expire on idleness (90 s without a datagram in either direction) and are swept, not kept: the client's next datagram re-creates the session, and the hash lands it on the same backend. `max_conns` bounds live sessions per listener (default 256, sharing `--max-published-conns` with the tcp side), refused-not-queued; `ip_restriction` is checked before a session exists, which is the accept-time hook a datagram socket lacks, recovered at the only moment there is. Refusals and expiries are counted (`kanea_edge_udp_*`, §9.1.1's discipline) — a session cap nobody can see reads as packet loss. **The upstream sees the edge's address**, exactly as on `tcp`, and the same caveat applies doubly: address-authenticated UDP protocols (TFTP's port dance, SIP's Via headers) do not survive a relay, and the docs say so rather than pretending.

§6.1 shows the `http` kind. The `tcp` kind, on the two things people actually ask for:

```hcl
service "survival" {
  project = "games"
  task "mc" {
    image = "itzg/minecraft-server:2024.1.0"
    env   = { EULA = "TRUE" }
    resources { cpu = 4000  memory = 6144 }
  }
  network {
    port "game" { container = 25565 }
    publish "game" { host = 25565  mode = "tcp"  max_conns = 200 }
  }
}

service "postgres" {
  project = "home"
  task "pg" {
    image = "postgres:16.3"
    env   = { POSTGRES_PASSWORD = "secret:home/pg-password" }
    resources { cpu = 1000  memory = 1024 }
  }
  network {
    port "pg" { container = 5432 }
    publish "pg" {
      host = 5432
      mode = "tcp"
      # The only control a raw listener has, and the only thing standing
      # between this and the internet if the node has no firewall. Postgres
      # will see the edge's address, not the client's, so its own host rules
      # cannot do this job.
      ip_restriction { allow = ["192.168.1.0/24"] }
    }
  }
}
```

And the `udp` kind (v1.42), on the thing it exists for:

```hcl
service "factorio" {
  project = "games"
  task "server" {
    image = "factoriotools/factorio:1.1.110"
    resources { cpu = 2000  memory = 4096 }
  }
  network {
    # A udp port never gets a VIP frontend — it exists to be published (R21).
    port "game" {
      container = 34197
      protocol  = "udp"
    }
    publish "game" {
      host = 34197
      mode = "udp"
      ip_restriction { allow = ["192.168.0.0/16"] }
    }
  }
}
```

(WireGuard fits the same shape but not the v1 sandbox: it needs `CAP_NET_ADMIN`, which R13 forbids because it can reconfigure Kanea's own datapath.)

### 7.2.3 Function endpoints (v1.39)

A function's `trigger "http"` lowers to the `expose` machinery, so on a node with a base domain a function is a host-routed service like any other: `resize-avatar.shop.<base_domain>`, TLS by R20, middleware by §7.2.1, nothing new in the edge. Two consequences are worth stating. **A subdomain per function walks toward §22 R8's ACME rate limit faster than services do** — functions are cheap to declare, which is the point — and the existing mitigation is the existing one: the per-project wildcard via DNS-01 beyond the ~20-name threshold (§7.3). And **a node with no base domain still gets HTTP functions**, which host routing cannot give it: the edge binds one **functions port** (`kanea-edge --functions-port`, default off when unset and no function declares an http trigger) and dispatches by path — `http://<node>:<port>/<project>/<function>/…` → the function's VIP, prefix stripped.

- **This is a mode of §7.2.2's listener machinery, not path routing.** The dispatcher is a published-port listener whose route table is function-name → VIP instead of a single fixed upstream; the §7.2.1 middleware chain applies the way it does to any `http` listener. General path-prefix routing on the host-routed :443 remains parked (§7.2.1 roadmap, §19.3) — when it ships, it ships for services and functions alike, and this port does not change meaning.
- **Which mode a function gets is the node's decision, resolved when `kanead` reads desired state** — R20's `--tls-default` pattern: the spec never encodes it, so one spec means the same thing on every node.
- **The functions port is plaintext HTTP, by design.** A client connecting by IP sends no SNI, which is the same fact that keeps `tls` off published ports (§19.3). A function that needs TLS needs a name, and a name means the FQDN path.

### 7.3 TLS & certificate sources

**A service says where its certificate comes from, and there are four answers** (R20). `expose.tls.mode` is one of `acme`, `self-signed`, `provided` or `plaintext`; an absent `tls` block means whatever the node's `--tls-default` is, so a homelabber sets the policy once and annotates nothing. Every source publishes into the same bundle the edge already reads (§5.2.6), and **`kanead` owns all of them** — obtaining or minting a certificate is *writing*, and the edge does not write.

| `mode` | Where the certificate comes from | For |
|---|---|---|
| `acme` | Let's Encrypt or another ACME CA | A node with a public name and a reachable :80 or a DNS provider |
| `self-signed` | A CA this node generated, installed once on the operator's devices | A LAN with wildcard DNS, no inbound :80 and no DNS-01 credential |
| `provided` | A certificate the operator put on the node and named in its config | A private CA, a Cloudflare origin certificate, a certificate another ACME client renews |
| `plaintext` | Nothing. Plain HTTP, declared | A service behind someone else's terminator, or one that genuinely wants HTTP |

- **`plaintext` exists because it was already happening and nothing could say so.** Before v1.33 a service whose certificate had not been issued — or on a node with no ACME configured at all — simply served HTTP, and the only signal was its absence. Declaring it makes it reviewable, and gives the edge the one fact it needs to stop redirecting the route and to withhold HSTS (§5.2.6).
- **The self-signed CA is per node, generated on first use, and lives in the Store.** ECDSA P-256, ten years, kept in the `certs` bucket beside the ACME account key — so it travels in the encrypted archive and is restored with everything else. Leaves are 90 days, deliberately Let's Encrypt's number: the 2/3 renewal rule below then exercises the renewal path every two months instead of once a decade, which is when a bug in it is cheap. `kanea ca show` prints the CA certificate to install on a phone, laptop or TV; there is no command and no API route that returns the CA *key*, in the same spirit as §16.3's rule about secrets. It is **not** a §15.4 key-ceremony artefact and the distinction is the point: the master key is unrecoverable and every backup dies with it, whereas losing this CA costs re-trusting some devices. A restore onto a node with no archive therefore produces a *new* CA, and every device that trusted the old one must be re-trusted (§15.3).
- **A `provided` certificate is named, not pathed** — R17's rule at TLS. The operator defines `certificate "<name>" { cert, key, allow }` in the node's own config (§15.1), listing the projects that may claim it; a spec asks for `mode = "provided"` and optionally a name. **What the certificate covers is read from its own SANs**, never declared: a domain list that could disagree with the certificate is a configuration that lies, and reading the SANs is also why a wildcard needs no filename convention. The files are re-read on a short poll rather than watched, because certbot and its kin write-then-rename and a watch registered on the old inode never fires; an operator who rotates a certificate should not wait for the renewal pass.
- **Nothing ever falls back to a weaker source.** A service whose `provided` certificate is missing, unreadable or not allowed to it emits `cert.failed` and serves plaintext — it does *not* quietly get a self-signed one. A silent downgrade to a certificate nothing trusts is worse than plain HTTP, because plain HTTP is visibly plain HTTP while a browser interstitial is something an operator learns to click through, and then clicks through on the day it means something. An *expired* provided certificate is published anyway, with the event naming the date: refusing it at midnight turns a stale site into an unreachable one.
- Challenges: **HTTP-01** (via edge proxy), **TLS-ALPN-01**, **DNS-01** (needed for wildcards).
- **`kanead` runs the ACME client; the edge only serves what it is handed.** Issuance writes to the `certs` bucket, renewal is a control-plane timer, and a failure is an event — none of which the edge can do, because it holds no Store handle and no write access (§5.2.6). What the edge gets is a projection: the certificate bundle, and for HTTP-01 the `token → keyAuth` pairs it answers `/.well-known/acme-challenge/*` with. Since publishing and the edge's poll are not synchronous, **`kanead` fetches its own challenge URL through the edge and waits for the right answer before telling the CA to validate** — a validation that fails only because the edge had not reloaded yet costs a failed-validation slot, and that limit takes an hour to clear.
- **Certificates are projected separately from routes**, into `/run/kanea-edge/certs.json` at 0640 (group-readable by the edge user, set up by `kanea init`). The route table is world-readable because the edge runs as its own user and nothing in it is secret; a private key is neither of those things, so it gets its own file rather than dragging the route table's permissions down or pushing the key's up.
- **A host with no certificate still serves plaintext.** The HTTP→HTTPS redirect applies only to hosts the edge holds a certificate for; redirecting the rest would turn "not issued yet" into "unreachable" and break the HTTP-01 validation that would have fixed it. `/.well-known/acme-challenge/*` is never redirected. An unknown SNI is refused at the handshake rather than answered with some other host's certificate.
- **Delivery order (M3 → M5):** **HTTP-01 ships in M3** and is what the auto-FQDNs of §7.2 use — the edge owns port 80, so it is the challenge with no prerequisites. **DNS-01 and the wildcard default ship in M5**, once the secrets store exists to hold the update credential as a `secret:` reference (R3/R5). **TLS-ALPN-01 is deferred past M5** (v1.20): it is the alternative for a node that does *not* own port 80, which is not a situation Kanea is in.
- **DNS-01 is RFC 2136, TSIG-signed** (v1.20): dynamic updates against BIND, Knot or PowerDNS, spoken directly with `miekg/dns` rather than through a provider catalogue that would link every vendor SDK into the binary. An unsigned update is refused — one is a passing ACME challenge for every name in the zone. Hosted providers are a curated list, added individually.
- **ACME rate limits are a design input:** hundreds of per-service certs + frequent redeploys hit Let's Encrypt limits (50 certs/registered domain/week, duplicate-cert 5/week, failed-validation caps). Beyond ~20 exposed services, Kanea **defaults to a wildcard cert via DNS-01** — **per project**, `*.<project>.<base_domain>`, because a wildcard covers exactly one label and the generated names of §7.2 are `service.project.<base_domain>`. Per-service certs remain for custom domains, which are somebody else's zone and not Kanea's to ask a CA for `*.` of. Without a DNS-01 solver the threshold is a **loud warning** rather than a switch: a wildcard cannot be validated over HTTP. **The collapse is an ACME rate-limit workaround and applies to no other source** — a CA this node owns has no rate limit — so it is skipped entirely for a project any of whose exposed services resolved to a different mode.
- **`--acme-directory` defaults to production** (v1.33), not to the LE staging endpoint. Staging's job was to absorb the first attempt, when the DNS is usually still wrong; `mode = "self-signed"` does that job better, because it yields HTTPS that actually works rather than a certificate that is untrusted *and* expires. Staging remains available by name, and is what CI and `init` testing use.
- Certs stored in Store (`certs` bucket), replicated to S3 with the rest of state; renewed at 2/3 of lifetime; renewal events emitted (notification-able).
- Internal traffic (alloc↔alloc) is plaintext within the node, and that is the design, not a gap (v1.36): it never leaves the kernel of a machine the operator owns, so encrypting it protects against nothing the kernel boundary does not already decide. Inter-node encryption becomes a real question at the clustering milestone, where kernel WireGuard between node peers answers it without per-workload identity (§19.2).

---

## 8. Storage

Named **storage resources** are defined at server level (config) or project level (job spec), then referenced by service `volume` blocks. Credentials always via secrets store.

| Driver | Mechanism | Ownership (R24) | Notes |
|---|---|---|---|
| `local` | Host path under `data_dir/volumes/` | `chown` + `chmod` on the volume directory | Default; per-alloc or shared |
| `host` | An existing operator-owned directory, named by `path` | **Refused** — the directory is the operator's | **Off unless enabled:** the path must sit under a prefix in the server config's `storage.allowed_host_paths` (§15.1), which defaults to empty. Shared by every alloc of the service |
| `s3` | FUSE mount — **`mountpoint-s3` (default, read-mostly)** or **`s3fs` (opt-in read-write)**, selected by `mode` (M0 spike ③) | `--uid`/`--gid`/`--file-mode`/`--dir-mode` (ro); `uid=`/`gid=`/`umask=` (rw) | Any S3-compatible endpoint; read-only is the default; **not for latency-sensitive or many-small-files data** (one round trip per file op: 200 files ≈ 30 s at 30 ms RTT). `goofys` is rejected (unmaintained since 2020, no arm64 build); `rclone mount` is not a built-in driver (defers uploads ~6 s past `close()`) |
| `nfs` | Kernel NFS mount | **Refused** — no `uid=` exists; the server decides | `server`, `export`, mount options |
| `smb` | Kernel CIFS mount | `uid=`, `gid=`, `file_mode=`, `dir_mode=` | `server`, `share`, credentials, `vers=3.0` default |

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
- Datapath map counters ───┘
  (east-west flows, drops —
   ON by default: map reads, not parsing)
```

- **Edge-proxy metrics are the primary autoscaling signal for exposed services** — already in the request path, zero extra data-plane cost.
- **East-west comes from the datapath's own maps** (§5.2.5): per-service connects (`flows_per_second`), per-endpoint bytes, drops by reason — written by the LB and policy programs as per-CPU counters and read at scrape time. On by default, because a map increment is not per-request parsing, and attribution is exact by construction: the platform assigned every address the counters are keyed by. This is the signal the edge cannot see — traffic between services — and it cannot lose fidelity under load the way ring-buffer flow parsing could (the defect that kept its predecessor opt-in).
- cgroup metrics come from containerd's Prometheus endpoint in **one scrape for all containers** — 2 000 allocs at 5 s resolution would otherwise mean thousands of shim RPCs per minute.
- **Ranged reads (v1.38):** `GET /v1/stats/history` serves the rings' range read to the dashboard so sparklines are seeded rather than accumulated from zero. Points are sparse `{at, value}` pairs — an unwritten slot is absent, never zero — and the node view records dedicated series (`node_cpu_percent`, `node_memory_percent`, and — v1.42 — `node_gpu_vram_percent`, served as `gpu_vram`) under names the exporter's fixed list does not publish, so the Prometheus surface is unchanged. Node `rps` is a read-time sum across services; node `p95` is an rps-weighted mean and documented as an approximation.
- **Function invocations are datapath connects, not edge rps (v1.39).** A connect to a function's VIP *is* an invocation — from the edge, from another service east-west, or from the §11 invokers — so the Functions page's rate is `flows_per_second` for the lowered service, one number from the counters the datapath already writes. Edge rps alone would silently miss every east-west call. Nothing new enters the kernel or the TS: the series already exists for every service. Under `--network netns` (dev/CI — no datapath) the rate falls back to edge rps plus the invokers' own counters and is labelled partial. `idle` on the Functions page means this counter was **observed present and zero** over a full window; absent data renders as active, never idle — "no data is never zero", applied to invocation.

#### 9.1.1 The two shapes (v1.35)

The edge publishes **two families with different readers, and they must not be merged**:

| | Aggregate | Labelled |
|---|---|---|
| Shape | 5 series per service: `rps`, `p50`/`p95`/`p99`, `error_rate` | `{service,code,method,protocol}` counters + histogram |
| Path | scraped, **differenced** into the in-memory rings | scraped, **retained verbatim**, never differenced |
| Reader | autoscaler, dashboard sparklines | `/v1/metrics`, dashboard panels, `kanea status` |

The labelled family **never enters `internal/scaling`**. That store is the evaluator's input and is capped and footprint-tested (§18 rule 2, §21); a per-code series there would break both, and would give the evaluator forty numbers where its rule names one. Passing labelled counters through unaltered is also what keeps counter semantics correct: an edge restart is a genuine reset, which `rate()` handles natively.

**Cardinality is bounded by construction.** `method` is a request-line token an attacker chooses — allowlisted to the nine RFC methods, everything else `OTHER`. `code` is upstream-chosen and exact, created lazily. `protocol` is derived from the connection (`http`/`https`/`websocket`/`grpc`), never read from `r.Proto` — `grpc` requires the route's R28 marker **and** the wire to agree (negotiated HTTP/2 plus the `application/grpc` content type as a bounded boolean), so browser traffic to a gRPC route stays `https` (v1.41). Past a per-service ceiling, further combinations fold into a single overflow series and increment a drop counter — visible, never silent, the discipline the metrics store already applies at its own cap.

**A hijacked connection is counted, never timed** (v1.41). A WebSocket observation keeps its request counter and its `websocket` label, but is excluded from both latency histograms: `ServeHTTP` returns when the session ends, so the "duration" of a WebSocket is its lifetime — hours, not milliseconds — and a single long session would dominate the aggregate `p95` the autoscaler reads (§9.2).

**Entrypoints** are `web` (:80), `websecure` (:443), and `port-<n>` per published listener (§7.2.2). The set comes from the Store, never from a client. Kanea has no router/service split — a route *is* a service — so there is no router level to publish.

`server_up` is emitted **only for services that declare a `check` block**: `AllocRecord.Healthy` is written solely by a probe, so a check-free service would report every alloc down forever. That is §9.2's "no data is never zero" applied to health. `kanea_edge_up` distinguishes "the edge is down" from "the service is idle", because `kanead` does not supervise the edge (§5.2.6) and keeps serving `/v1/metrics` without it.

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
- **Events:** `deploy.started/succeeded/failed`, `service.unhealthy/healthy`, `service.crashed`, `scale.up/down`, `cert.issued/renewed/failed`, `build.started/succeeded/failed`, `image.updated/update_failed` (§6.2 R19), `backup.succeeded/failed`, `auth.login_failed`, `function.invoke_failed` (v1.39 — and deliberately no `function.invoked`: an info event per invocation is a metric wearing an event's name, at invocation cardinality; the rate lives in §9.1), `secret.synced/sync_failed` (v1.44 — per provider per pass, naming local paths only, never values; `secret.synced` fires only when a pass actually changed something, so steady state is silent).
- Config at server level (defaults) and project level (overrides), with event filters (glob patterns, e.g. `on = ["deploy.*", "scale.up"]`).
- Delivery: at-least-once with retry/backoff; failures logged, never block the control plane.
- **Storm protection:** events are coalesced into digests under load ("42 allocs restarted in 5m" — one message, not 42), with per-channel rate limits and severity floors; a crash-looping fleet must never get the Telegram bot rate-limited or blocked.
- Outbound webhook targets: **https-only, RFC1918/link-local destinations blocked by default** (explicit opt-out for internal chat servers) — §14, A10. The address check runs at **dial time, on every resolved candidate**, not on the hostname: a name that resolves publicly when it is validated can resolve to 127.0.0.1 when it is connected to. Redirects are refused, since an allowed target answering 302 to the metadata service would walk past every check.
- **Channel credentials are `secret:` references and project-scoped** like every other credential (R3, R5): bot tokens, webhook signing keys, SMTP passwords, and Slack/Discord incoming-webhook URLs — the last because that URL *is* the credential.
- All channels also mirrored into the dashboard notification feed.
- **The invoker signs what it sends (v1.40).** A function that names a `signing_ref` (R26) gets every event and cron POST MACed with that secret: `X-Kanea-Timestamp` and `X-Kanea-Signature`, produced by the *same* `Sign` the webhook channel below uses — one implementation, one wire format, so a function author who has verified a Kanea webhook already knows how to verify an invocation. Without the header a function on a shared project cannot distinguish `kanead` from any east-west caller; with it, spoofing an invocation requires the secret, which R5 scopes to the project. A reference that stops resolving **fails the invocation** — `function.invoke_failed` names the reason — rather than sending unsigned: a declared control that is silently dropped is worse than one that was never claimed (R21's rule, R16's original sin), and an unsigned POST to a function that skips verification is exactly that drop wearing a delivery's clothes.
- **The function event invoker (v1.39) is a tee on the dispatcher's feed, not a channel.** A function's `trigger "event"` (R26) is matched against the same vocabulary with the same glob matcher, live — the trigger table is rebuilt from the Store on change, so `kanea apply` wires a trigger with no restart — and delivery is one `POST http://<VIP>:<port><path>` per matching event, JSON body in the same wire shape the webhook channel sends, bounded retry, failures counted per function and surfaced as `function.invoke_failed`. It shares the channels' backpressure discipline (non-blocking enqueue, drop counter, warn-once) and deliberately **not** their coalescing: a function wants each event, and its queue depth is its storm bound. **It is not behind the egress guard above, and that is not a hole:** the guard exists because a channel URL is attacker-influencable text; the invoker's target is *derived* from the VIP allocator, the spec has no URL field to influence (R26), redirects are refused, responses are drained under a size cap, and every dial carries a short timeout. The threat model records the argument (§14 A10).

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
| **Overview** | Node CPU/mem/disk/net (live charts) — plus GPU VRAM when a GPU is visible (v1.42; the panel is absent, never zeroed, on GPU-less nodes) — service health summary, recent events, active notifications |
| **Projects** | List (name, description, service count, health), create/edit, Git sync status |
| **Services** | Per project: name, description, image, count desired/actual, status chips; **Deploy service** — an HCL spec editor with server-side validation (v1.38: `POST /v1/spec/render`/`apply`) |
| **Service detail** | Live CPU/mem/network graphs per alloc, **seeded from `GET /v1/stats/history`** so a fresh page is not blank (v1.38); **log stream** (follow, per-alloc or merged, search, download); events timeline; allocs table (restart count, uptime); scaling history; exposed domains + cert expiry + edge middleware; actions (restart, scale, redeploy, rollback-to-digest, **edit spec** — generated HCL, marked as such, warned when GitOps owns the project) |
| **Pipelines** | Build runs, per-step streamed logs, image digests, trigger source |
| **Functions** | (v1.39) Wasm functions: name + module ref + artifact size, trigger chips (http FQDN or functions-port path, event patterns, cron schedule), invocations/min (§9.1 datapath connects), p95, memory cap, status (`active` / `idle` / `trapping` — derived, §9.1); stat tiles (invocations/min, median start→ready, errors/hr); **Deploy function** opens the spec editor seeded with a `function` block |
| **Storage** | Storage resources, mount health, usage where available |
| **Notifications** | Channel config, delivery log, test button |
| **Backups** | Snapshot list, verify/restore actions, replication lag |
| **Settings** | Node config read-only (listen/TLS, CIDRs, DNS, edge port policy, secrets providers), backup destination (Store-settled, hot-swapped — v1.46), notification defaults + per-project channels with the §11 test button, accounts, API tokens, audit log viewer |

- Dark/light mode (shadcn theme), keyboard navigation, responsive to tablet.
- XSS-safe log rendering (escaped text, no `dangerouslySetInnerHTML` — §14, A03).

---

## 13. Authentication & Authorization

### 13.1 First-install flow

- Auth is set up **before the API is exposed** (`kanea init` interactively creates the first admin account and/or the OIDC block, runs dependency/kernel/NTP checks, and performs the **master-key escrow ceremony**, §15.3). Accounts live in the Store, not in the config file (v1.18), so `kanea init` creates the first one through the same API everything else uses — over the local unix socket, which is the only door open at that point. As of v1.45 init does this itself rather than printing the instruction: it starts `kanead`, waits for the socket, creates the account, and restarts the daemon once so a configured network listener — refused at the accountless first boot — opens.
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
| **A01** | Broken Access Control | Auth middleware on **every** API/WS route (deny-by-default); project-scope checks on all object access (no IDOR — IDs resolved through project ownership); **secret references project-scoped at spec validation (§6.2, R5)**; role checks (`admin`/`viewer`) enforced server-side; CLI tokens scoped and revocable; WebSocket Origin allowlist (anti-CSWSH); CSRF tokens on cookie-auth mutations; `exec` admin-only + audited; **MCP tools pass through the same authz + audit pipeline, secrets are write-only via tools (§16.3)**; edge IP allow/deny middleware (§7.2.1). **A published port is unauthenticated reachability to a container, by design (§7.2.2)** — that is what the operator asked for, and it is stated rather than mitigated: on a `tcp` listener `ip_restriction` is the only control, it is checked at accept time before the upstream is dialled, and the upstream sees the edge's address, so its own address-based rules cannot do this job. The port range is the node's (R22), never the spec's |
| **A02** | Cryptographic Failures | TLS 1.2+ everywhere (API, dashboard, edge); bcrypt/argon2id for passwords; secrets encrypted at rest in Store (XChaCha20-Poly1305, key from `data_dir/master.key` 0600 or external KMS later); **externally-synced secrets (§5.2.13, v1.44) land in that same store — the provider is a source, never a second at-rest story — and provider credentials are 0600-checked files under `master.key`'s exact permission rule, with Azure/GCP access tokens held in memory only**; cert/key material 0600; backups encrypted client-side before S3 upload; **master key escrowed at `init` via key ceremony (print-once + passphrase-derived KEK option) — without it, S3 backups are unrecoverable (§15.3)**; secrets injected via tmpfs files by default, not env vars (§6.2, R3); **the self-signed CA's private key (§7.3) sits in the `certs` bucket at exactly the protection every leaf key there already has, and no API route, CLI command or MCP tool returns it** — `kanea ca show` emits the certificate only |
| **A03** | Injection | Strict HCL schema validation, no eval of user input; DNS-1123 name validation (§4.2); no shell invocation with user-controlled strings (buildctl/containerd called with arg arrays, never a shell); log output HTML-escaped in dashboard; SQL N/A (BoltDB); path-join sanitization for volume subpaths |
| **A04** | Insecure Design | Secure-by-default config (localhost-only if unauthenticated, HTTPS-only API); threat model maintained in `docs/THREAT_MODEL.md`; security review per milestone |
| **A05** | Security Misconfiguration | Hardened defaults; security headers on all responses: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`; no debug/pprof endpoints in release builds. **Workload hardening defaults:** drop `ALL` capabilities (the explicit allowlist is `task.capabilities`, bounded by a permitted set that excludes every privilege-equivalent capability — §6.2 R13), `no-new-privileges`, default seccomp profile, no `privileged` escape hatch **a job spec can declare**, per-alloc PID/IPC/cgroup namespaces, optional read-only rootfs — Kanea's own tasks get the same treatment. **A workload can declare the uid/gid it runs as and the ownership of its volumes (§6.2 R23–R24)**, which is what makes most `task.capabilities` grants unnecessary: an image asks for `CAP_CHOWN`/`CAP_SETUID`/`CAP_SETGID` in order to fix a root-owned data directory and drop privileges, and a spec that states both facts up front leaves nothing to grant. It is **declarable, not default** — an absent `user` block means the image's own `USER` stands, because overriding it globally would break every image that ships a correct one. **Device and socket passthrough (§6.2 R17–R18) is the one way past these defaults, and it is not spec-declarable:** a spec asks for a grant by name, the grant lives in the node's config, names the projects that may claim it, and defaults to not existing. A socket grant is node-level control for the container holding it and is documented as such rather than mitigated |
| **A06** | Vulnerable Components | `govulncheck` + `npm audit` gates in CI; Dependabot/Renovate; SBOM (`syft`) attached to releases; pinned base images (buildkit) by digest |
| **A07** | Identification & Auth Failures | Rate-limited login (5/min/IP + exponential account backoff); session rotation on privilege change; token expiry; OIDC delegates MFA to IdP and uses PKCE + state/nonce + full ID-token validation with deny-by-default role mapping; global API rate limits and WS connection caps beyond login; **per-service edge rate limits via expose middleware (§7.2.1)**; no credentials in logs/audit (redaction filters) |
| **A08** | Software & Data Integrity Failures | Release binaries signed (cosign) + checksums; image digest pinning honored (`image@sha256:` enforced when given); TLS-only registries (no insecure registries); pipeline deploys pin built digests; backup archives carry SHA-256 manifest verified before restore; Git webhook HMAC validation + replay protection. **`update.auto` (§6.2 R19) is the one deliberate exception and follows a moving tag by design** — opt-in per service, off by default, and it still runs a digest: the tag is resolved once and pinned, so every alloc of a deploy runs the same image and the digest that ran is recorded |
| **A09** | Logging & Monitoring Failures | Append-only **audit log** (all mutating API calls, auth events, restores) in Store, viewable in dashboard, with **signed periodic export for tamper evidence**; security events surfaced as notifications; log retention configurable |
| **A10** | SSRF | Containers blocked from cloud metadata (the whole `169.254.0.0/16` range) by the datapath's egress program on every alloc veth (§5.2.5) — enforced in the kernel with a per-alloc drop counter, not asserted in a policy file; Git sync URLs validated (scheme allowlist https/ssh, no local addresses unless `allow_insecure_git`); webhook delivery validates target URL against config, not user input at send-time; outbound notification webhooks https-only with RFC1918/link-local destinations blocked by default; **secret-provider endpoints (§5.2.13, v1.44) are operator-written node config and deliberately not behind that guard (the §11 invoker's argument — Vault legitimately answers on RFC1918), with redirects refused, bodies size-capped and dials time-bounded regardless; ambient metadata-service auth is unsupported by design** |

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
  system_reserve_memory = "1GiB"         # protected floor: kanead, edge, containerd, buildkitd
  oversubscribe         = false          # refuse apply when Σ declared memory > (total RAM − reserve)
}

edge {                                   # defaults for all exposed services (§7.2.1)
  default_security_headers = true
  default_rate_limit { requests = 1000  window = "1m"  per = "ip" }

  # Which node ports a spec may claim (§7.2.2, R22). "off" disables publishing.
  # Below 1024 is refused by default: a spec able to claim :22 would be deciding
  # something that belongs to whoever owns the machine.
  publish {
    ports     = "1024-65535"
    max_conns = 1024                     # process-wide ceiling across every tcp listener
  }
}

# Where an exposed service's certificate comes from when its spec does not say
# (§7.3, R20): acme | self-signed | provided | plaintext.
tls_default = "acme"

storage {                                # host-volume allowlist (§8, §6.2 R15)
  # Empty by default: no job spec can mount a host directory until an operator
  # names a permitted parent here. An unrestricted host mount is `privileged`
  # under another name, so this boundary belongs to whoever owns the node.
  allowed_host_paths = []                # e.g. ["/srv/kanea", "/opt/shared"]
}

# Device and socket grants (§6.2 R17–R18). Read from a separate file named by
# `--passthrough-config`, which defaults to "" — no file, no grants, and a spec
# asking for one fails its alloc rather than starting without it.
#
# A spec never names a path: it asks for a grant by name, and the node resolves
# it. `allow` is required and may not be empty — a grant nobody is named for is
# a typo, not a permissive default.
device "gpu" {
  nodes = ["/dev/dri/renderD128"]         # char/block devices, resolved per alloc
  allow = ["media"]                        # projects that may request it
  mode  = "rw"                             # cgroup permissions; "m" only if written
}

# A socket grant is root on the node for whoever holds it (R18). It is listed
# here, per project, because that is the only control over it.
socket "containerd" {
  path  = "/run/kanea/containerd.sock"
  allow = ["ops"]
}

containerd { socket = "/run/containerd/containerd.sock" }

datapath {
  # Set at install time and written into kanead's unit (§5.2.5) — kanead is the
  # IPAM. Both are validated as IPv4 prefixes; node_cidr must sit inside
  # cluster_cidr, and neither may overlap service_cidr.
  node_cidr    = "10.244.0.0/24"         # alloc addresses (IP = identity)
  cluster_cidr = "10.244.0.0/16"         # routed range, masqueraded on egress
  service_cidr = "10.201.0.0/16"         # service frontends (VIPs), outside cluster_cidr
  bpf_dir      = "/sys/fs/bpf/kanea"     # pinned maps, programs and the cgroup link
}

acme {
  email     = "ops@example.com"
  directory = "production"               # or "staging", or a directory URL
  # dns01 { provider = "cloudflare", auth_ref = "secret:acme/cloudflare" }
}

# Certificates the operator put on this node (§7.3, R20). Read from a separate
# file named by `--tls-certs-config`, which defaults to "" — no file, no
# certificates. Same shape and same reasoning as the device and socket grants
# above: a spec asks for one by name and never names a path, and `allow` is
# required because a certificate nobody is named for is a typo.
#
# What it covers is read from the certificate's own SANs, never declared here —
# a domain list that could disagree with the certificate is one that lies.
certificate "shop" {
  cert  = "/etc/kanea/tls/shop.crt"       # leaf + intermediates, PEM
  key   = "/etc/kanea/tls/shop.key"
  allow = ["shop"]                        # projects that may claim it
}

# External secret providers (§5.2.13, v1.44). Read from a separate file named
# by `--secrets-providers-config`, which defaults to "" — no file, no
# providers. Same shape and same reasoning as the grants above: a spec keeps
# saying `secret:<project>/<name>` and never names a provider; where a value
# comes from is this node's decision. `allow` is required — the scopes the
# provider's mappings may write into — and credentials are 0600 files on the
# node, never inline and never `secret:` references. Re-read by content
# fingerprint (config + every credential file), like the certificate file.
provider "doppler" "ci" {
  token_file = "/etc/kanea/secrets/doppler.token"
  project    = "backend"                  # Doppler project + config to read
  config     = "prd"
  allow      = ["shop", "shared"]         # writing into shared/ must be stated
  sync {
    name = "DATABASE_URL"
    to = "shop/db-url"
  }
  sync {
    name = "STRIPE_KEY"
    to = "shop/stripe-key"
  }
}
provider "vault" "infra" {
  address    = "https://vault.internal:8200"
  token_file = "/etc/kanea/secrets/vault.token"
  # ca_file  = "/etc/kanea/tls/vault-ca.pem"   # extra root for a private endpoint
  mount      = "kv"                       # KV v2 mount
  allow      = ["media"]
  sync {
    path = "apps/media"
    field = "s3_secret_key"
    to = "media/s3-secret"
  }
}
provider "aws-sm" "prod" {
  region          = "eu-west-1"
  access_key      = "AKIA…"               # an identifier, not a secret
  secret_key_file = "/etc/kanea/secrets/aws.secret"
  allow           = ["shop"]
  sync {
    id = "prod/shop/db"
    json_key = "password"
    to = "shop/db-password"
  }
}
provider "azure-kv" "corp" {
  vault_uri          = "https://corp-vault.vault.azure.net"
  tenant_id          = "00000000-…"       # identifiers, not secrets
  client_id          = "11111111-…"
  client_secret_file = "/etc/kanea/secrets/azure.secret"
  allow              = ["shop"]
  sync {
    name = "db-password"
    to = "shop/db-password"
  }   # optional: version = "…"
}
provider "gcp-sm" "prod" {
  credentials_file = "/etc/kanea/secrets/gcp-sa.json"      # service-account key JSON
  project          = "my-project"         # defaults to the key's project_id
  allow            = ["shop"]
  sync {
    name = "db-password"
    to = "shop/db-password"
  }   # version defaults "latest"
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
- **Backup:** scheduled (cron) + on-demand snapshots. Archive = state snapshot + certs + secrets (encrypted; SHA-256 manifest verified before restore). The `certs` bucket carries **the node's self-signed CA** (§7.3) along with every leaf, so it needs no separate path — but a node rebuilt *without* an archive generates a **new** CA, and every device that trusted the old one must be re-trusted. That is the cost of the CA deliberately not being escrowed, and the runbook says so.
- **Restore:** `kanea restore --from s3://bucket/prefix [--snapshot <id>]` on a stopped node; or **first-boot auto-restore** — if `state.replication.s3` is set and local state is empty, the agent offers pull-and-restore.
- **Recovery order:** master key → Store snapshot + segment replay → **datapath maps repopulated from desired state** (derived state; nothing under the bpffs pin root is ever backed up or restored, §5.2.5) → images re-pulled (parallel queue, bounded concurrency) → allocs re-attached (bounded concurrency, exposed services first) → edge routes live.
- **Realistic targets:** **RPO ≤ 5 min** (change segments). **RTO: control plane ≤ 15 min; full workload convergence is best-effort** — a fresh node must re-pull every image, and registry bandwidth/rate limits dominate. A registry mirror is recommended; an optional image pre-seed flag exists for small fleets.
- **Not backed up:** container images (re-pulled; optional pre-seed), ephemeral logs (optional inclusion flag).

### 15.4 Upgrades & schema migration

- **State migrations:** BoltDB buckets carry schema versions; `kanea agent` runs forward-only migrations at startup (with a pre-migration local snapshot + automatic S3 snapshot when replication is configured). Job specs are versioned via `spec_version` (§6.2, R6).
- **Upgrade flow:** `kanea upgrade` (or package manager) → `kanea-edge` drains and restarts first (brief, connection-drained), then `kanead` restarts; running allocs and the eBPF dataplane are untouched throughout — the datapath's programs, maps and cgroup link are pinned in bpffs and owned by no process (§5.2.5), so there is nothing for a restart to tear down.
- **Compatibility:** the component manifest (§5.2.12) **is** the version matrix — one table, compiled into the binary, pinning every host component per Kanea release. `kanea init` installs from it and `kanea doctor` enforces it. A matrix kept separately from the thing that installs would be a matrix that describes a node nobody has.
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
GET    /api/v1/stats/history?project=&service=&window=   # sparse TS points; gap = absent, never 0 (v1.38)
POST   /api/v1/spec/render                     # HCL in → diagnostics or converted services; no side effects (v1.38)
POST   /api/v1/spec/apply                      # render + the same apply path PUT /v1/services uses (v1.38)
GET    /api/v1/spec/source?project=&service=   # generated HCL from desired state, marked generated (v1.38)
GET    /api/v1/functions                       # functions with status, triggers, invocation counters (v1.39)
GET    /api/v1/pipelines | POST /api/v1/pipelines/{p}/{s}/run
GET    /api/v1/events?filter=…
GET    /api/v1/storage | POST /api/v1/storage
GET    /api/v1/backups | POST /api/v1/backups | POST /api/v1/backups/{id}/restore
GET    /api/v1/audit
GET    /api/v1/secrets                         # metadata only: paths, timestamps, source — never values (§13.3)
PUT    /api/v1/secrets/{path}                  # write-only; no GET-one route exists, by construction
DELETE /api/v1/secrets/{path}
GET    /api/v1/secrets/providers               # sync status per provider (§5.2.13, v1.44) — metadata only
GET    /api/v1/certs/ca                        # this node's self-signed CA certificate (never the key)
GET    /api/v1/edge/policy                     # permitted publish range + reserved ports (§7.2.2)
POST   /api/v1/webhooks/git/{project}          # HMAC-validated
GET    /api/v1/notifications/channels | POST …/test
```

### 16.2 CLI (`kanea`)

```
kanea init                 # interactive first-install: kernel/NTP checks, host components, listen address, key ceremony; starts kanead, creates the first admin, prints the node summary
kanea install              # install/upgrade the pinned host components (§5.2.12); --only, --dry-run, --bundle
kanea bundle create        # author an offline bundle on a connected machine (air-gapped installs)
kanea agent -config=…      # run the control-plane daemon (systemd-managed normally)
kanea edge -config=…       # run the edge ingress proxy (separate systemd unit)
kanea doctor               # verify node health: deps, versions, bpffs, disk, clock; --offline
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
kanea functions list       # wasm functions: triggers, invocation rate, status (v1.39)
kanea project sync shop
kanea backup create|list|verify
kanea secret put shop/db-url   # value from stdin or --from-file, never argv
kanea secret ls [prefix]       # paths, timestamps, source — never values
kanea secret rm shop/db-url    # the one deletion path, synced or not (§5.2.13)
kanea secret providers         # external-provider sync status (v1.44)
kanea restore --from s3://…
kanea ca show|info         # this node's self-signed CA, to install on your devices (§7.3)
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
- **Metrics:** per-alloc CPU/mem (single containerd `/v1/metrics` scrape), per-service network + L7 (edge proxy primary for exposed services; datapath map counters for east-west, on by default), node stats (procfs — plus, v1.38, node series `node_cpu_percent`/`node_memory_percent` recorded into the TS for history, under names the exporter never publishes; v1.42 adds GPU VRAM — amdgpu via sysfs, NVIDIA via a timeout-bounded, cached `nvidia-smi` exec — per-GPU on `/v1/stats` and one aggregate series `node_gpu_vram_percent`). In-memory TS (5 s/1 h → 1 m/6 h downsampled, compressed) + optional Prometheus `/metrics` exporter; ranged reads over `GET /v1/stats/history` (v1.38), where a gap is an absent point, never a zero.
- **Events:** everything state-changing emits a structured event (deploy, scale, crash, health, cert, backup, git) — dashboard feed, notification source, 7-day default retention.
- **Audit log:** separate append-only stream of all authenticated mutating actions, with signed periodic export (§14, A09).

---

## 18. Clustering-Ready Design Constraints

v1 is single-node, but these rules are **binding for all v1 code** so clustering is additive, not a rewrite:

1. All state mutations go through the `Store` interface with monotonic indexes (Raft FSM-compatible).
2. The reconciler reads desired state only from the Store, never from in-memory-only structures.
3. Placement goes through a `Scheduler` interface (v1 impl: `LocalScheduler`).
4. Agent internally separates `Server` and `Client` roles even though both run in one process (config: `server { enabled = true }`, `client { enabled = true }`).
5. No node-local paths in shared state — volumes referenced by named storage, alloc runtime data kept out of replicated buckets.
6. Node identity is a stable UUID in `data_dir/node-id`, not hostname-derived.
7. Datapath state (pinned maps, programs, links) is derived, node-local, and rebuilt from the Store — never represented in shared state. Identity is address allocation, and allocation lives behind the `Store` interface, so multi-node identity is the Store's clustering story (rule 1), not a second coordination system.
8. The edge proxy is a separate process (`kanea-edge`) from day one — north-south traffic survives control-plane restarts, crashes, and upgrades (§5.2.6).

---

## 19. Future Considerations (Post-v1)

Deliberately out of v1 scope, evaluated and parked. The architecture keeps the door open for both — revisit at the clustering-milestone review.

### 19.1 WebAssembly (Wasm) workloads — **shipped in v1.39** (residue below)

The core of what this section parked shipped in v1.39 as **functions** (§6.2 R25/R26, §7.2.3, §11, §12.2, §20 M11): wasm modules as long-running wasi-http services on the wasmtime runwasi shim, lowered to ordinary services — the §5.2.4 driver's runtime choice, exercised. The candidate spec shape changed on the way: not `task { runtime = "wasm" }` but a first-class `function` block that *lowers to* it, because a rule about what wasm refuses (R25) needs one block to be about, not conditions scattered across every validator. What this section keeps is the residue — deferred, with the mechanism that would build each named so deferral stays a decision:

- **Scale-to-zero.** The value line below promised it; v1.39 deliberately does not build it — there is no activation path, and `count` is honest about that (R25 refuses `scaling` on functions). The wake signal exists now, though: the datapath's per-destination drop counters (§9.1) make "connect attempted against a zero-backend VIP" observable, which is what a future activation loop would watch. Additive when it comes.
- **Edge-middleware wasm plugins** (request transforms, auth hooks — à la Envoy/Traefik). Unchanged from the original parking: a separate feature with a separate blast radius (user code in the request path of the process that terminates public traffic).
- **Custom application event names.** A function's `trigger "event"` matches the §11 vocabulary only — there is no application event bus, and inventing one for triggers would be a message queue wearing a trigger's name.
- **OCI wasm artifacts** (`wasi/wasm` platform, wasm media types). v1.39 packages modules as plain `linux/<arch>` scratch images, which flow through the existing pull path and BuildKit untouched; the artifact form needs a platform-matcher and media-type special case and waits for a reason.
- **~1 ms cold starts.** True of the runtime, unclaimed by the platform: a v1.39 function is always-on, so the dashboard reports **start→ready**, which is measurable, instead of "cold start", which for a long-running service is a number from someone else's benchmark.

Containers remain the general-purpose default — wasm complements, never replaces. §8 volume drivers still do not map into the sandbox, which is R25's refusal list, stated where it is enforced.

### 19.2 SPIFFE / SPIRE workload identity

- **Value:** cryptographic per-workload identity (`spiffe://kanea/<project>/<service>`) → mTLS and identity-based authorization without per-service cert management; federation once multi-node exists.
- **Why deferred:** SPIRE is a second control plane (against G1's single-binary ethos); single-node traffic never leaves the kernel, and v1's proportionate controls already cover the threat model — the datapath's default-deny ingress policy (§7.1) and edge TLS (§7.3).
- **Adoption path:** evaluate at the **clustering phase**, where the first real need is inter-node east-west encryption — which is kernel WireGuard between node peers and needs no per-workload identity to be useful (v1.36; the per-workload question comes after it). Interim option if internal mTLS is ever needed pre-clustering: an internal CA in the existing cert store issuing short-lived per-alloc certs ("SPIFFE-lite").

### 19.3 Longer-horizon parking lot

Multi-node clustering (per §18 constraints) · embedded OCI registry · canary auto-promotion · path-based edge routing · per-project ACLs · multi-task services (sidecars) · **cross-project service references** (explicit policy edges) · gVisor/Kata runtime classes for hostile multi-tenant workloads · **published-port extensions** (§7.2.2): PROXY protocol or TPROXY to restore the client's source address, and a `bind` address to put a listener on one NIC *(UDP shipped in v1.42 as the session relay §7.2.2 describes)* · **east-west UDP** (v1.42 is north–south only): a UDP service VIP needs `sendmsg4`/`recvmsg4` rewrite programs the datapath does not have, gated on a spike ⑤ extension before any of it is built · **`tls` on a published port** (the certificate is chosen by SNI and a client connecting to an IP sends none, so it would work only when the client has a name — and a client with a name has :443) · **edge protocol extensions** (v1.41): WebSocket-over-HTTP/2 (RFC 8441 extended CONNECT — the edge rejects CONNECT outright today, so this needs a deliberate carve-out), grpc-web-to-gRPC translation, TLS re-encryption to upstreams (the edge currently makes no outbound TLS by design), and `protocol` on published `http` ports (h2c on a LAN listener) · **public IPv6** (v1.41 is internal-only): edge listeners on v6, NAT66 or routed GUA, and migrating the owned nftables table from the `ip` family to `inet` — that migration belongs to this feature and must not be done early. (Each is marked v1.1+ where first mentioned; listed here for consolidation.)

---

## 20. Milestones

| MS | Name | Scope | Exit criteria |
|---|---|---|---|
| **M0** ✅ | **Spikes** (timeboxed, complete) | ① Standalone Cilium: CNI from containerd, endpoint labels, service LB, network policy, **Hubble metrics w/o k8s** — **done, GO** *(as shipped; the Cilium integration was replaced by the internal eBPF datapath in v1.36 — spike ⑤, `spikes/ebpf-datapath/`)* ② containerd task lifecycle + CNI + cgroup metrics — **done, GO** ③ S3 FUSE mount choice — **done, GO** ④ image build task on containerd — **done, GO** | Written spike reports; go/no-go per component; fallbacks documented (CNI bridge / edge-proxy metrics) |
| **M1** | Runtime core | Store + reconciler + containerd driver + HCL parser + CLI (plan/run/stop/ps/logs) + local volumes + **image-only deploys** (no git) + workload-parent cgroup & per-alloc limits (cpu/memory/pids, §5.2.11) | `kanea run` starts N healthy containers **from a bare image reference**; crash → restart; logs stream in CLI |
| **M2** | Networking & storage | Cilium integration *(as shipped; replaced by the internal eBPF datapath, v1.36 — §5.2.5)*, internal DNS (authoritative-only + capped forwarding), eBPF service LB, default policies; **service references + dependency-ordered reconcile (§7.1.1)**; NFS/SMB/S3 volume drivers; batched LB updates | Two services talk via DNS name; LB spreads traffic; dependents start only after dependencies are healthy; volume mounts work |
| **M3** | Ingress & TLS | Edge proxy as separate `kanea-edge` process, hardening (timeouts, host validation, X-Forwarded stripping), **edge middleware (IP restriction, rate limits, headers)**, auto FQDNs, **ACME HTTP-01** (DNS-01, TLS-ALPN-01 and the wildcard default move to M5 with the secrets store — §7.3) | Service publicly reachable at `web.shop.<base_domain>` with valid LE cert; `kanead` restart doesn't drop public traffic; middleware blocks/limits/headers verified end-to-end |
| **M4** | Dashboard | shadcn/ui SPA: overview, projects, services, service detail (stats + logs), events, settings shell | Full dashboard parity with CLI read ops; live WS updates |
| **M5** | Auth & OWASP pass | **Secrets store**; Basic + OIDC (PKCE), sessions, CSRF tokens, WS Origin checks, tokens, roles; workload hardening defaults (drop caps, seccomp, no-new-privs); security headers; rate limiting; audit log; CI gates (govulncheck, gosec, gitleaks); **ACME DNS-01 + TLS-ALPN-01 + wildcard default** (deferred from M3: the DNS provider credential is a `secret:` reference, §7.3) | §14 checklist green; unauthenticated API impossible; default container spec passes hardening audit |
| **M6** | Metrics & autoscaling | TS store (containerd `/v1/metrics` scrape + edge-proxy metrics primary), scaling evaluator, Hubble opt-in wiring *(as shipped; east-west now comes from datapath map counters, on by default — v1.36, §9.1)*, circuit breaker, Prometheus exporter | Service scales 2→N→2 on synthetic load per policy; metrics cost measured at 2 000-alloc scale |
| **M7** | GitOps & pipelines | Git sync (poll + webhooks), BuildKit runner (rootless `buildkitd` unit + `buildctl` driver; `Containerfile`/`Dockerfile` detection), pipeline objects + dashboard page | Push to GitHub → build → rolling deploy → event |
| **M8** | Notifications | Channel dispatcher (webhook, Telegram, Slack/Discord, SMTP, ntfy), filters, storm coalescing/digests, SSRF egress rules, test action, dashboard page | Configured channels receive filtered events; digest mode verified under event storm |
| **M9** | MCP server | MCP streamable-HTTP + stdio transports, read/mutate/destructive tool tiers, resources, token scopes, audit integration | AI agent can plan/apply/scale/stream logs via MCP; viewer vs admin scoping and `confirm` gating verified |
| **M10** | Hardening & packaging | S3 state replication (CDC segments), backup/restore + **key escrow ceremony** + DR runbook, upgrade & schema-migration framework (§15.4), `kanea init`, systemd units (`kanead` + `kanea-edge` in `kanea.slice`, `kanea-workloads.slice`, §5.2.11), **host-component installer + offline bundle (§5.2.12, v1.30)**, install script, signed releases, docs site | Fresh-node restore from S3 verified in CI (incl. key ceremony); upgrade+rollback tested; **`kanea init` brings up containerd, cilium, etcd and buildkitd on a bare node, online and from a bundle** (v1.30) *(as shipped; since v1.36 the list is containerd and buildkitd — cilium and etcd left the platform with §5.2.5's rewrite)*; **v0.1.0 tagged** (v1.29). **v1.0 additionally requires**: an SBOM attached to releases (§14 A06, §21 — the release workflow publishes none today), and `init`→first HTTPS service exercised on a real node rather than in CI, which is the §21 UX requirement and the only one no test can stand in for |

| **M11** | Functions (v1.39) | Wasm spike (`spikes/wasm-functions/` — the shim under Kanea's containerd, netns + VIP reachability, cgroup caps, hardening compat, no `task.Exec`; gates the rest the way spike ⑤ gates the datapath), wasmtime-shim host component (§5.2.12), `runtime` on the driver seam, `function` block + R25/R26 lowering, event/cron invokers (§11), functions-port dispatcher (§7.2.3), `GET /v1/functions` + CLI + dashboard page (§12.2) | Spike report GO; a wasi-http function deploys from a spec, serves through the edge (FQDN and functions-port modes), fires on a matching event and a cron tick; invocation rate visible from an east-west call; pre-v1.39 Store upgrade rolls zero allocs |

**Definition of done (every milestone):** OWASP §14 checks reviewed, `govulncheck` clean, tests green, docs updated.

---

## 21. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Platform** | Linux amd64/arm64; kernel ≥ 5.10 (Kanea's own eBPF datapath, §5.2.5 — the floor is spike-validated, not inherited); cgroups v2; bpffs; systemd; NTP-synced clock (ACME/OIDC/HMAC validity) — checked at `init`, and this is the whole list. containerd, `runc`, rootless `buildkitd` and the wasmtime shim (v1.39) are **installed by `kanea init` at pinned versions** (§5.2.12), online or from an offline bundle; they are no longer prerequisites the operator supplies |
| **Footprint** | kanea idle RSS ≤ 150 MiB, **total platform ≤ 1 GiB including containerd and kanea-edge** — the 1 GiB budget is the default `system_reserve_memory` (§5.2.11); dashboard bundle ≤ 1.5 MiB gzipped. Resident components since v1.36: **rootless `buildkitd` 157 MiB (spike ④)** + containerd 42 MiB ≈ 199 MiB before Kanea's own processes — v1.36 removed the two next-largest tenants (cilium-agent 153 MiB and etcd 23 MiB, the M0 measurements) and replaced them with pinned BPF maps, which are kernel memory bounded by construction (< 5 MiB at the §21 scale targets, sized from the CIDRs at startup) and no resident process at all. **Published ports (§7.2.2) add a bounded, operator-set term:** `--max-published-conns` × ~24 KiB, which is ~24 MiB at the default 1024 and is why the default is not larger — a ceiling nobody has turned on must not pre-spend a tenth of the budget. **The edge's labelled metrics (§9.1.1) add a second bounded term:** services × per-service series ceiling × ~200 B, ~4 MiB at 500 services with every ceiling saturated. It is bounded *because of* the ceiling, not because traffic is well-behaved, so the ceiling carries a footprint test of its own |
| **Storage** | S3 volumes cost **one object-store round trip per file operation** (~30 ms typical): creating or listing a 200-file directory takes tens of seconds, and a FUSE call with a dead backend blocks for tens of seconds uninterruptibly — S3 volumes are for bulk/read-mostly data, never for hot paths or many small files (M0 spike ③) |
| **Scale** | ≥ 500 services / ≥ 2000 allocs per node; reconcile loop ≤ 1 s at that scale |
| **Performance** | API p95 ≤ 100 ms (local); log stream latency ≤ 500 ms; **scale decision ≤ 20 s from a sustained metric breach** (v1.21: a 15 s averaging window — three samples at the 5 s scrape resolution — plus one 5 s evaluation tick; a large spike decides sooner) |
| **Durability** | RPO ≤ 5 min (S3 change segments); RTO: **control plane ≤ 15 min**, workload convergence best-effort (image re-pull bound); backup verify = restore test in CI; master key escrowed at `init` |
| **Security** | §14 gates in CI; signed releases; SBOM published |
| **Licensing** | **Apache-2.0**, chosen for the explicit patent grant — the norm for the infrastructure Kanea sits next to (containerd, BuildKit) and the one property a permissive licence without it does not give a self-hosted platform. No per-file headers: a convention applied to every file is a convention that will be applied unevenly, and `LICENSE` is not ambiguous. No CLA. Third-party terms travel with the module graph and are not restated here |
| **Reliability** | `kanead` restart disturbs neither running allocs **nor north-south traffic** (separate `kanea-edge` process); reconciler heals drift ≤ 30 s; log drains never backpressure workloads; workloads can never starve or OOM-kill the control plane (cgroup memory floor + OOM-killer policy, §5.2.11); disk watermark alerts at 80/90% |
| **UX** | `init`→first HTTPS service ≤ 5 min on a fresh VM — **including on a node with no public name**, where that means `--tls-default self-signed`, `kanea ca show`, and one certificate installed on one device (§7.3); every CLI mutation has `--json` |
| **i18n/a11y** | Dashboard EN only v1; WCAG 2.1 AA contrast via shadcn theme |

---

## 22. Risks & Open Questions

| # | Risk / Question | Impact | Mitigation |
|---|---|---|---|
| R1 | **Kanea owns its eBPF datapath** (v1.36 — replaced standalone Cilium, whose non-k8s file interfaces had churned once already, which was this row's residual risk) | High → Medium | **Spike-gated** ([spike ⑤](./spikes/ebpf-datapath/REPORT.md)): connect-time LB from host and alloc under systemd, tc policy with attach-before-up, pinned-link/filter survival across restarts, the generation flip under load, netfilter interplay and the 5.10 floor are validated on real kernels before the driver ships — the discipline spike ① set for the driver this replaces. Residual risk: **maintaining BPF programs across kernel releases is now Kanea's job.** Mitigation: no CO-RE/BTF dependency (the programs read only UAPI context types), pinned `cilium/ebpf` library, committed generated artifacts verified by CI, kernel floor enforced by `doctor`, `--network netns` as the dev/CI mode |
| R2 | ~~Hubble L7 metrics: CPU cost + ring-buffer drops under load → fidelity loss at peak~~ | **Retired (v1.36)** | Hubble left the platform with Cilium. East-west counters are per-CPU map increments written by the datapath's own programs (§9.1) — nothing is parsed per request and there is no ring buffer to drop from, so the fidelity trade this row managed no longer exists |
| R3 | FUSE S3 mount performance/reliability | Medium | Spike-chosen driver; documented "not for hot data"; NFS/SMB as alternatives |
| R4 | BuildKit frontend edge cases (some Dockerfiles); **single-driver risk** | Medium | **De-risked in M0** ([spike ④ report](./spikes/kaniko-build/REPORT.md), 11/11 on the daemon path): rootless `buildkitd` verified for build+push, `Containerfile`/`Dockerfile`, digest reporting, cache reuse, resource caps and clean failure surfacing — with no privilege anywhere and 546 ms warm builds. Single-driver risk is accepted deliberately (one builder to pin and patch); the runner keeps an internal driver seam, and buildah was measured as a working drop-in (26/27, task-shaped) should it ever be needed |
| R5 | S3-compat consistency differences across vendors | Low | Verify on AWS + MinIO in CI; checksums on every object |
| R6 | Single-node = SPOF by design | Accepted | S3 replication + DR runbook; clustering on roadmap; blast radius limited by `kanea-edge` process split |
| R7 | ~~Embedded etcd fsync sensitivity on cheap VPS disks → identity/endpoint stalls~~ | **Retired (v1.36)** | etcd left the platform with Cilium — identity is address allocation in the Store (§5.2.5), and nothing remains for a slow fsync to stall |
| R8 | ACME rate limits with per-service certs at scale | Medium | Wildcard-via-DNS-01 default beyond ~20 exposed services; staging endpoint in CI |
| R9 | Master-key loss = total backup loss | High → mitigated | Key escrow ceremony at `init` (print-once / passphrase-derived KEK); DR runbook starts with key recovery (§15.3) |
| R10 | Log-pipeline backpressure blocks workloads | Medium | Non-blocking drains + drop policy + drop counters (§17) |
| R11 | AI agents (MCP) misused → destructive ops or secret exfiltration | Medium | Role-tiered tools, destructive ops require `confirm`, secrets write-only, full audit, rate limits, payload caps (§16.3) |
| R12 | Workload resource exhaustion (memory/CPU/PIDs) starving or OOM-killing the control plane | High → mitigated | cgroups v2 reservation (`memory.min` floor, default 1 GiB) + collective workload ceiling + mandatory per-alloc limits with defaults + admission control (§5.2.11, §6.2 R11, §15.1); `mlock` rejected for the Go control plane |
| R13 | **Wasmtime shim behaviour under Kanea's OCI spec** (v1.39 — hardening opts, netns join, cgroup caps on a runtime that is not runc) | Medium | **Spike-gated** (`spikes/wasm-functions/`, §20 M11): the compat matrix is findings before the PRD's claims freeze, the discipline spikes ① and ⑤ set. Residual: runwasi release cadence and artifact naming drift — pinned by SHA-256, `manifest-verify` CI catches re-tags, and a bump re-runs the spike checklist |
| R14 | **Hand-written secret-provider clients drift with provider APIs** (v1.44 — five external services, no SDKs) | Medium | Fixed-verb clients against versioned/stable endpoints (Doppler v3 download, Vault KV v2, ASM `GetSecretValue`, Key Vault 7.4, GCP SM v1); httptest fakes that verify auth server-side (the ASM fake recomputes SigV4 — the MinIO lesson); a drift presents as a named `secret.sync_failed`, never a silent stale value, and the local store keeps serving the last good one |
| R15 | **A provider credential file on the node reads every mapped external secret** (v1.44) | Medium | 0600-checked (`master.key`'s rule), root-owned under `/etc/kanea`; docs prescribe scoped credentials (Doppler service token per config, Vault token with a read-only policy on the mapped paths, IAM/SP/SA limited to the named secrets); the `allow` list bounds what a compromised *config* could overwrite locally; tokens never enter the Store, status output or logs |
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

- `containerd`, `runc` and `containerd-shim-wasmtime-v1` (runwasi, v1.39) — **host components Kanea installs at manifest-pinned versions** (§5.2.12), verified against SHA-256 hashes compiled into the binary. The pins live in `internal/provision/components.json`, which is also the §15.4 version matrix; this list names the components, not the numbers, because a document is the wrong place to keep a value a test can check
- `github.com/containerd/containerd/v2` — runtime client
- `github.com/cilium/ebpf` — the pure-Go eBPF loader behind the internal datapath (§5.2.5), with `github.com/vishvananda/netlink` (veth/address/route/neighbor plumbing) and `github.com/google/nftables` (the masquerade rule, spoken over netlink — no `nft` binary on the node). It is a standalone library with **no Kubernetes dependency**; `github.com/cilium/cilium` — the agent's own module, which pulls the k8s client graph — remains banned (constraint #10 is about kube imports, and this library has none). The BPF programs themselves are committed as bpf2go output and regenerated under a digest-pinned toolchain (§5.2.5)
- `golang.org/x/net` — direct since v1.41 for `http2` (the edge's h2c upstream transport, §5.2.6); it was already in the module graph indirectly
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
- **Function** — a wasm module run as a long-running wasi-http service on the wasmtime shim, declared with a `function` block and lowered to a service (§6.2 R25).
- **Edge middleware** — per-service ingress controls (IP restriction, rate limits, header transforms) applied by `kanea-edge`.
- **MCP** — Model Context Protocol; Kanea's interface for AI agents (§16.3).
- **Project** — named group of services; isolation, discovery, and notification boundary.
- **Reconciler** — control loop converging actual state to desired state.
- **Spike** — timeboxed technical investigation producing a go/no-go report.

---

*End of PRD. This document is the project's north star: deviations require a PRD amendment with rationale.*
