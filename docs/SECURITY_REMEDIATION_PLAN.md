# Kanea - Security Remediation Plan

Companion to [`SECURITY_AUDIT_2026-08-16.md`](./SECURITY_AUDIT_2026-08-16.md) (findings K-01…K-52, I-1…I-5). This plan covers **all of them**, grouped into 25 PRs across 4 phases.

## Decisions locked (2026-08-16)

| Question | Decision |
|---|---|
| K-19 env secrets | **Implement R3 tmpfs injection** (reconciler resolves at alloc create; per-alloc tmpfs files) |
| K-07 build network | **Document + metadata egress drop** (threat-model section + nftables uid-keyed drop of 169.254.0.0/16; worker netns deferred) |
| K-20 host-path TOCTOU | **fd-based `openat2` resolution** (mount the object that was checked, via `/proc/self/fd/N`) |
| Release strategy | **Deferred** - fix on main; tag when you say so. Plan is written so Phases 1-2 are independently shippable. |

## Working rules (repo constraints that shape every PR)

1. **PRD amendment discipline (binding constraint #1):** any PR that changes documented behavior edits `PRD.md` first in the same PR (version bump + amendment note). The PRs below flag their obligation; most fixes align code to existing claims and need none.
2. **One logical change per PR**, conventional commits, `make check` green before merge.
3. **Tests are part of the fix, not a follow-up**: table-driven, named after the behavior (`TestATraversalNamedApplyIsRefused`); reconciler/jobspec stay >80% covered. Every fix lands with the regression test that would have caught it.
4. **AGENTS.md gets a "trip-over" bullet per merged PR** (repo rule + release checklist item 4). THREAT_MODEL/VALIDATION updates are called out per PR.
5. **Duplicated checks are this codebase's idiom**: plan-time refusal for the operator, apply/runner-time refusal for records that arrive another way, with an equality test where two lists must match.
6. Datapath PRs regenerate BPF artifacts with `make bpf` (digest-pinned toolchain; `bpf-verify` CI enforces) and update `floor_linux_test.go` map/program counts.

---

## Phase 1 - Boundary fixes (Critical/High, ship-ready alone)

> Theme: close the holes that cross documented trust boundaries. ~1 week.

### PR-01 - K-01 (+K-40): build-context symlink escape - **Critical**
- **Code:** `internal/gitops/runner.go` `withinDir` → compare `filepath.EvalSymlinks` of both paths *and* walk the resolved context path components with `Lstat`, refusing any symlink at/below the checkout root. `internal/gitops/buildkit.go` `DetectRecipe` → `Lstat` the recipe, refuse symlinks. New `internal/jobspec` `validateBuild` refusing absolute/`..` forms of `context`/`dockerfile` at plan (called from `validateServices`; K-40's oracle dies with the symlink refusal).
- **Tests:** symlink-escape refused (runner, mirroring `TestABuildContextOutsideTheCheckoutIsRefused`); recipe-symlink refused; plan refusals for absolute/`..` forms.
- **Docs:** AGENTS.md bullet. No PRD amendment (the code comment already claims the refusal).

### PR-02 - K-03: storage `auth_ref` scoping + `endpoint` validation - **High**
- **Code:** `internal/jobspec/validate.go` - scope-check `storage.auth_ref` at `validateVolumes` time (storage is top-level, so the rule is: *every service mounting the storage may read the ref*, `scope == svc.Project || scope == shared`); validate `endpoint` at plan: must parse as URL, host non-empty, **`https://` required** (mirrors `validateNotifyURL`; a plaintext endpoint is the exfiltration shape). Refuse non-`secret:` `auth_ref` shapes. (Apply-seam half for inline `Resource.AuthRef` lands in PR-03.)
- **Tests:** cross-project ref refused at plan; `http://` endpoint refused; same-project/`shared` accepted; mount of foreign storage by two projects each checked.
- **Docs:** PRD amendment (§8 validation addition, version bump); AGENTS.md bullet; site/docs storage reference.

### PR-03 - K-04 + K-17: apply-seam validation - **High**
- **Code:** new `validateDesired(svc)` in `internal/api` (or an exported jobspec helper - `jobspec.IsName` at `validate.go:34` is already importable), called from `applyServices` before any Store write:
  - DNS-1123 for `Project`/`Service`/`Pipelines[].Project` **and** nested volume/storage names;
  - capability forbidden/permitted lists (export a checker from jobspec, don't copy the maps);
  - R5 scope on every inline `Resource.AuthRef` and env `secret:` ref;
  - full R25 refusal list when `Runtime != ""` (volumes, devices, sockets, capabilities, `user`, scaling - only runtime-name and exec-probe are checked today);
  - identical auth across `AllExposes()`.
  - Defense in depth at composition points: `VolumeHostPath`/`SharedVolumeHostPath`/`AllocID`/`WriteResolvConf`/log-path joins assert the cleaned result stays under its base (`mustJoinUnder` helper); fix `network/types.go` `validateLabelValue` to refuse `/`.
- **Tests:** traversal-named apply refused (each primitive); each K-17 invariant refused; path-helper escape tests.
- **Docs:** AGENTS.md bullet (the `types.go:799` "DNS-1123 by R1" assumption must be corrected to name the apply-seam gate).

### PR-04 - K-15 + K-16: git/build spec validation - **Medium (rides with Phase 1: same files as PR-01)**
- **Code:** extend `validateBuild`: `target`/`cache_repo` parse as image references (`distribution/reference` is already a dependency); reject `,`, `=`, whitespace in `tag`; same checks duplicated in the runner (`ownershipRefusedBy` precedent). `validateGit`: refuse userinfo in `git.url` with a diagnostic pointing at `auth_ref`; scheme allowlist `https`/`ssh`/scp-form (`http://` refused - no daemon opt-in in v1; note for operators with LAN git servers). Belt-and-braces: userinfo-stripping helper (the `notify.redactURL` pattern) at the clone-log and error call sites (`runner.go:249`, `git.go:178,243,398-405`).
- **Tests:** comma injection refused (plan + runner); userinfo refused and redacted; scheme refusals; ssh/scp forms still parse.
- **Docs:** PRD amendment (§10.1 validation additions); AGENTS.md bullet; site/docs git reference.

### PR-05 - K-05: bundle image digest verification - **High**
- **Code:** `internal/provision/image.go` `Fetch`: when `GetImage` hits, require `img.Target().Digest` to equal the digest parsed from `ref`; fail loudly naming both. Repeat the comparison in `Import` (or immediately after, in `cmd/kanea/install.go`) so a forged annotation fails at import time. Correct the inverted comment at `image.go:143-147`. (I-3's opaque-whiteout comment rides along.)
- **Tests/CI:** extend the `install-smoke-airgapped` CI tamper test to the image component (OCI archive with the pinned name annotation, wrong content → install must fail).
- **Docs:** AGENTS.md bullet ("a name is not a digest" next to the bundle-trust bullet).

### PR-06 - K-02: edge runs as its own user - **High**
- **Code:** `kanea init` creates a `kanea-edge` user+group (alongside the `kanea` group ceremony); `cmd/kanea/units.go` `edgeService` gains `User=kanea-edge`/`Group=kanea-edge`; the kanead unit renders `--edge-certs-gid kanea-edge` (flag already exists, `agent.go:138`) so the 0640 group-read bundle path (`certs.go:174-180`) is finally exercised. `kanea doctor` gains a finding: edge process not running as `kanea-edge`.
- **Migration:** units are rendered at init, so upgraded nodes keep the root unit until re-init - release note: re-run `kanea init` (idempotent) or accept the doctor finding. No in-place unit rewrite on upgrade (nothing migrates units in place today; consistent).
- **Tests:** `units_test.go` asserts `User=`/`Group=` present (beside the capability checks); init user-creation test.
- **Docs:** AGENTS.md bullet; THREAT_MODEL wording already claims the boundary - verify §1/§3 stand once shipped. VALIDATION.md: edge process uid on a real node.

---

## Phase 2 - Documented-control gaps (High)

> Theme: make the code match what the documents already promise. ~1.5 weeks (PR-10 is the largest single item).

### PR-07 - K-06: actually apply a default seccomp profile - **High**
- **Code:** vendor the Moby default seccomp profile (Apache-2.0, attribution in the file header) as an embedded JSON in `internal/runtime`; `withHardening` sets `s.Linux.Seccomp`. Projection-only, **not** SpecHash material → no fleet rolls; existing allocs stay unconfined until their next replacement (the v1.56 heterogeneous-fleet note applies - write the AGENTS.md bullet in those words). Confirm the wasmtime shim runs under the profile (spike ⑥ shim accepted the full opt set; seccomp is the one addition since).
- **Tests:** `spec_test.go` asserts `Seccomp != nil`, default action `SCMP_ACT_ERRNO`, and that the baseline syscalls containers actually use are allowed; VALIDATION.md real-node check (a Go static binary and the wasm shim both start under it).
- **Docs:** none needed for the claim (already documented); AGENTS.md bullet for the rollout semantics.

### PR-08 - K-08: backup manifest MAC + replay contiguity - **High**
- **Code:** `internal/backup/crypto.go` `DeriveKeys` gains a third key (`"kanea backup manifest mac v1"`); `Manifest` gains `MAC` (`omitempty`) = HMAC-SHA256 over the canonical manifest bytes (field order is deterministic; MAC computed with the field empty). `Fetch`/`Restore` verify the MAC before trusting any field (incl. `KeyID`). **Compatibility:** pre-MAC archives are accepted with a loud warning (operator-initiated restore; documented residual), never silently. `replay` refuses a non-contiguous segment chain above the snapshot index (`next.From == prev.To + 1` - Segment carries From/To), with the same honest-error shape as the unreadable-segment refusal.
- **Tests:** tampered manifest refused; `KeyID`-stripped manifest refused; pre-MAC archive accepted-with-warning; gapped segment chain refused.
- **Docs:** PRD amendment (§15 archive format); AGENTS.md bullet; DR_RUNBOOK note on the pre-MAC warning.

### PR-09 - K-07: build threat model + metadata egress drop - **High**
- **Docs first:** new THREAT_MODEL §3.x - "a build is arbitrary code execution by whoever can push, with host networking"; enumerate what that reaches (loopback diagnostics, cross-project VIPs, metadata), state the control and the residual honestly. PRD amendment (§10.2 build isolation).
- **Code:** `internal/datapath/fw_linux.go` (or a sibling) gains `EnsureBuildEgress`: an output-chain rule in the owned `kanea` nftables table - `meta skuid <kanea-buildkit uid> ip daddr 169.254.0.0/16 drop` (uid from `provision.BuildkitUser`, looked up once; covers buildkitd and, via rootless uid-mapping, every RUN step). Re-ensured periodically like `EnsureMasquerade`. Note in the rule comment: pulls/registries are unaffected (not link-local).
- **Tests:** rule rendering unit test; VALIDATION.md real-node check (`RUN curl 169.254.169.254` fails, registry push works).
- **Docs:** AGENTS.md bullet (incl. "the datapath guard filters workload veths, not host-netns processes" - the generalization).

### PR-10 - K-19: R3 env-secret tmpfs injection - **Medium severity, largest item (~1-2 days)**
- **Step 0 (design pin):** re-read PRD §6.1 example + §6.2 R3 (line 775) and fix the wire semantics *before coding*: the reference name maps to `/run/kanea/secrets/<alloc>/<name>`; decide precisely what the env var becomes (path vs. dropped) and whether an opt-in literal-env form exists. If the PRD is ambiguous, a small amendment pins it - do not invent semantics in code.
- **Code:** reconciler at `create`: resolve env `secret:` refs (scopes already enforced at parse + PR-03's apply seam), write per-alloc tmpfs dir (`/run/kanea/secrets/<alloc>/`, 0711 root, files 0400 owned by the alloc's effective user), bind-mount the dir read-only into the container, tear down with the alloc. Plaintext never enters the Store, the audit log, or an API response (resolution happens only at create). Crash-loop safety: a resolution failure fails the alloc honestly (recorded start failure, not silent literal).
- **Tests:** ref resolves to a mounted file with right perms/ownership; foreign scope refused; resolution failure = recorded start failure; teardown removes the dir; exec/probes see the same mount (they copy `*spec.Process` - verify).
- **Docs:** AGENTS.md bullet ("never resolve into `Desired.Env`"); site/docs secrets section.

---

## Phase 3 - Mediums

> ~1 week. PR-11 and PR-18 are the careful ones; the rest are small.

### PR-11 - K-09: bind source identity to the veth - **datapath**
- **Code:** new pinned hash maps `veth_src` (ifindex → `__be32`) + `veth_src6` (additive, per the v1.41 ABI rule); written in `plumb()` before link-up, deleted in `Detach`; `from_container` drops `DROP_SPOOF` when `ip->saddr != map[ingress_ifindex]`. **Migration:** `Init` populates `veth_src` for already-attached veths from the rebuilt IPAM/ifalias walk (an upgrade must not fail-close running allocs). Update `floor_linux_test.go` map count and the "five PERCPU_HASH" comment.
- **Tests:** Go-side map writer/reader; real-node check in VALIDATION.md (IP_FREEBIND spoof probe is dropped). `make bpf` regen.
- **Docs:** PRD amendment (datapath behavior, v1.65 precedent); AGENTS.md bullet ("IP is identity, now for in-cluster sources too"); THREAT_MODEL §3.5 updated (the mis-cited paragraph at `kanea.c:853` is corrected).

### PR-12 - K-10: health-check path validation
- **Code:** jobspec `validateHealthChecks`: path must start with `/`, refuse `@`, `?`, `#`, whitespace/control chars (mirror `validateTriggerPath`, `function.go:373`). Prober belt-and-braces (`reconciler/health.go:145`): after building the request, assert `req.URL.Host` equals the intended `host:port` before dialing.
- **Tests:** plan refusals; prober refuses a userinfo-injected path without dialing.

### PR-13 - K-11: slow-body via Upgrade
- **Code:** `internal/edge/proxy.go` `applyDeadline`: drop `isUpgrade(r)` from the exemption (handshakes have no body, so `ContentLength == 0` already covers them; grpcStream stays). Optional hardening: clear the deadline in `statusRecorder.Hijack` on successful upgrade.
- **Tests:** upgrade-with-body keeps its deadline; real websocket upgrade is unaffected.

### PR-14 - K-12: UDP relay anti-amplification
- **Code:** `internal/edge/udp.go` - per-session `bytesOut` cap (constant, e.g. 4 KiB) until the client sends a **second** datagram from the same socket (proof-of-receipt lifts the cap); per-source-IP session cap alongside the listener cap; metrics for both refusals.
- **Tests:** first-datagram response capped; second lifts; spoofed-source flood hits the per-IP cap.
- **Docs:** THREAT_MODEL §3.13 gains the spoofing/amplification paragraph with the residual stated; PRD small amendment (§7.2.2 relay semantics); site/docs publish reference.

### PR-15 - K-13: session revocation
- **Code:** `internal/auth/store.go` - `DeleteUser` and `PutUser`-on-password-change sweep `auth/session/*` for the subject (bounded prefix scan; rare events). New admin route `DELETE /v1/users/{name}/sessions` (CSRF, audited) so the documented emergency lever exists; CLI verb `kanea user revoke-sessions <name>` (or a flag on `user rm` - pick one, keep it minimal).
- **Tests:** deleted/re-credentialled user's session 401s immediately; route + audit line; last-admin rule untouched.

### PR-16 - K-14: login-limiter bounds
- **Code:** `internal/auth/store.go` - key the account half by a fixed-size value (truncate to 64 bytes or SHA-256; the audit log keeps the plaintext name), add an LRU capacity cap mirroring `ratelimit.DefaultCapacity`.
- **Tests:** map bounded under a synthetic flood; lockout behavior unchanged.

### PR-17 - K-18: WS subscription caps + feed efficiency
- **Code:** `internal/api/ws.go` - per-connection subscription cap (32, one error frame on excess); `feed.go` - index-gate the empty-tailer resync (re-scan only when the Store index moved, plus slow backoff) and cache the alloc list per index in `statsFor` (the `feedStoreKind` pattern).
- **Tests:** cap refused with error frame; resync does not scan on idle ticks; feeds still re-select on deploy (the v1.70 regression stays green).

### PR-18 - K-20: fd-based host-path mounts
- **Code:** `internal/storage/hostpath.go` - `Resolve`/`ResolveOrCreate` return an open handle (`openat2(RESOLVE_BENEATH|NO_SYMLINKS)`; kernel floor 5.10 covers it) instead of a bare string; the reconciler holds the fd through `driver.Create` and the mount source becomes `/proc/self/fd/N`. Interface change ripples: `ensureVolumes`, `plan.go` mount construction, the create path's failure cleanup. Keep the string form for the plan/dry-run paths (no mount there).
- **Tests:** symlink-swap race loses (mount sees the checked object); create=true ancestor logic unchanged; fd lifecycle (no leaks on failure paths).
- **Docs:** THREAT_MODEL §3.12 note (the race is closed, the rw-volume precondition paragraph rewritten); AGENTS.md bullet.

---

## Phase 4 - Lows, in themed batches

> ~1 week total. Each batch is one PR; every item still gets its own test/assertion.

### PR-19 - edge (K-21…K-25)
- K-21: `--status` non-loopback → loud warning at startup (refuse would break existing flag users; warn + doctor finding). K-22: one exported header blocklist shared by jobspec and the edge + equality test. K-23: bcrypt cost ceiling (12-14) at projection and edge compile; dummy hash at the configured cost. K-24: THREAT_MODEL §3.14 documents session-resumption behavior (decision: document, not re-key). K-25: projection files stat-checked on load (regular, root-owned, not group/world-writable; keep-last-good makes refusal safe).

### PR-20 - DNS (K-26…K-28)
- K-26: internal answers served inline behind a global in-flight semaphore with drop-on-full (+ drop counter, constraint-#8 discipline). K-27: `--dns-listen` refuses non-private/non-loopback/non-ULA (flag validation; small PRD §15.1 note). K-28: read up to 4096 (or client EDNS size); overflow → TC with header+question only.

### PR-21 - datapath (K-29…K-32, I-1, I-2)
- K-29: `stats_ep` entries deleted in `Detach`; `stats_drops` overflow key per reason past a watermark (count the fold). K-30: drop v4 multicast/broadcast in `from_container`. K-31: ethertype whitelist (`ETH_P_IP`/`ETH_P_IPV6`/`ETH_P_ARP`, drop rest) on both programs. K-32: add `100.100.100.200/32` and decode `64:ff9b::/96` in the v6 egress drop. One `make bpf` regen for all; floor test counts updated; I-1/I-2 become comments beside the code they describe.

### PR-22 - API/auth (K-33…K-39)
- K-33: login requires `Content-Type: application/json` (415 otherwise). K-34: fixed 5xx body + correlation id (verbatim stays for 4xx). K-35: `recover()` in feed and exec goroutines. K-36: per-subject WS connection caps (or a reserved write-role slice) + fix the stale comment. K-37: bounded semaphore on streaming REST log routes. K-38: remove the `LastUsed` column (document why - per-request writes are forbidden). K-39: `backup.verify` becomes `adminOnly`.

### PR-23 - supply/platform (K-41…K-45, I-4)
- K-41: `upgrade` refuses `target < running` without `--allow-downgrade` (+ flag help on the schema story). K-42: SHA-pin every GitHub Action (Dependabot keeps them fresh), pin tool versions in `make tools`, move gates to a separate job from build+sign in `release.yml`. K-43: `selfupdate` `CheckRedirect` mirroring `fetch.go`. K-44: clone byte cap (`--max-clone-mb`-style guard in the syncer). K-45: scrub C0/C1 control chars at the CLI print boundary. I-4: anchor/comment the cosign identity regexp.

### PR-24 - isolation/storage (K-46…K-48)
- K-46: plan-time character validation for `bucket`/`server`/`export`/`share`; `--` before positional helper args where supported; screen `options` against Kanea-set keys (`ro,rw,uid,gid,dir_mode,file_mode,umask,credentials,passwd_file,url`). K-47: volume destinations get the socket-path refusals (share `systemPathFor`; include the resolv.conf destination). K-48: document the `CAP_SETFCAP` + rw-host-volume interaction in the permitted-set rationale and site/docs (decision: document; removing it from the permitted set would break existing specs).

### PR-25 - crypto/state (K-49…K-52, I-5)
- K-49: S3 sink `CheckRedirect: http.ErrUseLastResponse` + actionable 3xx error naming the `Location` host. K-50: one-time warning per secretsource provider on `http://` endpoints (mirror the S3 wording). K-51: `loadGrant` warns on group/other-readable key files (warn, not refuse - certbot layouts). K-52: `store.Open` stats `state.db` and warns/refuses on group/other-readable (mirror `checkKeyPermissions`; pick warn-with-doctor-finding for consistency with upgrades). I-5: comment on `NewLDAP` userinfo.

---

## Coverage map (everything is assigned)

| Findings | PR |
|---|---|
| K-01, K-40 | PR-01 |
| K-02 | PR-06 |
| K-03 | PR-02 (+PR-03 for the inline-resource half) |
| K-04, K-17 | PR-03 |
| K-05, I-3 | PR-05 |
| K-06 | PR-07 |
| K-07 | PR-09 |
| K-08 | PR-08 |
| K-09 | PR-11 |
| K-10 | PR-12 |
| K-11 | PR-13 |
| K-12 | PR-14 |
| K-13 | PR-15 |
| K-14 | PR-16 |
| K-15, K-16 | PR-04 |
| K-18 | PR-17 |
| K-19 | PR-10 |
| K-20 | PR-18 |
| K-21…K-25 | PR-19 |
| K-26…K-28 | PR-20 |
| K-29…K-32, I-1, I-2 | PR-21 |
| K-33…K-39 | PR-22 |
| K-41…K-45, I-4 | PR-23 |
| K-46…K-48 | PR-24 |
| K-49…K-52, I-5 | PR-25 |

## Sequencing and dependencies

```
Phase 1 (any order, all independent):  PR-01 → PR-04 share files (land together or PR-01 first)
                                       PR-02 ↗ lands beside PR-03 (inline half)
                                       PR-03, PR-05, PR-06 independent
Phase 2:                               PR-07, PR-08, PR-09 independent
                                       PR-10 after PR-03 (env scope checks at the seam)
Phase 3:                               PR-11 first (datapath), PR-21 after it (one regen cadence)
                                       PR-18 after PR-02/PR-24 settle (storage interface churn)
                                       PR-12…PR-17 independent
Phase 4:                               batches in any order; PR-21 sequenced as above
```

- **Sizes:** PR-10 L; PR-11, PR-18 M+; PR-06, PR-08, PR-09 M; everything else S.
- **Estimate:** ~4-5 weeks solo end-to-end; Phases 1-2 (the shippable security content) ≈ 2.5 weeks.
- **Parallelizable:** Phases 1's PRs, and Phase 4's batches, touch disjoint packages.

## Cross-cutting checklist (run once, at the end)

1. Every PR with a PRD obligation has landed its amendment (PR-02, PR-04, PR-08, PR-09, PR-10 (if semantics pinned), PR-11, PR-14, PR-20 (K-27 note)).
2. AGENTS.md bullets current for all 25 PRs; THREAT_MODEL gains the build section (PR-09), UDP paragraph (PR-14), §3.12 rewrite (PR-18), §3.14 note (PR-19); VALIDATION.md lists the real-node checks (PR-06, PR-07, PR-09, PR-11, PR-18).
3. `make check` green on main; the new CI tamper test (PR-05) and SHA-pinned actions (PR-23) verified in a CI run.
4. Release decision (deferred): when you tag, walk the AGENTS.md release list - version strings, docs-site references for changed user-facing behavior (storage `https`, git URL rules, UDP relay semantics, build security notes), and consider GitHub Security Advisories per SECURITY.md for K-01…K-08.
