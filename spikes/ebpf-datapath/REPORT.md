# REPORT — Spike ⑤: internal eBPF datapath (the standalone-Cilium replacement)

**Date:** TBD · **Verdict: PENDING (fill in after running the harness on both target kernels)** · **PRD amendments required: TBD**

> This report is a **template**. Every verdict below is `PENDING` and every
> findings block is a stub. Fill them in by running `sudo ./spike-linux` on
> the two target kernels and pasting the real `PASS`/`FAIL`/`INFO` lines and
> measurements. **Do not fabricate results.** The go/no-go for retiring
> Cilium in favour of an internal datapath depends on real numbers from real
> nodes — especially the 5.10 floor, where several checks exist precisely to
> discover what does not work.

This is the sequel to spike ① (standalone Cilium: GO, but only on ≥ 1.18 and
through file interfaces that churned mid-series). The question here is
whether Kanea can drop Cilium, etcd and the kvstore entirely and own a small
BPF datapath itself.

## Environment

Fill one column per kernel actually tested.

| | Kernel A (5.10 floor) | Kernel B (current) |
|---|---|---|
| Distro / kernel | Debian 11, `5.10.x` (TBD) | TBD |
| Arch | TBD | TBD |
| cgroup mode | v2 (TBD confirm unified) | v2 |
| clang / llvm | TBD | TBD |
| go | TBD | TBD |
| `cilium/ebpf` | v0.22.0 | v0.22.0 |
| Result | `N/N` (TBD) | `N/N` (TBD) |

Build: `./build.sh` (clang → `bpf/spike.o`). Reproduce: `README.md`.

---

## Q1 — connect4 at the root cgroup (host + netns/systemd cgroup, ALLOW_MULTI): **PENDING**

Attaches `kanea_connect4` at `/sys/fs/cgroup` as a pinned `bpf_link` with
multi semantics, and asserts a VIP connect is rewritten from (a) a plain host
process and (b) a process inside a pod netns wrapped in a transient systemd
scope — and that systemd's own cgroup programs are undisturbed
(before/after `BPF_PROG_QUERY` enumeration).

```
(paste 1a / 1b / 1c lines here)
```

**Findings:** _stub._ Record: does `AttachCgroup` return a real `bpf_link`
(pinnable) on the floor, or fall back to `PROG_ATTACH` (not pinnable)? What
cgroup programs does systemd already have attached at the root, and did the
count survive our attach?

## Q2 — pinned cgroup link survives loader exit; `Link.Update` under load: **PENDING**

A child process re-attaches + pins a link and exits; the parent verifies the
rewrite still happens. Then `Link.Update()` swaps the program repeatedly
while a connect hammer runs; asserts zero dropped connects.

```
(paste 2a / 2b lines here)
```

**Findings:** _stub._ Confirm the pin outlives the process. Record the
`Link.Update` swap error count under load (must be 0). Note if the floor
kernel lacks pinnable cgroup links (pre-5.7 territory — 5.10 has them, but
record it).

## Q3 — tc filters survive loader exit; `NLM_F_REPLACE` atomic; clean veth delete: **PENDING**

```
(paste 3a / 3b / 3c lines here)
```

**Findings:** _stub._ Record whether `clsact` + pinned-program `FilterReplace`
is genuinely atomic under traffic (0 errors), and that deleting the host-side
veth removes both filters and the qdisc with no leak.

## Q4 — end-to-end matrix: **PENDING**

pod→VIP→pod (random spread across two backends), host→VIP→pod (the
`kanea-edge` path), hairpin (pod→VIP→itself), zero-backend VIP fails **fast**
with EPERM (measured immediate, not a timeout), pod→uplink via masquerade
(asserted through the nft counter, not internet reachability).

```
(paste 4a–4e lines here)
```

**Findings:** _stub._ Record the zero-backend refusal latency (the whole
point of the connect-time `count==0 → return 0` path — it must be
sub-millisecond, not a connect timeout). Record the backend spread.

## Q5 — SYN-gated stateless policy: **PENDING**

same-project allowed; cross-project SYN dropped (drop counter increments);
`allow_v4` edge permits the cross-project connect and the reply flows; ICMP
within and across projects **recorded** (the SYN gate does not police ICMP —
this is a design input, not a pass/fail).

```
(paste 5a–5d lines + the 5d INFO lines here)
```

**Findings:** _stub._ The ICMP result is the interesting one: decide whether
the real datapath needs an explicit ICMP decision or accepts cross-project
ping as the cost of a stateless SYN gate.

## Q6 — netfilter interplay (docker/ufw simulation): **PENDING**

Installs a second nftables table with a FORWARD `policy drop` chain (what a
docker or ufw install does), records whether routed pod↔pod and pod→uplink
break, whether our own accept chain rescues them, and whether an explicit
accept inside the foreign chain restores reachability. State restored after.

```
(paste 6a–6d lines + the 6b INFO line here)
```

**Findings:** _stub._ This is the real-world-collision question. Record the
chain-priority interaction: our accept chain runs at `filter` priority, the
sim at `filter+10`. Does priority alone rescue routed traffic, or is a
DOCKER-USER-style explicit rule required? Whatever the answer, it drives a
`kanea doctor` check.

## Q7 — strict `rp_filter` and PERMANENT neighbors: **PENDING**

With `net.ipv4.conf.all.rp_filter=1`, does masqueraded return traffic and
pod↔pod routing still work, and do the static PERMANENT neighbor entries
function (no ARP on the point-to-point veths).

```
(paste 7a–7c lines here)
```

**Findings:** _stub._ The /32-on-both-ends + PERMANENT-neigh + scope-link-gw
plumbing is chosen specifically to survive strict rp_filter; confirm it does,
and that the neighbor entries never go STALE.

## Q8 — measurements: **PENDING**

Added connect latency through the LB program (1000 connects via VIP vs
direct), full alloc attach latency for the veth+tc+maps sequence (target:
beat Cilium's measured 123 ms – 1.15 s from spike ①), pinned map+prog kernel
memory, program load+verify time.

```
(paste the 8 INFO lines + 8a/8b/8c here)
```

| Metric | Kernel A | Kernel B | Cilium (spike ①) |
|---|---|---|---|
| added connect latency (VIP − direct) | TBD | TBD | n/a |
| alloc attach (min / median / max) | TBD | TBD | 123 ms – 1.15 s |
| pinned map+prog memlock | TBD | TBD | ~150 MiB agent RSS |
| program load+verify | TBD | TBD | n/a |

**Findings:** _stub._ The attach-latency comparison is the headline: a full
alloc here is veth + clsact + two filter attaches + a handful of map updates,
with no agent round-trip and no identity allocation from a kvstore. If it
lands well under Cilium's range, that is the strongest single argument for
the internal datapath.

## Q9 — batch map ops and the generation-flip update pattern: **PENDING**

Probes whether `BatchUpdate`/`BatchLookup`/`BatchDelete` work on this kernel
(they may not on 5.10 — the errno is recorded, not treated as failure), then
demonstrates the generation-flip update (write gen+1 backends, single
`svc_v4` update to the new gen, delete old gen) under concurrent connect
load, asserting no connect ever lands on a torn set — generations are
distinguishable by listen port.

```
(paste 9a (INFO + check) and 9b lines here)
```

**Findings:** _stub._ Record the batch-op errno on the floor. The important
result is 9b: the flip pattern is written to **not** depend on batch ops
(new-gen backends first, single pointer swap, old-gen delete last), so it
must be torn-free even where batch ops are absent. If a connect ever EPERMs
mid-flip, the ordering is wrong and the report must say so.

## Q10 — getpeername after connect-time DNAT: **PENDING**

Does `getpeername(2)` after a connect4 DNAT return the backend address (no
fixup program needed) or the VIP (a getpeername fixup program **is** needed)?

```
(paste the 10 INFO + check line here)
```

**Findings:** _stub._ This single result decides whether the real datapath
needs a fourth program (`cgroup/getpeername4`). Record it unambiguously.

## Q11 — `PROG_TEST_RUN` on SCHED_CLS; `bpf_sock_addr.protocol` probe: **PENDING**

Runs `kanea_to_container` under `BPF_PROG_TEST_RUN` against a crafted
cross-project SYN (expect `TC_ACT_SHOT`) and non-SYN (expect `TC_ACT_OK`),
recording whether `PROG_TEST_RUN` on sched_cls works at the floor. Also loads
a second connect4 variant that reads `ctx->protocol` to record whether that
field is usable at the floor (it gates whether the real program can rely on
`protocol` or must gate on `type` alone).

```
(paste 11a and 11b (+ INFO) lines here)
```

**Findings:** _stub._ Two independent floor facts here: (1) is sched_cls
`PROG_TEST_RUN` usable (it underpins any future unit testing of the policy
program), and (2) is `bpf_sock_addr.protocol` readable on 5.10. If (2) is
no, `kanea_connect4` must gate on `ctx->type == SOCK_STREAM` only, which is
what the shipping program already does — `kanea_connect4_proto` is the probe,
not the production form.

---

## Q12 — dual-stack (PRD v1.41): **PENDING**

The v6 half rides this spike rather than getting its own (the datapath's
gate is the datapath's gate). On both kernels, with the shipping object from
`internal/datapath/bpf`:

- **connect6 at the root cgroup**: a native v6 VIP dial from the host and
  from a netns/systemd cgroup rewrites to a v6 backend; a **v4-mapped dial**
  (`::ffff:a.b.c.d` through an `AF_INET6` socket) rewrites word 3 against the
  v4 service table and connects. Both under `BPF_F_ALLOW_MULTI` beside
  connect4, each behind its own pinned link.
- **verifier acceptance at the floor**: the v6 branches (fixed-offset
  `ipv6hdr` parse, the four-word compares) and the 20-byte-key maps
  (`svc_v6`, `backend_val6`, `drop_key6`, 32-byte `dp_config6`) load on 5.10.
- **tc v6 policy**: cross-project v6 SYN dropped, same-project and
  host-flagged v6 passes, non-SYN v6 TCP passes (the stateless gate),
  a nexthdr that is not plain TCP is denied cross-project (no
  extension-header walk — deny-closed by design).
- **the disabled-mode drop**: with `config6` all-zero, `ETH_P_IPV6` is
  dropped at both tc hooks and **v4 traffic is undisturbed** — this is the
  one default-behavior change v1.41 makes on v4-only nodes.
- **NODAD / addr_gen_mode=1 plumbing**: eth0 comes up with the static /128
  only (no fe80, no DAD delay), the AF_INET6 PERMANENT neighbors resolve
  both directions, and the cluster-CIDR6 route (deliberately not a default
  route) carries alloc↔alloc v6; external v6 fails ENETUNREACH immediately.
- **stats**: a v6 VIP connect increments the same `stats_svc` entry as its
  v4 twin (one invocation counter per frontend, §9.1); `stats_drops6`
  reasons match the events above.

```
(paste 12a–12f (+ INFO) lines here)
```

**Findings:** _stub._

---

## Go/No-Go summary

| # | Question | Kernel A (5.10) | Kernel B (current) | Notes |
|---|---|---|---|---|
| 1 | connect4 at root cgroup, ALLOW_MULTI, undisturbed host | PENDING | PENDING | |
| 2 | pinned link survives exit; Update under load | PENDING | PENDING | |
| 3 | tc filters survive exit; atomic replace; clean delete | PENDING | PENDING | |
| 4 | end-to-end matrix incl. fast EPERM + masquerade | PENDING | PENDING | |
| 5 | SYN-gated policy + allow edge + ICMP recorded | PENDING | PENDING | |
| 6 | netfilter interplay (docker/ufw drop) | PENDING | PENDING | |
| 7 | strict rp_filter + PERMANENT neighbors | PENDING | PENDING | |
| 8 | measurements (latency / attach / memory / verify) | PENDING | PENDING | |
| 9 | batch ops + generation-flip torn-free | PENDING | PENDING | |
| 10 | getpeername after DNAT | PENDING | PENDING | |
| 11 | PROG_TEST_RUN sched_cls + protocol field | PENDING | PENDING | |
| 12 | dual-stack: connect6 (+v4-mapped), tc v6, disabled-mode drop, NODAD (v1.41) | PENDING | PENDING | |

**Overall verdict: PENDING.** GO requires: Q1–Q9 green on both kernels; Q10
recorded (drives whether a getpeername program is needed); Q11 recorded
(drives the `type`-vs-`protocol` gate at the floor); **Q12 green on both
kernels for the dual-stack half of v1.41 — a Q12 failure gates only the v6
feature, not the datapath** (the v4 programs are unchanged by v1.41 except
the disabled-mode ETH_P_IPV6 drop, which Q12 covers). A FAIL on Q6 or Q7 is
not necessarily a NO-GO but must produce a documented `kanea doctor` check
and an operator note.

## PRD amendments required (fill in after the run)

_TBD — expected to touch the sections spike ① amended (§5.2.5 networking,
§23.2 tech stack, §21 footprint), retiring the Cilium/etcd/kvstore
dependency in favour of the internal datapath, if the verdict is GO._

## Implementation notes to carry into `internal/network` (fill in after the run)

_TBD — e.g. attach/detach ordering, the generation-flip primitive, whether a
getpeername program is needed, the floor-kernel gate, the nft chain-priority
interaction with docker/ufw._
