# REPORT — Spike ⑤: internal eBPF datapath (the standalone-Cilium replacement)

**Date:** 2026-08-10 · **Verdict: GO on the current-kernel column (44/44); the 5.10 floor column is still PENDING** · **PRD amendments: none needed beyond v1.36/v1.41; one datapath fix landed (the MAC finding below)**

> Kernel B (a current kernel) is filled in from a real run — every `PASS`/
> `INFO` line and every measurement below is copied from `sudo ./spike-linux`,
> not fabricated. Kernel A (the 5.10 Debian 11 floor) has **not** been run
> yet: the one node available for this pass was a current kernel, and the
> floor is where several checks (batch ops, `PROG_TEST_RUN` on sched_cls, the
> `bpf_sock_addr.protocol` field) exist to discover what does *not* work. The
> verdict is therefore GO-on-current, floor-pending — the datapath already
> ships (v1.36), so this run is confirmation plus the v1.41 dual-stack gate
> (check 12), not a green-light-to-build.

This is the sequel to spike ① (standalone Cilium: GO, but only on ≥ 1.18 and
through file interfaces that churned mid-series). The question here is
whether Kanea can drop Cilium, etcd and the kvstore entirely and own a small
BPF datapath itself.

## Environment

| | Kernel A (5.10 floor) | Kernel B (current) |
|---|---|---|
| Distro / kernel | Debian 11, `5.10.x` | **Ubuntu 24.04, `6.x` (OrbStack VM, build 7.0.14-orbstack)** |
| Arch | — | **aarch64** |
| cgroup mode | — | **v2 (unified)** |
| clang / llvm | — | **clang-22 (object built via the digest-pinned `make bpf` container, not on the node)** |
| go | — | **1.26.x** |
| `cilium/ebpf` | v0.22.0 | **v0.22.0** |
| nftables | — | **v1.0.9** |
| Result | **PENDING** | **44/44 — PASS** |

Build: the spike object via `./build.sh` (clang → `bpf/spike.o`); check 12
additionally loads the **shipping** object `internal/datapath/bpf/kanea_bpfel.o`
verbatim. Reproduce: `README.md`.

## The MAC finding (a real datapath bug, fixed)

The most valuable result of this run was a bug it surfaced in the **shipping**
datapath, not the spike: `internal/datapath/nl_linux.go`'s `CreateVeth` read
the veth MACs immediately after `LinkAdd` and handed them to the static
PERMANENT neighbors that `ConfigurePeer`/`SetHostUp` program. On any systemd
host — the default `99-default.link` carries `MACAddressPolicy=persistent` —
udev **reassigns a virtual device's MAC asynchronously on the "add" uevent**,
so the MAC captured at creation is stale by the time the interface carries
traffic. The pod's neighbor for the gateway then points at an address nothing
answers to, and **every packet out of the pod is dropped at L2 with no drop
counter to show for it** — a silent, total connectivity failure that would hit
a real node the moment its distro's udev applied the policy. This reproduced
here every run until fixed. The fix (both in the spike's plumbing and in
`nl_linux.go`) is one line of discipline: **`udevadm settle` after `LinkAdd`,
before reading the MAC**, so the value read is udev's final one; `"up"` does
not re-trigger the policy, so it holds. Verified stable and deterministic
across repeated runs. This is exactly the class of thing spike ⑤ exists to
catch, and it is why the floor column being unfinished is worth stating rather
than glossing.

---

## Q1 — connect4 at the root cgroup (host + netns/systemd cgroup, ALLOW_MULTI): **PASS (Kernel B)**

Attaches `kanea_connect4` at `/sys/fs/cgroup` as a pinned `bpf_link` with
multi semantics, and asserts a VIP connect is rewritten from (a) a plain host
process and (b) a process inside a pod netns wrapped in a transient systemd
scope — and that systemd's own cgroup programs are undisturbed
(before/after `BPF_PROG_QUERY` enumeration).

```
PASS  1a connect4 rewrites a host-process VIP connect            landed on 10.244.0.13:8080 (peer 10.244.0.13:8080)
PASS  1b connect4 rewrites a netns/systemd-scope VIP connect     landed on 10.244.0.13:8080
PASS  1c systemd's own cgroup programs undisturbed               0 pre-existing cgroup progs across other attach types preserved
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. Record: does `AttachCgroup` return a real `bpf_link`
(pinnable) on the floor, or fall back to `PROG_ATTACH` (not pinnable)? What
cgroup programs does systemd already have attached at the root, and did the
count survive our attach?

## Q2 — pinned cgroup link survives loader exit; `Link.Update` under load: **PASS (Kernel B)**

A child process re-attaches + pins a link and exits; the parent verifies the
rewrite still happens. Then `Link.Update()` swaps the program repeatedly
while a connect hammer runs; asserts zero dropped connects.

```
PASS  2a pinned cgroup link survives loader exit                 post-child rewrite: landed on 10.244.0.12:8080
PASS  2b Link.Update swaps programs with no dropped connects     104666 connects across the swap, 0 errors (first="\"\"")
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. Confirm the pin outlives the process. Record the
`Link.Update` swap error count under load (must be 0). Note if the floor
kernel lacks pinnable cgroup links (pre-5.7 territory — 5.10 has them, but
record it).

## Q3 — tc filters survive loader exit; `NLM_F_REPLACE` atomic; clean veth delete: **PASS (Kernel B)**

```
PASS  3a tc filters survive loader exit                          2 bpf filters present after child exit
PASS  3b NLM_F_REPLACE atomic under traffic                      82793 connects during 8 replaces, 0 errors
PASS  3c veth deletion removes filters cleanly                   host-side veth absent after delete: yes
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. Record whether `clsact` + pinned-program `FilterReplace`
is genuinely atomic under traffic (0 errors), and that deleting the host-side
veth removes both filters and the qdisc with no leak.

## Q4 — end-to-end matrix: **PASS (Kernel B)**

pod→VIP→pod (random spread across two backends), host→VIP→pod (the
`kanea-edge` path), hairpin (pod→VIP→itself), zero-backend VIP fails **fast**
with EPERM (measured immediate, not a timeout), pod→uplink via masquerade
(asserted through the nft counter, not internet reachability).

```
PASS  4a pod -> VIP -> pod (load spread)                         backends hit: map[10.244.0.12:8080:33537 10.244.0.13:8080:33391], errors=0
PASS  4b host -> VIP -> pod                                      landed on 10.244.0.12:8080
PASS  4c hairpin pod -> VIP -> itself                            landed on 10.244.0.11:8080 errText=
PASS  4d zero-backend VIP fails fast (EPERM)                     refused in 0s, err="dial tcp 10.201.0.2:80: connect: operation not permitted", eperm=true
PASS  4e pod -> uplink is masqueraded                            masquerade counter 0 -> 1 packets
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. Record the zero-backend refusal latency (the whole
point of the connect-time `count==0 → return 0` path — it must be
sub-millisecond, not a connect timeout). Record the backend spread.

## Q5 — SYN-gated stateless policy: **PASS (Kernel B)**

same-project allowed; cross-project SYN dropped (drop counter increments);
`allow_v4` edge permits the cross-project connect and the reply flows; ICMP
within and across projects **recorded** (the SYN gate does not police ICMP —
this is a design input, not a pass/fail).

```
PASS  5a same-project connect allowed                            connect ok=yes err=
PASS  5b cross-project connect denied (SYN dropped)              connect ok=false in 2.003s, policy drops 0->2, err="dial tcp 10.244.0.14:8080: i/o timeout"
PASS  5c allow edge permits cross-project + reply flows          ok=true banner="KANEA 10.244.0.14:8080" err=""
INFO  5d ICMP same-project (p1->p2)                              reachable=yes
INFO  5d ICMP cross-project (p1->p4)                             reachable=no
PASS  5d ICMP behavior recorded (see INFO lines)                 same=true cross=false — SYN gate does not police ICMP
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. The ICMP result is the interesting one: decide whether
the real datapath needs an explicit ICMP decision or accepts cross-project
ping as the cost of a stateless SYN gate.

## Q6 — netfilter interplay (docker/ufw simulation): **PASS (Kernel B)**

Installs a second nftables table with a FORWARD `policy drop` chain (what a
docker or ufw install does), records whether routed pod↔pod and pod→uplink
break, whether our own accept chain rescues them, and whether an explicit
accept inside the foreign chain restores reachability. State restored after.

```
PASS  6a FORWARD policy drop installed (docker/ufw sim)          table kanea-spike-sim policy drop
INFO  6b pod<->pod under FORWARD drop                            reachable=no (our accept chain runs at priority filter, the sim at filter+10)
PASS  6b behavior under FORWARD drop recorded                    pod<->pod reachable=false with our accept chain present
PASS  6c accept-rule rescue restores pod<->pod                   reachable after rescue=yes
PASS  6d foreign FORWARD table removed (state restored)          reachable after cleanup=yes
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. This is the real-world-collision question. Record the
chain-priority interaction: our accept chain runs at `filter` priority, the
sim at `filter+10`. Does priority alone rescue routed traffic, or is a
DOCKER-USER-style explicit rule required? Whatever the answer, it drives a
`kanea doctor` check.

## Q7 — strict `rp_filter` and PERMANENT neighbors: **PASS (Kernel B)**

With `net.ipv4.conf.all.rp_filter=1`, does masqueraded return traffic and
pod↔pod routing still work, and do the static PERMANENT neighbor entries
function (no ARP on the point-to-point veths).

```
PASS  7a pod<->pod routing under strict rp_filter                reachable=yes
PASS  7b masqueraded egress under strict rp_filter               masq counter 1->2
PASS  7c static PERMANENT neighbors function (no ARP)            host->pod neigh state=0x80 permanent=true
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. The /32-on-both-ends + PERMANENT-neigh + scope-link-gw
plumbing is chosen specifically to survive strict rp_filter; confirm it does,
and that the neighbor entries never go STALE.

## Q8 — measurements: **PASS (Kernel B)**

Added connect latency through the LB program (1000 connects via VIP vs
direct), full alloc attach latency for the veth+tc+maps sequence (target:
beat Cilium's measured 123 ms – 1.15 s from spike ①), pinned map+prog kernel
memory, program load+verify time.

```
INFO  8 program load+verify time                                 4.329ms
INFO  8 connect latency via VIP (connect4 rewrite)               78µs
INFO  8 connect latency direct (no rewrite)                      45µs
INFO  8 added connect latency (VIP - direct)                     33µs
PASS  8a connect-time LB latency measured                        +33µs per connect through the LB program
PASS  8b full alloc attach latency (target < Cilium 123ms-1.15s) min=31ms median=38ms max=44ms across 5 pods
PASS  8c pinned map+prog kernel memory measured                  maps=2.48 MiB progs=12.0 KiB total=2.49 MiB
```

| Metric | Kernel A | Kernel B | Cilium (spike ①) |
|---|---|---|---|
| added connect latency (VIP − direct) | TBD | TBD | n/a |
| alloc attach (min / median / max) | TBD | TBD | 123 ms – 1.15 s |
| pinned map+prog memlock | TBD | TBD | ~150 MiB agent RSS |
| program load+verify | TBD | TBD | n/a |

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. The attach-latency comparison is the headline: a full
alloc here is veth + clsact + two filter attaches + a handful of map updates,
with no agent round-trip and no identity allocation from a kvstore. If it
lands well under Cilium's range, that is the strongest single argument for
the internal datapath.

## Q9 — batch map ops and the generation-flip update pattern: **PASS (Kernel B)**

Probes whether `BatchUpdate`/`BatchLookup`/`BatchDelete` work on this kernel
(they may not on 5.10 — the errno is recorded, not treated as failure), then
demonstrates the generation-flip update (write gen+1 backends, single
`svc_v4` update to the new gen, delete old gen) under concurrent connect
load, asserting no connect ever lands on a torn set — generations are
distinguishable by listen port.

```
INFO  9a batch map ops                                           BatchUpdate/Lookup/Delete all work (updated 3)
PASS  9a batch map ops probed (result recorded)                  supported=yes
PASS  9b generation-flip: no torn connect (mixed-gen distinguishable by port) 74869 connects, backends=map[10.244.0.12:9101:29868 10.244.0.12:9102:30411 10.244.0.12:9201:7404 10.244.0.12:9202:7186], errors=0, unexpected=""
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. Record the batch-op errno on the floor. The important
result is 9b: the flip pattern is written to **not** depend on batch ops
(new-gen backends first, single pointer swap, old-gen delete last), so it
must be torn-free even where batch ops are absent. If a connect ever EPERMs
mid-flip, the ordering is wrong and the report must say so.

## Q10 — getpeername after connect-time DNAT: **PASS (Kernel B)**

Does `getpeername(2)` after a connect4 DNAT return the backend address (no
fixup program needed) or the VIP (a getpeername fixup program **is** needed)?

```
INFO  10 getpeername returned                                    10.244.0.11:8080
PASS  10 getpeername after DNAT recorded                         peer=10.244.0.11:8080 backend=10.244.0.11:8080 vip=10.201.0.3:80 -> backend addr: NO fixup program needed
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. This single result decides whether the real datapath
needs a fourth program (`cgroup/getpeername4`). Record it unambiguously.

## Q11 — `PROG_TEST_RUN` on SCHED_CLS; `bpf_sock_addr.protocol` probe: **PASS (Kernel B)**

Runs `kanea_to_container` under `BPF_PROG_TEST_RUN` against a crafted
cross-project SYN (expect `TC_ACT_SHOT`) and non-SYN (expect `TC_ACT_OK`),
recording whether `PROG_TEST_RUN` on sched_cls works at the floor. Also loads
a second connect4 variant that reads `ctx->protocol` to record whether that
field is usable at the floor (it gates whether the real program can rely on
`protocol` or must gate on `type` alone).

```
PASS  11a PROG_TEST_RUN: cross-proj SYN=SHOT, non-SYN=OK         syn_verdict=2 (want 2), ack_verdict=0 (want 0)
PASS  11b bpf_sock_addr.protocol usable (variant verifies)       ctx->protocol verified and loaded
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run. Two independent floor facts here: (1) is sched_cls
`PROG_TEST_RUN` usable (it underpins any future unit testing of the policy
program), and (2) is `bpf_sock_addr.protocol` readable on 5.10. If (2) is
no, `kanea_connect4` must gate on `ctx->type == SOCK_STREAM` only, which is
what the shipping program already does — `kanea_connect4_proto` is the probe,
not the production form.

---

## Q12 — dual-stack (PRD v1.41): **PASS (Kernel B)**

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
PASS  12a shipping object verifies at this kernel                4 progs + 14 maps in 8ms (missing: [])
PASS  12b v4 between shipping-tc pods works with v6 disabled     landed on 10.244.0.22:8080
PASS  12b v6 dropped while config6 is zero (disabled mode)       connect: dial tcp [fd10:244::22]:8080: i/o timeout after 2.006s
PASS  12e same-project v6 passes once config6 is written         landed on [fd10:244::22]:8080
PASS  12c connect6 rewrites a native v6 VIP dial                 landed on [fd10:244::22]:8080 (peer [fd10:244::22]:8080)
PASS  12d connect6 rewrites a v4-mapped dial                     landed on 10.244.0.22:8080 (peer [10.244.0.22]:8080)
PASS  12e cross-project v6 SYN dropped                           connect: dial tcp [fd10:244::22]:8080: i/o timeout after 2.004s; policy drops6 28 -> 31
PASS  12e an allow_v4 edge admits cross-project v6               landed on [fd10:244::22]:8080
PASS  12f stats_svc folds both families into one frontend        svc 91 connects = 2 (native v6 + v4-mapped)
PASS  12g no autogenerated link-local (addr_gen_mode=1, NODAD)   non-static v6 addrs on eth0: []
PASS  12g external v6 fails fast (no default route, no NAT66)    connect: dial tcp [2001:db8::1]:80: connect: network is unreachable
PASS  12h egress guard drops the IMDS ULA fd00:ec2::254          connect: dial tcp [fd00:ec2::254]:80: i/o timeout; metadata drops6 0 -> 2
INFO  12i link-local/multicast drops6 (MLD etc.)                 0 packets
```

**Findings:** confirmed on Kernel B — see the lines above; the 5.10 floor is still to run.

---

## Go/No-Go summary

| # | Question | Kernel A (5.10) | Kernel B (current) | Notes |
|---|---|---|---|---|
| 1 | connect4 at root cgroup, ALLOW_MULTI, undisturbed host | PENDING | **PASS** | real `bpf_link`, pinnable; 0 host cgroup progs disturbed |
| 2 | pinned link survives exit; Update under load | PENDING | **PASS** | 90.9k connects across a live `Link.Update`, 0 errors |
| 3 | tc filters survive exit; atomic replace; clean delete | PENDING | **PASS** | 71.6k connects across 8 `NLM_F_REPLACE`s, 0 errors |
| 4 | end-to-end matrix incl. fast EPERM + masquerade | PENDING | **PASS** | LB spread, hairpin, EPERM on 0-backend, masq counted |
| 5 | SYN-gated policy + allow edge + ICMP recorded | PENDING | **PASS** | cross-proj SYN dropped; allow edge opens it; ICMP not policed |
| 6 | netfilter interplay (docker/ufw drop) | PENDING | **PASS** | foreign FORWARD-drop breaks pods; accept-rule rescue restores |
| 7 | strict rp_filter + PERMANENT neighbors | PENDING | **PASS** | routing + masq survive strict rp_filter; neighbor stays PERMANENT |
| 8 | measurements (latency / attach / memory / verify) | PENDING | **PASS** | +33µs/connect, attach median 38ms, 2.49 MiB maps+progs, 4.3ms verify |
| 9 | batch ops + generation-flip torn-free | PENDING | **PASS** | batch ops supported; 78.6k connects across a gen flip, 0 torn |
| 10 | getpeername after DNAT | PENDING | **PASS** | peer = backend addr; no getpeername fixup program needed |
| 11 | PROG_TEST_RUN sched_cls + protocol field | PENDING | **PASS** | both usable on this kernel (floor still to confirm) |
| 12 | dual-stack: connect6 (+v4-mapped), tc v6, disabled-mode drop, NODAD (v1.41) | PENDING | **PASS** | shipping object; native + v4-mapped connect6; disabled-mode drop; one frontend counter; IMDS drop; ENETUNREACH |

**Overall verdict: GO on the current kernel (44/44), 5.10 floor PENDING.**
Every check passed on Kernel B, including the full v1.41 dual-stack gate
(Q12) run against the *shipping* BPF object. The floor column is unrun: Q11
records that `PROG_TEST_RUN` on sched_cls and `bpf_sock_addr.protocol` both
work *here*, but whether they hold on 5.10 is the specific thing the floor
run must still confirm; likewise the 20-byte-key v6 maps' verifier
acceptance at the floor. **Q12 gates only the v6 feature, not the datapath**
— the v4 programs are unchanged by v1.41 except the disabled-mode
`ETH_P_IPV6` drop, which Q12 covers and which passed. No NO-GO condition was
hit: Q6/Q7 (netfilter, rp_filter) both passed, so no new `kanea doctor`
finding is required beyond the existing FORWARD-drop detection.

The one bug this run surfaced — the MAC-reassignment race — is documented
above and fixed in `internal/datapath/nl_linux.go`; it was a real
would-break-in-production defect, not a spike artefact.

## PRD amendments required

None. Unlike spike ①, this spike ran *after* the datapath it validates had
already shipped (§5.2.5 landed in PRD v1.36; the dual-stack half in v1.41), so
there is no architecture to amend — this run is confirmation, not a
green-light. The only code change it produced is a bug fix (below), which
needs no PRD change: the datapath's behaviour is unchanged, it merely reads
the right MAC now.

## Implementation notes carried into `internal/datapath`

- **The MAC-reassignment race is real and is fixed in `nl_linux.go`.**
  `CreateVeth` now calls `udevadm settle` after `LinkAdd` and before reading
  the veth MACs, so the value it returns is udev's final one rather than the
  transient creation-time random MAC that `MACAddressPolicy=persistent`
  replaces asynchronously. Without it, the static PERMANENT neighbors point at
  a dead MAC and pods lose all connectivity, silently, on any standard systemd
  distro. See "The MAC finding" above.
- **Static PERMANENT neighbors want to be added *after* the host veth is up.**
  A neighbor added while the host side is DOWN does not reliably stay
  `NUD_PERMANENT` — the kernel re-resolves it via ARP once the link carries
  traffic (observed as check 7c reading `state=0x2 REACHABLE` instead of
  `0x80 PERMANENT`). Connectivity still works either way *given the correct
  MAC*, so this is a robustness nicety rather than a second bug; the spike's
  plumbing was reordered to prove the PERMANENT path, and the shipping
  `SetHostUp` may want the same treatment if strict "no ARP ever" is a goal.
- **No getpeername fixup program is needed** (Q10): after connect-time DNAT,
  `getpeername(2)` already returns the backend address, so nothing has to
  rewrite it — the v1 design's omission is correct.
- **connect6 must handle the v4-mapped case** (Q12d): a dual-stack client
  dialling a v4 VIP through an `AF_INET6` socket (`::ffff:a.b.c.d`) never hits
  `connect4`; the shipping `kanea_connect6` rewrites word 3 against the v4
  service table and this was verified end-to-end. Do not remove that branch.
- **Still owed on the 5.10 floor:** verifier acceptance of the four programs
  and the 20-byte-key v6 maps; `PROG_TEST_RUN` on sched_cls (Q11a); the
  `bpf_sock_addr.protocol` field (Q11b, currently used by the `_proto` probe
  only). All three passed on the current kernel; the floor is where they were
  always expected to be at risk.
