# REPORT: Spike ⑧: user namespaces for workload allocs

**Date:** 2026-08-30 · **Verdict: GO on the mechanics, NO-GO as a drop-in (15/15 runnable checks; the feature needs a netns-lifecycle inversion)** · **PRD amendments required: none for the spike; the feature, if built, needs one**

> Every PASS/FAIL/INFO below is a real run on the media node against Kanea's
> own containerd; the raw output is pasted verbatim. Nothing is fabricated.
> One demonstration (a low-port bind against the floor) is deliberately an
> INFO, not a fabricated PASS: the stock alpine probe image has no working
> low-port listener, so the bind is stated as not-exercised rather than faked.

## Why this spike exists

User namespaces are the hardening report's "real isolation bump" and the item
PRD §19.3 (v1.103) parks explicitly behind a spike, "the way datapath and wasm
were spiked". The accepted risk today is recorded in THREAT_MODEL §7: *container
uid 0 is host uid 0, held back by capabilities, seccomp and namespaces rather
than a uid map.* This spike answers whether a Kanea-shaped alloc — the full
hardening opt set, the pre-created netns, a correct rootfs, and the host-side
ownership arithmetic (R24 chown, the secrets tmpfs) — can run under a uid map on
Kanea's pinned containerd, and what breaks.

## Environment

| | |
|---|---|
| Node | media (`kanea-media` containerd namespace lives beside the spike's own) |
| OS / kernel | Debian 12, `6.1.0-44-amd64` |
| Arch | amd64 |
| containerd | v2.3.3 (Kanea's, at `/run/kanea/containerd.sock`) |
| Snapshotter | overlayfs, advertises `remap-ids` (idmapped mounts available) |
| Map | `0 → 300000`, length 65536 (OCI-spec-only; no `/etc/subuid` write) |
| Result | **15 PASS, 0 FAIL, 11 INFO** |

## Checklist

```
sudo ./spike-linux -socket /run/kanea/containerd.sock
sudo ./spike-linux -socket /run/kanea/containerd.sock clean
```

| # | Check | Verdict | Notes |
|---|---|---|---|
| A | idmapped snapshots available | **PASS** | overlayfs advertises `remap-ids`; no chown-copy needed on this kernel |
| B1 | shape 1: runc-userns + `ip netns add` netns | **refused (INFO)** | sysfs will not mount for a netns the mounting userns does not own — kanead's current netns shape cannot combine with a userns |
| B2 | kanead-side plumbing reaches an owned netns | **PASS** | `ip netns exec` (setns + lo up) works against a child-userns-owned netns from init-root |
| B3 | shape 2: joined userns + owned netns | **refused (INFO)** | runc unconditionally remounts the rootfs `MS_PRIVATE`, which a *joined* (non-owning) userns may not do to an init-owned mount |
| B4 | shape 3: runc-made userns + fresh netns | **PASS** | the production model; this is what comes up, and what C–J run against |
| C | host uid is mapped | **PASS** | task Uid on the host is 300000 |
| C2 | container root is uid 0 inside | **PASS** | `id -u` = 0 |
| C3 | a written file is mapped on the host | **PASS** | a file the container writes lands host-owned 300000 |
| D | sees its netns / cannot modify it | **PASS** | lo is up inside; `ip link set lo down` refused (NET_ADMIN stays forbidden, R13) |
| E | port floor is the per-netns sysctl | **PASS + INFO** | kanead's lo-up + sysctl reach the userns netns (PASS); the :80 bind itself is INFO (no low-port listener in the stock image) |
| F | R24 chown arithmetic | **PASS** | a dir chowned base+999 is writable by container uid 999; one chowned plain 999 is not |
| G | shifted 0400 secret is readable | **PASS** | uid 999 reads its base+999-owned 0400 secret; uid 1000 is refused |
| H | PUID/s6 image under a map | **PASS** | linuxserver nginx's s6 init completes: chown /config, drop to PUID, serve — all inside the userns; /config/nginx lands host-owned 301000 (base+PUID) |
| I | an unmapped grant is unusable | **INFO** | a host-root socket stats as overflow uid 65534 inside and its 0600 sibling is unreadable — the evidence for R21 (refuse grants under a map) |
| J | exec into the userns task | **PASS** | the driver's copy-the-process-spec exec shape works |

### Raw output

```
INFO kernel                                 6.1.0-44-amd64
INFO containerd                             v2.3.3
PASS idmapped snapshots available           overlayfs advertises remap-ids (no chown copy needed)
INFO image                                  docker.io/library/alpine:3.20 (pulled)
INFO shape 1: runc-userns + init-owned netns refused: task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: error mounting "sysfs" to rootfs at "/sys": mount src=sysfs, dst=/sys, dstFd=/proc/thread-self/fd/15, flags=MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC: operation not permitted - sysfs mount checks ns_capable(net->user_ns), and runc's fresh userns does not own an `ip netns add` netns
PASS kanead-side plumbing reaches an owned netns ip netns exec (setns + lo up) works against a child-owned netns from init-root
INFO shape 2: joined userns + owned netns   refused: task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: error preparing rootfs: remount-private dst=/run/kanea/containerd/io.containerd.runtime.v2.task/kanea-spike-userns/spike-userns-b-1788091924/rootfs, flags=MS_PRIVATE: permission denied - runc unconditionally remounts the rootfs MS_PRIVATE, which a joined userns may not do to an init-owned mount
PASS create+start under hardening + userns  runc-made userns + fresh netns, map 0:300000:65536
INFO snapshot prep (create call)            45ms
PASS host uid is mapped                     task Uid on the host is 300000
PASS exec into the userns task              the driver's copy-the-process-spec shape works
PASS container root is uid 0 inside         id -u = 0
PASS a written file is mapped on the host   host owner is 300000
PASS sees its netns (lo up)                 the workload observes the netns kanead wired
PASS cannot modify the netns                ip link set lo down refused: ip: ioctl 0x8914 failed: Operation not permitted (NET_ADMIN stays forbidden, R13)
PASS kanead plumbing reaches the userns netns lo up + sysctls applied from init-root by pid
INFO port floor is the per-netns sysctl     the workload's :80 bind is not exercised (the stock probe image has no low-port listener); the floor is ip_unprivileged_port_start=1024 in this netns, kanead's v1.103 knob, unchanged by the userns
PASS shifted chown (base+999) is writable   uid 999 wrote its volume
PASS today's chown (plain 999) is not       refused: touch: /vol-unmapped/no: Permission denied - the feature must shift every host-side chown, and host volumes (R15) stay incompatible
PASS a shifted 0400 secret is readable      uid 999 read its secret
PASS 0400 still excludes other uids         uid 1000 refused
INFO an unmapped grant is unusable          host-root socket stats as the overflow uid 65534 and its 0600 sibling is unreadable: grants must be refused under a map (R21)
INFO image                                  lscr.io/linuxserver/nginx:latest (pulled)
INFO PUID snapshot prep (create call)       50ms
PASS PUID image under a map                 the s6 init completed: chown /config, drop to PUID, serve - all inside the userns
INFO PUID chown lands mapped on the host    /config/nginx host owner is 301000 (base+PUID is 301000)

15 PASS, 0 FAIL, 11 INFO
```

## Findings

1. **The isolation is real and works on this kernel/containerd (checks C, C3, H, I).**
   Container root is host uid 300000; a file it writes is host-owned 300000; a
   linuxserver PUID image completes its full chown/drop-privileges init *inside*
   the userns and its `/config` chown lands host-owned 301000 (base+PUID). A
   kernel bug that reached container root would reach an unprivileged host uid,
   not host root. The v1.56 crash-loop class (PUID images) is not made worse by
   a map — it is made *safer*.

2. **The rootfs is a solved problem here (check A).** The overlay snapshotter
   advertises `remap-ids`, so `WithUserNSRemapperLabels` hands runc an idmapped
   mount with no recursive chown and ~45 ms of snapshot-prep per create. **This
   is a kernel gate for the feature**: idmapped overlayfs needs ≥ 5.19, above
   Kanea's 5.10 floor, so a userns feature would either carry its own higher
   kernel gate or fall back to the (slower, disk-heavier) recursive-chown remap
   on old kernels. Recorded so the floor decision is explicit.

3. **The netns lifecycle is the wall, and it is an inversion, not a flag (B1, B2, B3, B4).**
   Kanea is **netns-first**: kanead runs `ip netns add`, wires the veth, tc
   programs and sysctls, then runc *joins* the netns by path. sysfs refuses to
   mount for a netns whose owning user namespace the mounter does not own
   (`ns_capable(net->user_ns, …)`), so a runc-created userns cannot join an
   `ip netns add` netns (B1). Joining *both* a userns and a netns by path gets
   past sysfs but then runc cannot make the rootfs `MS_PRIVATE` from a non-owning
   userns (B3). The only shape that comes up is runc creating the userns **and**
   a fresh netns together (B4) — which is **netns-with-userns**, the opposite of
   kanead's order. B2 is the encouraging half: init-root *can* still wire a netns
   that a child userns owns (`ip netns exec` works), so the datapath's operations
   survive the map; what has to change is *when* the netns is created relative to
   the container. A userns feature therefore means: let runc create the netns,
   and have kanead attach the veth + tc + sysctls **by the task's pid afterward**
   — a real reconciler/datapath change (the attach step moves from before-create
   to after-create), not a per-service boolean bolted onto the current path.

4. **Every host-side chown must shift by the map base, and host/socket grants
   stay incompatible (checks F, G, I).** A volume chowned base+uid is the
   workload's; one chowned plain uid (today's `applyOwnership`,
   `reconcile.go:1385`) is unreadable under a map. The secrets tmpfs
   (`secrets.go:211`) and R35 secret files (`files.go:224`) need the same shift.
   A host resource nobody mapped — the socket grant of R18, a host volume of
   R15 — appears as overflow uid 65534 and is unusable, which is exactly why the
   feature must **refuse** a userns alloc that also declares such a grant (R21),
   never silently hand it something it cannot use.

5. **`task.user` is already userns-clean, and the SpecHash discipline is named.**
   The driver sets `Process.User` to container-namespace uids directly
   (`spec.go:245`), so nothing there changes. Any spec-visible `userns` field is
   SpecHash material (it changes the container) and must default to empty with
   `omitempty`, or turning userns on across an upgrade would roll every alloc on
   the node — the R23 lesson, restated for whoever builds this.

## Go / No-Go

**GO** that user namespaces are *viable and worth building* for Kanea: on a
current kernel the map applies cleanly, the idmapped rootfs is free, the
hardening opts and the PUID image class all survive it, and the ownership
arithmetic is a mechanical base-shift. This is the isolation bump the report
wanted, and nothing here refuses it.

**NO-GO** on a drop-in `userns = true`: the feature is gated on **inverting the
netns lifecycle** — runc creates the netns with the userns, kanead attaches the
datapath by pid afterward — plus a kernel-floor decision for idmapped overlayfs
(≥ 5.19, else the chown-remap fallback), the base-shift on every host-side chown,
and the R21 refusal of host/device/socket grants under a map. Those are the
scope of the feature, and they are real work, not configuration.

## Cleanup

`sudo ./spike-linux clean` removes the spike's containers, images, snapshots,
content blobs, both netns and userns binds, and the scratch tree, all in the
`kanea-spike-userns` containerd namespace (the empty namespace record itself
is inert and left for containerd to GC). The media services in `kanea-media`
are never touched. Verified on the node after the run: only `kanea-media` and
`kanea-system` hold content.
