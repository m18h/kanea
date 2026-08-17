# Spike ⑤: internal eBPF datapath (the standalone-Cilium replacement)

Throwaway M0-style validation code (see [`../README.md`](../README.md)).
**Nothing here ships.** If the verdict is GO, the real datapath is
reimplemented properly in `internal/network`; the spike is then frozen as
reference material.

## The question

Spike ① proved standalone Cilium works, but at a cost: a pinned 1.19.x
agent, etcd, `--lb-state-file`/`--static-cnp-path` file interfaces whose
REST equivalents were removed mid-series, and k8s-shaped objects on disk.
This spike asks whether Kanea can own the datapath itself with a handful of
small BPF programs and plain netlink/nftables (no Cilium, no etcd, no
kvstore) and still get: connect-time service load balancing, per-project
SYN-gated isolation, masquerade, and clean plumbing that survives the
control plane restarting.

The three programs (in [`bpf/spike.c`](./bpf/spike.c)):

| Prog | Type | Hook | Job |
|---|---|---|---|
| `kanea_connect4` | `cgroup/connect4` | root cgroup, `BPF_F_ALLOW_MULTI` via pinned `bpf_link` | VIP → backend DNAT at `connect(2)` (TCP only) |
| `kanea_to_container` | `sched_cls` | tc **egress** of the host-side veth | SYN-gated stateless policy (traffic **into** the pod) |
| `kanea_from_container` | `sched_cls` | tc **ingress** of the host-side veth | link-local + service-CIDR guard, tx accounting (traffic **out of** the pod) |

Maps are pinned under `/sys/fs/bpf/kanea-spike/`: a spike-specific root so
nothing here can collide with a real datapath or another tool.

Answers, kernel versions, measurements and the go/no-go: **[`REPORT.md`](./REPORT.md)**.

## Prerequisites (on the node)

- **root** (cgroup BPF attach, netns, tc, nftables).
- Linux **≥ 5.10** with cgroups v2 and `CONFIG_CGROUP_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_NET_CLS_BPF`, `CONFIG_NFT_MASQ`.
- **bpffs** mounted at `/sys/fs/bpf` (`mount -t bpf bpf /sys/fs/bpf`).
- **clang/llvm ≥ 10** and **go ≥ 1.26** on the node (the object is compiled there; there is deliberately no bpf2go generate step: see below).
- `iproute2` (`ip`), and `ping` for the ICMP observations in check 5.
- An IPv4 default route (the masquerade checks need an uplink).

### The two target kernels

1. **5.10-era**: Debian 11 (bullseye). This is the floor; several checks
   exist specifically to record what does *not* work here (batch map ops,
   `PROG_TEST_RUN` on sched_cls, the `bpf_sock_addr.protocol` field).
2. **current**: a recent distro kernel (6.x). The expected all-green run.

## Build and run

No `go generate`, no bpf2go: for throwaway code the object is compiled by a
one-line `clang` wrapper and loaded at runtime with
`ebpf.LoadCollectionSpec("bpf/spike.o")`. That removes the generate step and
keeps the air-gapped/offline story trivial.

```sh
cd spikes/ebpf-datapath

# 1. compile the BPF object (needs clang on the node)
./build.sh                       # -> bpf/spike.o

# 2. build the harness
go build -o spike-linux .

# 3. run as root, from this directory (it reads bpf/spike.o relative to cwd)
sudo ./spike-linux               # all 11 checks
sudo ./spike-linux -only 1,4,5   # a subset
sudo ./spike-linux -bpf /path/to/spike.o   # explicit object path

# if a run crashed and left state behind:
sudo ./spike-linux -cleanup      # purge netns, veths, dummy, nft tables, pin dir
```

The harness sets up its own world (BPF load + pin, cgroup attach, a host
dummy anchor, an nftables table, four pods `p1`-`p4`), runs the selected
checks, and tears **everything** down on exit: including on failure
(defer-based teardown). `-cleanup` is the belt-and-braces path for a hard
crash; note it does **not** restore sysctls (a fresh process cannot know the
pre-crash values), so if a run died inside check 7 you may want to reset
`net.ipv4.conf.all.rp_filter` by hand.

## Expected output shape

Same house style as spike ①; numbered `PASS`/`FAIL` lines, `INFO` for
recorded observations that are not go/no-go criteria, and a final tally:

```
── 1. connect4 at the root cgroup (host + netns/systemd cgroup, ALLOW_MULTI) ──
PASS  1a connect4 rewrites a host-process VIP connect        landed on 10.244.0.12:8080 (peer ...)
PASS  1b connect4 rewrites a netns/systemd-scope VIP connect landed on 10.244.0.13:8080
PASS  1c systemd's own cgroup programs undisturbed           7 pre-existing cgroup progs ... preserved
...
== 24/24 checks passed ==

OVERALL: PASS
```

(The exact check count depends on how many sub-checks each question emits;
fill the real numbers into `REPORT.md` after a run: do not trust this
sample.)

## What the code is

| File | Role |
|---|---|
| `bpf/headers.h` | self-contained minimal UAPI defs (no vmlinux.h, no CO-RE) |
| `bpf/spike.c` | the three datapath programs + the `protocol`-field load probe |
| `build.sh` | the `clang -target bpf` one-liner that produces `bpf/spike.o` |
| `main.go` | subcommands, shared env, setup/teardown, PASS/FAIL bookkeeping |
| `bpfload.go` | load + pin the object, attach connect4, cgroup-prog enumeration, memlock |
| `maps.go` | map key/value layouts (mirrors `spike.c`) + typed accessors |
| `plumb.go` | per-alloc netns/veth/tc/route/neigh plumbing, host anchor, nft-free sysctls |
| `nft.go` | nftables masquerade + FORWARD accept, and the docker/ufw drop simulation |
| `helpers.go` | the re-exec child modes (`__serve`/`__connect`/…) and their parsers |
| `checks_ab.go` … `checks_ij.go` | the 11 go/no-go checks |
```
