# REPORT — Spike: wasm functions on the wasmtime runwasi shim

**Date:** TBD · **Verdict: PENDING (fill in after running the harness on a real node)** · **PRD amendments required: TBD**

> This report is a **template**. Every verdict below is `PENDING`. Fill them in
> by running the harness on a Linux node with Kanea's containerd 2.3.3 and the
> pinned shim (`kanea install --only wasmtime-shim`), and paste the real
> `PASS`/`FAIL`/`INFO` lines. **Do not fabricate results.** The v1.39
> functions feature is implemented against the assumptions this spike tests —
> a FAIL here is a finding the implementation must absorb (§20 M11 gates on
> it), not a number to massage.

## Why this spike exists

PRD v1.39 ships functions as long-running wasi-http services on
`io.containerd.wasmtime.v1`. The code paths are ordinary — `WithRuntime` at
container create, the standard hardening opts, the netns join — but four
assumptions are load-bearing and only a real node can confirm them:

1. **The shim accepts Kanea's OCI spec.** `withHardening` (drop-ALL caps,
   no-new-privileges, masked/readonly paths) and `withResources` (memory,
   CPU, pids on the sandbox cgroup) are applied unconditionally in
   `internal/runtime/spec.go`. The plan of record is *no* wasm branch; if the
   shim rejects an opt, `specOpts` grows exactly one `if spec.Runtime != ""`
   branch naming this report's finding.
2. **`task.Exec` is absent.** `ErrNoExec` in the driver, R25's parse refusal
   and the apply-boundary check all assume it. If the shim grows exec, those
   stay (a *policy* now), but the report should say so.
3. **The scratch-image layout works end to end** — `FROM scratch` +
   `/app.wasm` + entrypoint, pulled by `EnsureImage` with `WithPullUnpack`,
   no platform-matcher special case. The alternative (OCI wasm artifacts,
   `wasi/wasm` platform) was deferred pending exactly this check.
4. **The netns join carries** — the module's listener is reachable on the
   alloc's VIP through the datapath, like any container. (The harness's HTTP
   check runs host-side; the full VIP check is the end-to-end pass below.)

## Environment

| | Node |
|---|---|
| Distro / kernel | TBD |
| Arch | TBD |
| containerd | 2.3.3 (Kanea's, `/run/kanea/containerd.sock`) |
| shim | containerd-shim-wasmtime v0.6.1 (manifest-pinned) |
| module toolchain | TBD (tinygo wasip2 / cargo-component) |
| Result | `N/N` (TBD) |

## Checklist

Run:

```
./build-module.sh
./mkimage.sh
go build -o spike-wasm .
sudo ./spike-wasm -socket /run/kanea/containerd.sock
```

| # | Check | Verdict | Notes |
|---|---|---|---|
| A | shim binary resolvable on containerd's PATH | PENDING | |
| B | scratch wasm image imports and resolves | PENDING | record whether `wasip2` platform imported or the linux/<arch> fallback was needed — this decides packaging docs |
| C | create+start under the full hardening/resources opt set | PENDING | a rejected opt is THE finding; name it |
| D | `task.Exec` refused | PENDING | |
| E | wasi-http answers | PENDING | |
| F | module/shim RSS | PENDING | feeds the §21 footprint table |
| G | memory cap kills an allocating module (`GET /hog` under a 16 MiB cap) | PENDING | the MEM CAP column's honesty depends on this |
| H | end-to-end on a kanead node: `kanea run` a function spec, curl the FQDN and the functions port, fire an event, watch a cron tick | PENDING | the §20 M11 exit criterion |

## Findings

TBD — paste harness output and observations here.

## Verdict

PENDING. GO requires A–E and G on the target node; F and the seccomp/masked-
paths interplay are recorded findings either way.
