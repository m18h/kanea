# REPORT; Spike: wasm functions on the wasmtime runwasi shim

**Date:** 2026-08-10 · **Verdict: GO (7/7 harness checks; the load-bearing questions A-E and G all pass)** · **PRD amendments required: none**

> Filled in from a real run: every `PASS`/`INFO` line below is copied from
> the harness against a real containerd, not fabricated. One node was
> available (a current kernel); that is sufficient here because the questions
> this spike gates are about the shim's acceptance of Kanea's OCI spec and the
> module packaging, not kernel-version behaviour the way the datapath spike's
> floor is.

## Why this spike exists

PRD v1.39 ships functions as long-running wasi-http services on
`io.containerd.wasmtime.v1`. The code paths are ordinary (`WithRuntime` at
container create, the standard hardening opts, the netns join) but four
assumptions are load-bearing and only a real node can confirm them. All four
are now confirmed (see Findings).

## Environment

| | Node |
|---|---|
| Distro / kernel | Ubuntu 24.04.4 LTS, `6.x` (OrbStack VM, build 7.0.14-orbstack) |
| Arch | aarch64 |
| containerd | v2.3.3 (system daemon at `/run/containerd/containerd.sock`; the version Kanea pins) |
| shim | containerd-shim-wasmtime v0.6.1 (manifest-pinned; SHA-256 verified against `components.json`, arm64 `0ae922…`) |
| module toolchain | Rust 1.97: `wasm32-wasip1` for the idle/hog modules, `wasm32-wasip2` + the `wasi` crate for the wasi-http module (see "How the modules were built") |
| Result | **7 PASS, 0 FAIL, 1 INFO** |

## Checklist

Run (module toolchain is Rust/rustup here rather than tinygo/cargo-component;
see below):

```
# modules (Mac or node, wasm is arch-neutral)
rustup target add wasm32-wasip1 wasm32-wasip2
#   idle+hog: a wasip1 bin; wasi-http: a wasip2 cdylib depending on `wasi = "0.14"`
./mkimage-host.sh    # host-platform scratch image for the wasi-http module (REF=…hello-wasm-host:1)
./mkimage-hog.sh     # host-platform scratch image whose entrypoint is /app.wasm hog
go build -o spike-wasm-linux .
sudo ./spike-wasm-linux -socket /run/containerd/containerd.sock \
    -image registry.local/spike/hello-wasm-host:1 \
    -hog-image registry.local/spike/hog-wasm:1
```

| # | Check | Verdict | Notes |
|---|---|---|---|
| A | shim binary resolvable on containerd's PATH | **PASS** | `/usr/local/bin/containerd-shim-wasmtime-v1` (on containerd's `PATH`) |
| B | scratch wasm image imports **and unpacks** | **PASS** | only as a **host-platform** (`linux/arm64`) image: see finding 2 |
| C | create+start under the full hardening/resources opt set | **PASS** | the load-bearing one: the shim accepts drop-ALL caps, no-new-privs, masked/readonly paths, and the memory/CPU/pids cgroup spec unchanged |
| D | `task.Exec` refused | **PASS** | `/containerd.task.v2.Task/Exec is not supported` |
| E | wasi-http answers | **PASS** | HTTP 200 from the module, probed inside the instance's netns |
| F | module/shim RSS | **INFO** | ~19-20 MiB per module process: §21 footprint input |
| G | memory cap kills an allocating module | **PASS** | hog exited code 137 (SIGKILL/OOM) under a 16 MiB `memory.max` == swap |
| H | end-to-end on a kanead node (FQDN + functions port + event + cron) | **pending a run** | the §20 M11 exit criterion; needs a full kanead node with the datapath, not a containerd-level harness: this run validates everything H depends on below the datapath. The harness now exists: [`check-h/`](./check-h/), one check per clause. See the check-H section below |

```
PASS shim binary                            /usr/local/bin/containerd-shim-wasmtime-v1
PASS scratch image present + unpacks        registry.local/spike/hello-wasm-host:1
PASS create+start under hardening           runtime io.containerd.wasmtime.v1
PASS exec is absent                         task.Exec refused: /containerd.task.v2.Task/Exec is not supported
PASS wasi-http answers                      HTTP 200 from the module in its netns
INFO task RSS (module process)              ~20 MiB
PASS scratch image present + unpacks        registry.local/spike/hog-wasm:1
PASS memory cap OOM-kills a hog             hog exited under a 16 MiB cap (code 137; SIGKILL/OOM)

7 PASS, 0 FAIL, 1 INFO
```

## Findings

1. **The shim accepts Kanea's full OCI spec unchanged: no wasm branch needed
   in `specOpts` (check C).** `withHardening` (drop-ALL capabilities,
   `NoNewPrivileges`, masked/readonly paths) and `withResources`
   (memory/CPU/pids on the sandbox cgroup) applied verbatim, and create+start
   succeeded on `io.containerd.wasmtime.v1`. This is the plan-of-record
   confirmation: `internal/runtime/spec.go` needs **no** `if spec.Runtime != ""`
   branch. Had any opt been rejected, that opt would have been *the* finding.

2. **Module images must be host-platform scratch images, not `wasm/wasip2`
   (check B; packaging).** A scratch image labelled `architecture: wasm,
   os: wasip2` imports but the snapshotter will not unpack it for the host
   platform, and create then fails with "parent snapshot … not found". Kanea's
   `EnsureImage` pulls with the **default (host) platform matcher and no
   special case**, so the module must ship in a `linux/<arch>` scratch image
   (`FROM scratch` + `/app.wasm` + entrypoint). Re-labelling the image
   `arm64/linux` made unpack and create+start succeed. This confirms the
   deferred "OCI wasm-artifact / `wasi/wasm` platform" alternative would have
   required a matcher change: the host-platform scratch image is the right v1
   packaging, and the functions docs should say `FROM scratch` for a real
   host platform.

3. **`task.Exec` is genuinely unsupported (check D).** The shim returns
   `/containerd.task.v2.Task/Exec is not supported`, so the driver's
   `ErrNoExec`, R25's parse refusal, and the apply-boundary check rest on a
   real absence, not a policy. (If a future shim adds exec, they become a
   policy and the report should be revisited.)

4. **The cgroup memory cap is real, not advisory (check G).** A module
   allocating without bound under a 16 MiB `memory.max` (== `memory.swap.max`,
   so it cannot swap around the cap) was OOM-killed: the task exited with
   code 137. This is the claim R25/R11 rest on ("the memory cap is real").

5. **wasi-http serving works, in the instance's own network namespace
   (check E).** The shim logs `Found HTTP proxy target` → `Serving HTTP on
   http://0.0.0.0:8080/`, and a probe inside the instance's netns gets HTTP
   200. Two operational notes carried from this: the shim serves the proxy
   component on `0.0.0.0:8080` **inside the instance's netns** (so reaching it
   is the datapath's job (the alloc VIP) exactly as for any container), and a
   bare netns has `lo` **down**, so `127.0.0.1` is unreachable until it is
   brought up. Kanea's `createPod` already does `LinkSetUp(lo)`, so a real
   alloc is reachable both on its VIP and on loopback; the harness brings `lo`
   up to mirror that.

6. **Footprint (check F, §21):** ~19-20 MiB RSS per running module process
   (the embedded wasmtime runtime dominates a trivial module). One data point,
   on this arch/kernel.

## How the modules were built

The spike's `build-module.sh` documents tinygo / cargo-component; neither was
available on the run host, and wasm is arch-neutral, so the modules were built
with plain Rust (rustup) instead; a lighter path that needs no extra
component tooling:

- **idle / hog** (`wasm32-wasip1`): a `[[bin]]` crate whose `main` either idles
  (`loop { sleep }`) or, in `hog` mode (argv), appends 1 MiB chunks forever.
  `cargo build --release --target wasm32-wasip1` → `app.wasm`.
- **wasi-http** (`wasm32-wasip2`): a `cdylib` depending on `wasi = "0.14"`,
  exporting `wasi:http/incoming-handler` via `wasi::http::proxy::export!` and
  returning a 200. Rust ≥ 1.82 emits a component for `wasm32-wasip2` directly,
  so no cargo-component/wasm-tools step is needed.

Both are packaged by `mkimage-host.sh` / `mkimage-hog.sh` (host-platform
variants of `mkimage.sh`, per finding 2).

## Verdict

**GO.** A-E and G (the spike's stated GO criteria) all pass on the target
node, and F is recorded. The four load-bearing assumptions behind the v1.39
functions feature are confirmed: the shim takes Kanea's hardening/resources
spec unchanged, exec is absent, the memory cap is enforced, and a
host-platform scratch image is the correct module package. **Check H (the full
kanead end-to-end: `kanea run` a function, curl its FQDN and the functions
port, fire an event, watch a cron tick) remains**; it is the §20 M11 exit
criterion and needs a running kanead node with the datapath, above what a
containerd-level harness can reach. Everything H depends on below the datapath
is validated here.

---

## Check H: end to end on a kanead node

**Status: harness written, run pending.**

A-G above ran at the containerd level and validated everything below the
datapath. H is the §20 M11 exit criterion itself, verbatim:

> a wasi-http function deploys from a spec, serves through the edge (FQDN and
> functions-port modes), fires on a matching event and a cron tick; invocation
> rate visible from an east-west call; pre-v1.39 Store upgrade rolls zero allocs

[`check-h/`](./check-h/) drives it: one check per clause, `PASS`/`FAIL` per
line, non-zero exit on any failure. See its README for the module build and the
prerequisites. It is deliberately a node runbook rather than a CI job; CI
excludes the datapath on purpose (`ci.yml`: "a flaky required job teaches people
to ignore CI"), so the half CI could run is precisely the half A-G already
proved, and the half that is owed is precisely the half CI cannot reach.

### Environment

| | |
|---|---|
| Node | *(fill in: host, arch, kernel)* |
| kanea | *(fill in: `kanea version`)* |
| containerd / shim | *(fill in: `kanea doctor`)* |
| Network mode | *(ebpf: the invocation-rate clause needs it; under `netns` the datapath publishes no counters and that clause is a documented partial)* |
| Date | *(fill in)* |

### Result

```
(paste the output of `sudo ./check-h/check-h.sh` here)
```

### The clause the driver does not script

"pre-v1.39 Store upgrade rolls zero allocs" is a property of an upgrade rather
than of a running node, so it cannot be staged after the fact on a node that has
already been upgraded. It is pinned structurally by
`TestSpecHashIsUnchangedForASpecWithNoUserOrOwnership`, whose comment records
that v1.39's `Runtime` holds the same line: an empty string with `omitempty`
vanishes from the hash material, so a pre-v1.39 record and a post-v1.39 runc
service produce identical bytes. To observe it as well, capture every alloc's
`spec_hash` from `GET /v1/services` before upgrading `kanead` across a v1.39
boundary and confirm none are replaced afterwards.

Observation: *(fill in; node, versions either side, allocs replaced)*
