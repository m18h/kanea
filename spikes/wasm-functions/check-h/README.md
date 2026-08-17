# Check H: functions end to end on a kanead node

Checks A-G ran at the containerd level and went 7/7 GO (`../REPORT.md`,
2026-08-10). They validated everything *below* the datapath. H is the rest, and
it is the §20 M11 exit criterion:

> a wasi-http function deploys from a spec, serves through the edge (FQDN and
> functions-port modes), fires on a matching event and a cron tick; invocation
> rate visible from an east-west call; pre-v1.39 Store upgrade rolls zero allocs

It needs a real node (a running `kanead` with the eBPF datapath, `kanea-edge`,
and the wasmtime shim) which is exactly what a containerd-level harness cannot
stand in for.

## Files

| File | What it is |
|---|---|
| `check-h.hcl` | the spec: the function, an east-west caller, and a service deployed to emit `deploy.succeeded` |
| `mkimage.sh` | packages a `.wasm` as a host-platform scratch image and imports it into kanead's own containerd namespace |
| `check-h.sh` | the driver: one check per clause, `PASS`/`FAIL` per line, non-zero exit on any failure |

## Prerequisites

A node where `kanea init` has run, with the edge up and a functions port. The
shim is installed by default (`kanea install` with no `--only`), so a node
initialised with a current release already has it; `kanea doctor` reports it.

The module is **not committed**: `../.gitignore` excludes `/testdata/`, and a
`.wasm` blob in git is a binary nobody can review. Build it from the committed
Rust source:

```bash
rustup target add wasm32-wasip2          # Rust >= 1.82 emits a component directly
(cd ../modules/hello-http && cargo build --release --target wasm32-wasip2)
mkdir -p ../testdata
cp ../modules/hello-http/target/wasm32-wasip2/release/hellohttp.wasm ../testdata/hello.wasm
```

## Running it

```bash
sudo ./check-h.sh                 # everything, then tear the project down
sudo ./check-h.sh --keep          # leave it deployed to poke at
```

It takes about three minutes, most of it waiting: a cron tick is up to 90 s and
the east-west rate needs a minute of traffic to be worth reading.

Paste the output into `../REPORT.md`'s check-H section, which is the discipline
every other spike report follows.

## Two things that look like bugs and are not

**The image ref never resolves against a registry.** `mkimage.sh` imports into
`kanea-<project>`, the namespace `runtime.Namespace(project)` computes, and
`EnsureImage` returns early whenever the image is already present locally. So
`registry.local/checkh/hello-http:1` is a name, not an address, which is what
makes this runnable on a node with no registry.

**The image is `linux/<arch>`, not `wasm/wasip2`.** That is REPORT.md finding 2:
containerd's default platform matcher (which `EnsureImage` uses, with no
special case) will not unpack a wasm-platform image. `mkimage.sh` defaults to
the node's own architecture for that reason.

## The clause this does not script

"pre-v1.39 Store upgrade rolls zero allocs" is a property of an *upgrade*, not
of a running node, so it cannot be staged after the fact on a node already
upgraded. It is pinned structurally by
`TestSpecHashIsUnchangedForASpecWithNoUserOrOwnership`, whose comment records
that v1.39's `Runtime` holds the same line: an empty string with `omitempty`
vanishes from the hash material, so a pre-v1.39 record and a post-v1.39 runc
service produce identical bytes.

To *observe* it as well as pin it, capture every alloc's `spec_hash` from
`GET /v1/services` before upgrading `kanead` across a v1.39 boundary and confirm
none are replaced afterwards. Any node that predates v1.39 can serve; the
upgrade is the test.
