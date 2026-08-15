# Validation — what has been exercised on real hardware

Most of what this platform claims is covered by tests, and those claims are
kept honest by CI. A handful are not coverable that way: §21's UX budget is a
stopwatch on a human being, the kernel floor needs the kernel, and functions
end to end need a node with a datapath. This page is where those runs are
recorded, so that a reader can tell which claims have evidence behind them and
which are still assertions.

It is deliberately a short page with dates on it. "We ran it once on a laptop"
is not a durable record, and a claim whose evidence nobody can find is
indistinguishable from one nobody checked.

| Claim | Where it is claimed | Evidence |
|---|---|---|
| `init` → first HTTPS ≤ 5 min on a fresh VM | §21 UX, §20 M10 | [§1](#1-init--first-https) — **pending** |
| Functions end to end on a node | §20 M11 exit criterion | [`spikes/wasm-functions/REPORT.md`](../spikes/wasm-functions/REPORT.md) check H — **harness written, run pending** |
| Kernel floor ≥ 5.10 | §21 Platform | [`spikes/ebpf-datapath/REPORT.md`](../spikes/ebpf-datapath/REPORT.md) Kernel A — **pending**; run `go test -tags bpfload` on the node |
| S3 interoperability | §15.3 | `s3-interop` CI (MinIO, both addressing styles); real providers via `s3-cloud.yml` — **pending secrets** |
| OOM kills are attributed, not guessed | §17, §5.2.11 (v1.68) | [§5](#5-oom-attribution-v168) — **pending** |

---

## 1. `init` → first HTTPS

§21's UX row is the acceptance standard, and it is more specific than "it
works":

> `init`→first HTTPS service ≤ 5 min on a fresh VM — **including on a node with
> no public name**, where that means `--tls-default self-signed`,
> `kanea ca show`, and one certificate installed on one device (§7.3)

So this is **two timed runs**, and the first needs no domain at all. Both start
from a *fresh* VM: a node with history — hand-edited units, a previous install —
cannot produce an honest number, and the failure class this is hunting is the
one that only appears on a machine nothing has been done to yet. (Both bugs in
the v1.53 and #59 genre were invisible in dev and fatal on the first real
systemd node.)

Time from the first command to a browser showing a valid certificate. Note
anything that required reading a doc, guessing, or a second attempt — that is
the finding, not a footnote.

### Run A — no public name (local VM)

The `--tls-default self-signed` path. No DNS, no ACME, no inbound ports: this
one runs on a laptop.

```bash
# 1. a fresh Linux VM — OrbStack, UTM, multipass, anything
#    (OrbStack: orb create ubuntu kanea-uxtest)

# 2. install
curl -fsSL https://raw.githubusercontent.com/m18h/kanea/main/scripts/install.sh | sudo sh

# 3. init: key ceremony, listen prompt, first admin
sudo kanea init

# 4. a service with a self-signed certificate from the node's own CA
sudo systemctl edit --full kanead    # or set --tls-default in the unit / kanea.hcl
# ... --base-domain home.lan --tls-default self-signed

# Checked against the real parser. The blocks are on their own lines on
# purpose: HCL's single-line block form takes exactly one argument, so
# `network { port "http" { container = 80 } }` is a parse error, not a
# shorthand (PRD v1.10 records the same trap in the §6.1 example).
cat > web.hcl <<'HCL'
spec_version = 1

project "demo" {}

service "web" {
  project = "demo"

  task "web" {
    image = "docker.io/library/nginx:1.27-alpine"
  }

  network {
    port "http" {
      container = 80
    }
  }

  expose {}
}
HCL
kanea plan web.hcl        # validates before anything touches the node
kanea apply web.hcl

# 5. trust the node's CA on one device, then open the service
kanea ca show > kanea-ca.crt
```

Record: time to a green browser at `web.demo.home.lan`, and whether the
dashboard was reachable at the address `init` chose.

### Run B — a real name (cloud VM)

The ACME path. This needs a cheap cloud VM with a public A record, because
HTTP-01 needs inbound :80 from Let's Encrypt and forwarding a laptop VM's port
is not an honest substitute for what an operator will do.

Same walk, with `--base-domain <your.domain>` and `--tls-default acme` (plus
`--acme-email`). Record time to a browser-green Let's Encrypt certificate.

### Results

| | Run A (self-signed) | Run B (ACME) |
|---|---|---|
| Date | *(pending)* | *(pending)* |
| kanea version | | |
| VM (image, arch, vCPU/RAM) | | |
| install → `init` complete | | |
| `init` → first HTTPS green | | |
| Within §21's 5 min? | | |
| Friction worth fixing | | |

---

## 2. Functions end to end (M11 check H)

Driver and prerequisites: [`spikes/wasm-functions/check-h/`](../spikes/wasm-functions/check-h/).
Results belong in that spike's REPORT.md, beside checks A–G, which is the
discipline every other spike follows. This table points at it rather than
duplicating it.

## 3. Kernel floor (spike ⑤ Kernel A)

`spikes/ebpf-datapath/`'s Kernel A column — Debian 11 / 5.10 — is still
`PENDING` in every row. What is owed, in the report's own words: verifier
acceptance of the four programs and the 20-byte-key v6 maps, `PROG_TEST_RUN` on
sched_cls (Q11a), and the `bpf_sock_addr.protocol` field (Q11b).

Two of those have caveats worth knowing before the run, so a failure is read
correctly rather than treated as a blocker:

- **Q11b is not a blocker.** `bpf_sock_addr.protocol` is read only by the
  spike's own `_proto` probe. The shipping `kanea.c` never reads it — its only
  `protocol` reads are off the IP header — so the field's absence at the floor
  costs nothing that ships.
- **Batch map operations (Q9) may legitimately fail.** The report already
  treats the errno as recorded rather than as a failure.

Verifier acceptance is now also checked continuously: `internal/datapath`'s
`bpfload`-tagged floor test loads the shipping object and asserts all four
programs and sixteen maps verify. **CI does not run it** — booting a 5.10 kernel
there was tried through `cilium/little-vm-helper` and abandoned, because the
action fetches the image and then hands `lvh` the qcow2 path where it expects a
registry reference, and a check that always fails is worse than one that does not
exist. So it runs by hand, here, as part of this same session:

```bash
sudo -E go test -tags bpfload -run Floor -v ./internal/datapath/
```

It does not replace the full harness — it never attaches, and attachment is where
the datapath meets netlink and cgroups — but it is the cheapest question worth
asking first, and it fails fast if the object will not verify at all.

**One thing to confirm during the run:** below kernel 5.11, BPF memory is
charged against `RLIMIT_MEMLOCK` rather than the cgroup memory controller, and
`kanead.service` sets no `LimitMEMLOCK`, so it inherits systemd's 8 MiB
default. Five of the datapath's maps are `PERCPU_HASH` at roughly 360 KiB per
CPU, so a machine with enough cores would exceed that. `loadPinned` now calls
`rlimit.RemoveMemlock()` to remove the question; the floor run is where "would
have failed without it" stops being arithmetic and becomes an observation. Try
it once with the call disabled on a many-core 5.10 box.

Run:

```bash
cd spikes/ebpf-datapath
./build.sh && GOOS=linux go build -o spike-linux .
sudo ./spike-linux
```

## 4. S3 interoperability

CI covers MinIO in both addressing styles (`s3-interop`). Real providers are
`s3-cloud.yml`: on demand and monthly, never required, skipping cleanly until
the per-provider secrets exist. Record here which providers have passed and
when, since that is the claim `docs/DR_RUNBOOK.md` §8 makes to someone
configuring a destination during an incident.

| Provider | Addressing | Last green | Notes |
|---|---|---|---|
| MinIO | path + virtual-hosted | every CI run | |
| AWS S3 | | *(pending secrets)* | |
| Cloudflare R2 | | *(pending secrets)* | |
| Backblaze B2 | | *(pending secrets)* | |
| Wasabi | | *(pending secrets)* | |

---

## 5. OOM attribution (v1.68)

§17 claims an alloc says *why* it died, and that the OOM half is **read rather
than inferred**. Unit tests cover the classifier and the cgroup parser against
a temp directory, which is exactly the part a fake can prove. What no test here
can answer is the one thing the whole feature rests on:

> **is the alloc's cgroup still readable at the moment the reconciler observes
> the stopped task?**

The kill is recorded in `memory.events`, and that file lives in a cgroup runc
removes when the *container* is deleted — not when the task exits. The
reconciler observes the exit first and tears down after, so the window should
hold, and the M0 spike read the counter after exit successfully
([`spikes/containerd-lifecycle/cgroups.go`](../spikes/containerd-lifecycle/cgroups.go),
check "alloc cgroup oom_kill incremented"). "Should hold" on a timing question
is exactly the genre of claim v1.53 and PR #59 were: invisible in dev, wrong on
the first real node. So it gets a run.

Five checks, on a node installed the ordinary way (`install.sh` + `kanea init`):

```bash
# ① a declared limit, exceeded — the message must name the number
cat > oom.hcl <<'EOF'
project "val" {}
service "hog" {
  project = "val"
  count   = 1
  task {
    image   = "alpine:3.20"
    command = ["sh", "-c", "tail /dev/zero"]   # allocates until it is stopped
  }
  resources { memory = 64 }
  restart   { attempts = 1 }
}
EOF
kanea run oom.hcl
kanea describe val/hog     # REASON: OOMKilled — exceeded its 64 MiB memory limit
kanea ps                   # unchanged from before v1.68: no REASON column here

# ② no declared limit — the kill came from the collective ceiling, and the
#    message must say so rather than naming a limit nobody typed. Squeeze the
#    node: --reserve leaves total-RAM − reserve for the whole workload slice.
#    (Remove the resources block from the spec above, then re-run.)
kanea describe val/hog     # REASON: OOMKilled — out of memory under the node's
                           #         workload ceiling — no limit declared

# ③ THE NEGATIVE CASE, and the reason the counter is read at all: a forced stop
#    produces exit 137 too. It must NOT be reported as a memory problem.
kanea run examples/… ; kanea stop val/quiet   # any service that ignores SIGTERM
kanea describe val/quiet   # REASON: Signalled — killed by SIGKILL (exit 137)

# ④ an alloc that never starts explains itself instead of sitting at `pending`
kanea run --set image=ghcr.io/nope/nope:v0 …
kanea describe val/nope    # REASON: ImageFailed — <the registry's own words>
                           # and it keeps retrying: restarts stays 0, state
                           # never reaches `failed`

# ⑤ the notification carries the cause without anyone changing a filter
#    (an `on = ["service.crashed"]` route must still fire for ①)
```

**What a failure looks like, and what to do about it.** If ① reports
`Signalled — killed by SIGKILL` instead of `OOMKilled`, the cgroup was gone
before it was read, and the window assumption is wrong. The fix is not to
loosen the classifier — inferring OOM from 137 would break ③, which is the
check that matters most — but to move the read earlier: containerd publishes a
`/tasks/oom` event, and `runtime.Driver.Exits()` is already implemented and
currently unwired, so subscribing is the additive path.

| Check | Result | Date | Node |
|---|---|---|---|
| ① declared limit named | | | |
| ② collective ceiling named | | | |
| ③ `kanea stop` is not an OOM | | | |
| ④ start failure explained | | | |
| ⑤ `service.crashed` carries the cause | | | |
