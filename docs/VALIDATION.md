# Validation: what has been exercised on real hardware

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
| `init` → first HTTPS ≤ 5 min on a fresh VM | §21 UX, §20 | [§1](#1-init--first-https), **pending** |
| Functions end to end on a node | §20, the functions exit criterion | [`spikes/wasm-functions/REPORT.md`](../spikes/wasm-functions/REPORT.md) check H, **harness written, run pending** |
| Kernel floor ≥ 5.10 | §21 Platform | [`spikes/ebpf-datapath/REPORT.md`](../spikes/ebpf-datapath/REPORT.md) Kernel A, **pending**; run `go test -tags bpfload` on the node |
| S3 interoperability | §15.3 | `s3-interop` CI (MinIO, both addressing styles); real providers via `s3-cloud.yml`, **pending secrets** |
| OOM kills are attributed, not guessed | §17, §5.2.11 (v1.68) | [§5](#5-oom-attribution-v168), **pending** |

---

## 1. `init` → first HTTPS

§21's UX row is the acceptance standard, and it is more specific than "it
works":

> `init`→first HTTPS service ≤ 5 min on a fresh VM, **including on a node with
> no public name**, where that means `--tls-default self-signed`,
> `kanea ca show`, and one certificate installed on one device (§7.3)

So this is **two timed runs**, and the first needs no domain at all. Both start
from a *fresh* VM. A node with history, whether hand-edited units or a previous
install, cannot produce an honest number, and the failure class this is hunting is the
one that only appears on a machine nothing has been done to yet. (Both bugs in
the v1.53 and #59 genre were invisible in dev and fatal on the first real
systemd node.)

Time from the first command to a browser showing a valid certificate. Note
anything that required reading a doc, guessing, or a second attempt. That is
the finding, not a footnote.

### Run A: no public name (local VM)

The `--tls-default self-signed` path. No DNS, no ACME, no inbound ports: this
one runs on a laptop.

```bash
# 1. a fresh Linux VM: OrbStack, UTM, multipass, anything
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

### Run B: a real name (cloud VM)

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

## 2. Functions end to end (check H)

Driver and prerequisites: [`spikes/wasm-functions/check-h/`](../spikes/wasm-functions/check-h/).
Results belong in that spike's REPORT.md, beside checks A to G, which is the
discipline every other spike follows. This table points at it rather than
duplicating it.

## 3. Kernel floor (spike ⑤ Kernel A)

`spikes/ebpf-datapath/`'s Kernel A column (Debian 11 / 5.10) is still
`PENDING` in every row. What is owed, in the report's own words: verifier
acceptance of the four programs and the 20-byte-key v6 maps, `PROG_TEST_RUN` on
sched_cls (Q11a), and the `bpf_sock_addr.protocol` field (Q11b).

Two of those have caveats worth knowing before the run, so a failure is read
correctly rather than treated as a blocker:

- **Q11b is not a blocker.** `bpf_sock_addr.protocol` is read only by the
  spike's own `_proto` probe. The shipping `kanea.c` never reads it, and its
  only `protocol` reads are off the IP header, so the field's absence at the
  floor costs nothing that ships.
- **Batch map operations (Q9) may legitimately fail.** The report already
  treats the errno as recorded rather than as a failure.

Verifier acceptance is now also checked continuously: `internal/datapath`'s
`bpfload`-tagged floor test loads the shipping object and asserts all four
programs and sixteen maps verify. **CI does not run it.** Booting a 5.10 kernel
there was tried through `cilium/little-vm-helper` and abandoned, because the
action fetches the image and then hands `lvh` the qcow2 path where it expects a
registry reference, and a check that always fails is worse than one that does not
exist. So it runs by hand, here, as part of this same session:

```bash
sudo -E go test -tags bpfload -run Floor -v ./internal/datapath/
```

It does not replace the full harness, because it never attaches and attachment
is where the datapath meets netlink and cgroups. It is still the cheapest
question worth asking first, and it fails fast if the object will not verify at all.

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
removes when the *container* is deleted, not when the task exits. The
reconciler observes the exit first and tears down after, so the window should
hold, and the containerd-lifecycle spike read the counter after exit successfully
([`spikes/containerd-lifecycle/cgroups.go`](../spikes/containerd-lifecycle/cgroups.go),
check "alloc cgroup oom_kill incremented"). "Should hold" on a timing question
is exactly the genre of claim v1.53 and PR #59 were: invisible in dev, wrong on
the first real node. So it gets a run.

Five checks, on a node installed the ordinary way (`install.sh` + `kanea init`):

```bash
# ① a declared limit, exceeded: the message must name the number
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
kanea describe val/hog     # REASON: OOMKilled: exceeded its 64 MiB memory limit
kanea ps                   # unchanged from before v1.68: no REASON column here

# ② no declared limit: the kill came from the collective ceiling, and the
#    message must say so rather than naming a limit nobody typed. Squeeze the
#    node: --reserve leaves total-RAM − reserve for the whole workload slice.
#    (Remove the resources block from the spec above, then re-run.)
kanea describe val/hog     # REASON: OOMKilled: out of memory under the node's
                           #         workload ceiling (no limit declared)

# ③ THE NEGATIVE CASE, and the reason the counter is read at all: a forced stop
#    produces exit 137 too. It must NOT be reported as a memory problem.
kanea run examples/… ; kanea stop val/quiet   # any service that ignores SIGTERM
kanea describe val/quiet   # REASON: Signalled: killed by SIGKILL (exit 137)

# ④ an alloc that never starts explains itself instead of sitting at `pending`
kanea run --set image=ghcr.io/nope/nope:v0 …
kanea describe val/nope    # REASON: ImageFailed: <the registry's own words>
                           # and it keeps retrying: restarts stays 0, state
                           # never reaches `failed`

# ⑤ the notification carries the cause without anyone changing a filter
#    (an `on = ["service.crashed"]` route must still fire for ①)
```

**What a failure looks like, and what to do about it.** If ① reports
`Signalled: killed by SIGKILL` instead of `OOMKilled`, the cgroup was gone
before it was read, and the window assumption is wrong. The fix is not to
loosen the classifier, since inferring OOM from 137 would break ③, which is the
check that matters most. The fix is to move the read earlier: containerd publishes a
`/tasks/oom` event, and `runtime.Driver.Exits()` is already implemented and
currently unwired, so subscribing is the additive path.

| Check | Result | Date | Node |
|---|---|---|---|
| ① declared limit named | | | |
| ② collective ceiling named | | | |
| ③ `kanea stop` is not an OOM | | | |
| ④ start failure explained | | | |
| ⑤ `service.crashed` carries the cause | | | |

## 6. The edge runs as its own user

The §5.2.6 boundary is only real if the edge is not root (the audit's K-02:
uid 0 matches the owner of every root-owned file without needing one
capability). Unit tests pin the directive; what they cannot prove is that a
real init wires the account, the unit and the bundle's group together. On a
freshly inited node:

```bash
# ① the account exists
id kanea-edge

# ② the process runs as it
ps -o user= -p "$(systemctl show -p MainPID --value kanea-edge.service)"

# ③ the certificate bundle is group-readable by exactly that group
stat -c '%a %U %G' /run/kanea-edge/certs.json

# ④ doctor has no edge-user finding
kanea doctor
```

| Check | Result | Date | Node |
|---|---|---|---|
| ① `id kanea-edge` resolves | | | |
| ② edge process uid is kanea-edge | | | |
| ③ bundle is 0640 root:kanea-edge | | | |
| ④ `kanea doctor` is quiet about the edge user | | | |

## 7. The seccomp filter is real on a running alloc

PRD §14 A05 has claimed a default seccomp profile from the start; the audit found
it applied nowhere (K-06). The unit tests pin the spec. What they cannot prove
is that a real runc on a real kernel accepts the resolved profile and a
workload actually runs under it:

```bash
# ① a stock alloc runs under a filter (2 = SECCOMP_MODE_FILTER)
kanea run val/web --image nginx:1.27-alpine
pid=$(pgrep -f "nginx: master" | head -1)
grep Seccomp "/proc/$pid/status"

# ② a baseline alloc cannot call the gated syscalls
kanea exec val/web -- cat /proc/kallsyms >/dev/null 2>&1   # works (read)
kanea exec val/web -- /bin/true
# inside the alloc: `mount -t tmpfs none /tmp` must fail with EPERM *and* the
# syscall must be the one refusing (strace shows EPERM before any cap check)

# ③ the wasmtime shim starts under the same profile (functions node)
```

| Check | Result | Date | Node |
|---|---|---|---|
| ① `/proc/<pid>/status` shows `Seccomp: 2` | | | |
| ② `mount` fails with EPERM inside a baseline alloc | | | |
| ③ a wasm function serves under the profile | | | |

## 8. A build cannot reach the metadata service (v1.75)

A Dockerfile `RUN` step is repo-controlled code with host networking
(THREAT_MODEL §3.21), and the alloc-veth egress guard never sees it. The
control is an nftables drop of `169.254.0.0/16` for the `kanea-buildkit`
uid. Unit tests pin the rule's shape; what they cannot prove is that the
rootless daemon's processes really do carry that uid on the host:

```bash
# ① the rule is there
sudo nft list table ip kanea

# ② a RUN step cannot reach metadata, but the registry still works
cat > /tmp/Dockerfile <<'EOF'
FROM alpine:3
RUN wget -q -T 3 -O- http://169.254.169.254/latest/meta-data/ && exit 1 || exit 0
EOF
kanea build shop/meta-probe --path /tmp   # succeeds; the wget timed out

# ③ buildkitd itself pulls/pushes: a normal build still pushes its image
```

| Check | Result | Date | Node |
|---|---|---|---|
| ① the drop rule is in the `kanea` table | | | |
| ② a RUN step to 169.254.169.254 times out | | | |
| ③ a normal build pushes to its registry | | | |

## 9. The audit hardening pass (K-09, K-20, K-12)

The security remediation wave landed three controls whose correctness is
architectural but whose activation needs a node: the maps have to exist, the
mount has to be a mount, and the relay has to drop. Unit tests pin the shapes;
this run proves the wiring.

```bash
# ① K-09: the binding exists, and a forged source is dropped
sudo bpftool map show | grep veth_src            # both maps pinned
sudo bpftool map dump name veth_src               # one entry per alloc veth
kanea run --name probe --image alpine/curl       # in some project
# from the probe: forge another alloc's source address and fail
kanea exec probe -- sh -c 'ip addr add 10.200.0.99/32 dev eth0 2>/dev/null; ping -c1 -W1 10.200.0.1'
# (the add needs no capability Kanea grants; if it works, the ping must
#  still fail: the binding checks the veth's assigned address, not eth0's)
sudo bpftool map dump name stats_drops | grep -c SPOOF   # grew
```

```bash
# ② K-20: the mount source is the staging bind, not the checked path
kanea inspect shop-data | grep /run/kanea/host-volumes/   # per-alloc staging
mount | grep /run/kanea/host-volumes                       # the binds exist
# rename a symlink in the checked path after apply; the alloc restarts onto
# the pinned object, and the spec's next deploy re-derives cleanly.
```

```bash
# ③ K-12: one datagram gets at most 4 KiB back, and the 9th socket from one
#    address is refused
# (a udp-published service whose backend answers big; two datagrams lift the
#  cap; the counters kanea_edge_udp_refused_total{reason="unverified_cap"}
#  and {reason="source_limit"} move)
```

| Check | Result | Date | Node |
|---|---|---|---|
| ① veth_src maps exist and spoof drops count | | | |
| ② host volumes mount from the staging tree | | | |
| ③ the unverified byte cap and per-source cap bite | | | |

---

## 10. Init containers end to end (v1.84, §6.2 R32/R33)

The state machine is a pure function over a `World`, so the planner's every
transition is unit-tested against fixtures a node cannot easily produce: a step
running past its timeout, a vanished container mid-sequence, a spec change
between steps. What no test here can answer is the half that is a conversation
with containerd and the kernel:

> **does a second container of the same alloc actually join that alloc's
> network namespace, mount its volumes, and see its secrets — and does the
> reconcile loop keep serving every other service while a five-minute step
> runs?**

Everything about the design assumes yes. `initSpecFor` hands runc the alloc's
`NetnsPath` rather than one derived from the step's own id, the volume mounts
and the secrets bind come across from the alloc's spec unchanged, and the pass
returns after starting a step rather than waiting on it. Each of those is the
v1.53 genre: dev mode has no runc, so a wrong netns path or a mount that lands
empty is invisible until the first systemd node runs a migration.

Seven checks, on a node installed the ordinary way (`install.sh` + `kanea init`):

```bash
# The canonical shape: root fixes a directory the task will own as 999, then a
# migration reaches the database by name, then the task starts.
cat > init.hcl <<'EOF'
project "val" {}

storage "d" { type = "local" }

service "db" {
  project = "val"
  count   = 1
  task "db" {
    image = "postgres:17-alpine"
    env   = { POSTGRES_PASSWORD = "val" }
  }
  network { port "pg" { container = 5432 } }
  health_check "up" { type = "tcp", port = "pg" }
}

service "app" {
  project = "val"
  count   = 2

  volume "data" { storage = "d", mount_path = "/data" }

  init "fix-perms" {
    image        = "busybox:1.36"
    command      = ["sh", "-c", "chown -R 999:999 /data && echo fixed"]
    capabilities = ["CAP_CHOWN"]
    timeout      = "1m"
  }

  init "wait-db" {
    image   = "busybox:1.36"
    command = ["sh", "-c", "until nc -z $HOST 5432; do sleep 1; done; echo up"]
    env     = { HOST = "${service.db.host}" }
    timeout = "2m"
## 11. Env groups and config files (v1.85, §6.2 R34/R35)

The parse half is unit-tested hard, including the three properties that make a
secret placeholder unforgeable. What no test here can answer is the half that is
a conversation with runc and the kernel:

> **does a bind-mounted file actually appear at its path, with the right mode
> and owner, when the parent directory does not exist in the image — and does a
> secret-bearing one really live on a tmpfs rather than on disk?**

Everything about the design assumes yes. runc creates a missing mountpoint
before binding and does so before the rootfs is remounted read-only; the
secret-bearing tree is a tmpfs mounted lazily on first use; the plain tree lives
under the data dir precisely so that mount cannot hide it. Each is the v1.53
genre: dev mode has no runc and no `CAP_SYS_ADMIN`, so a wrong path, a mode that
does not apply, or a file written to disk instead of RAM is invisible until the
first systemd node runs one.

```bash
cat > files.hcl <<'EOF'
project "val" {}

env_group "common" {
  LOG_LEVEL = "info"
}

service "web" {
  project  = "val"
  count    = 2
  env_from = ["common"]

  file "nginx" {
    path    = "/etc/nginx/conf.d/default.conf"
    content = <<-EOT
      server {
        listen 8080;
        # a literal dollar-brace, which must survive as one
        proxy_set_header Host $${host};
      }
    EOT
  }

  file "pgpass" {
    path    = "/etc/app/pgpass"
    mode    = "0400"
    content = "db:5432:app:${secret.val["password"]}"
  }

  task "app" {
    image = "nginx:1.27-alpine"
    user { uid = 999, gid = 999 }
  }
}
EOF
kanea run init.hcl

# ① the sequence is visible while it runs, and names the step
kanea describe val/app     # STATE: init 2/2 wait-db
kanea ps                   # the other services keep their states; nothing stalls

# ② each step's output is its own log
kanea logs val/app -c fix-perms   # "fixed"
kanea logs val/app -c wait-db     # "up"  <- proves the shared netns and DNS

# ③ the task started after the last step, as uid 999, into a chowned directory
kanea exec val/app -- id          # uid=999
kanea exec val/app -- ls -ld /data

# ④ a failing step spends the restart budget rather than looping forever
#    (change fix-perms's command to `exit 1` and re-apply)
kanea describe val/app     # REASON: InitFailed: init "fix-perms" (1 of 2) exited with code 1
                           # then backoff 10s / 30s / 1m / 5m, then STATE failed

# ⑤ a hung step is killed and classified, within a reconcile interval of its
#    timeout (command = ["sleep", "600"], timeout = "30s")
kanea describe val/app     # REASON: InitTimeout: … exceeded its 30s timeout

# ⑥ a restart mid-sequence waits rather than re-running a finished step
#    (start a long step, then:)
sudo systemctl restart kanead
kanea describe val/app     # still on the same step; step 1 does not run again
sudo ctr -n kanea-val containers ls | grep '\.init\.'   # completed steps kept

# ⑦ pull_policy = "never" fails by name on an absent image, and starts on a
#    preloaded one
printf 'images {\n  pull_policy = "never"\n}\n' | sudo tee /etc/kanea/kanea.hcl
sudo systemctl restart kanead
kanea run init.hcl         # REASON: ImageFailed: … pull_policy is "never"
sudo ctr -n kanea-val images pull docker.io/library/busybox:1.36
kanea run init.hcl         # starts, with no registry reachable
```

Two things to watch for that the checks above will not spell out. The alloc must
**never appear as an LB backend while it is in `init`** (`backendsFor` gates on
the *main* container reporting running, so `curl` against the VIP during a
sequence must refuse at connect, not hang); and `kanea ps` for the *other*
services on the node must keep updating throughout ⑤, which is the whole
"the pass never waits" claim.

| Check | Result | Date | Node |
|---|---|---|---|
| ① the sequence is visible and names the live step | | | |
| ② each step's log is readable with `-c` | | | |
| ③ the task runs as its own user into the chowned volume | | | |
| ④ a failed step spends the restart budget | | | |
| ⑤ a hung step is killed and classified `init_timeout` | | | |
| ⑥ a kanead restart resumes without re-running finished steps | | | |
| ⑦ `pull_policy = "never"` refuses and preloading works | | | |
    user { uid = 101, gid = 101 }
  }
}
EOF
kanea secret put val/password 's3cr3t'
kanea run files.hcl

# ① the plain file is at its path, world-readable, read-only, and the parent
#    directory did not exist in the image for the second one
kanea exec val/web -- cat /etc/nginx/conf.d/default.conf   # ${host}, not $${host}
kanea exec val/web -- stat -c '%a %U' /etc/nginx/conf.d/default.conf   # 644
kanea exec val/web -- sh -c 'echo x >> /etc/nginx/conf.d/default.conf' # read-only

# ② the secret-bearing file is 0400, owned by the workload, and on a tmpfs
kanea exec val/web -- stat -c '%a %u' /etc/app/pgpass      # 400 101
kanea exec val/web -- cat /etc/app/pgpass                  # …:app:s3cr3t
findmnt -no FSTYPE /run/kanea/files                        # tmpfs
grep -r s3cr3t /var/lib/kanea/ ; echo "exit=$?"            # must find nothing

# ③ the value is nowhere in the platform's own state
kanea describe val/web            # names the reference, never the value
curl -s .../v1/services | grep -c s3cr3t                   # 0
kanea backup create && kanea backup verify <id>            # then grep the archive

# ④ rotation lands at the next replacement, not before
kanea secret put val/password 'rotated'
kanea exec val/web -- cat /etc/app/pgpass                  # still s3cr3t
kanea restart val/web
kanea exec val/web -- cat /etc/app/pgpass                  # rotated

# ⑤ an unresolvable reference fails the alloc before any container exists
kanea secret rm val/password && kanea restart val/web
kanea describe val/web                                     # REASON: files_failed

# ⑥ an unchanged spec re-applied rolls nothing
kanea run files.hcl && kanea ps                            # same alloc ids, no restarts

# ⑦ the plain tree survives the tmpfs being mounted after it
#    (deploy a plain-file-only service first, then one with a secret file)
```

| Check | Result | Date | Node |
|---|---|---|---|
| ① a plain file mounts at its path, 0644, read-only | | | |
| ② a secret file is 0400, owned by the workload, on tmpfs | | | |
| ③ the value is absent from the Store, the API and a backup | | | |
| ④ a rotation lands at the next replacement | | | |
| ⑤ an unresolvable reference fails the alloc `files_failed` | | | |
| ⑥ re-applying an unchanged spec rolls nothing | | | |
| ⑦ the plain tree is not hidden by the files tmpfs | | | |
