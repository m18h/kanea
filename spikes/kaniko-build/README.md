# Spike ④ — image builds as containerd tasks

Throwaway M0 validation code (PRD §20). **Nothing here ships.** M7 implements the
chosen driver in `internal/gitops`.

## Questions this spike answers

1. **Does it work at all?** Build a Dockerfile and push it to an authenticated
   registry from a short-lived containerd task — no Docker daemon, no socket mount.
2. **Which driver?** PRD §10.2 names kaniko and defers the decision ("alternatives
   `buildah`, `img` noted; decision after M0 spike"). kaniko's upstream is now
   **archived**, so this spike compares it against two maintained alternatives.
3. **How much privilege?** Kanea's workload default is drop-ALL-caps +
   no-new-privileges (AGENTS.md #6). What does each builder actually require?
4. **Cache, limits, failures** — remote layer cache (PRD §10.2), builds under cgroup
   caps so they can't starve workloads, and failures that surface a usable error.

5. **Which shape?** BuildKit as a one-shot task needs a privileged container; as a
   **rootless host daemon** it needs no privilege at all. Both are measured.

Verdict and driver decision (**BuildKit as a rootless daemon**, buildah fallback,
kaniko removed): **[`REPORT.md`](./REPORT.md)**.

## Candidates

| Builder | Version tested | Upstream |
|---|---|---|
| kaniko | v1.24.0 | **ARCHIVED** (read-only since 2025-06; last release 2025-05-23) |
| BuildKit | v0.32.0 (rootless image) | active (released 2026-07-29) |
| buildah | image v1.43.1 (source v1.45.0) | active (released 2026-07-30) |

`img` is not tested: last commit 2024-05, effectively dormant.

The registry is a local `registry:3` run as a containerd task with **htpasswd basic
auth enforced** (the spike asserts an unauthenticated request gets 401), so the push
path exercises real credentials from a `config.json`, as PRD §10.2 requires.

## How to run (on the `kanea-spike` OrbStack VM, Ubuntu 24.04 arm64)

Requires spike ②'s VM (containerd).

```sh
# one-time, inside the VM: registry + credentials + build contexts + builder images
orb -m kanea-spike bash /Users/michael/Projects/kanea/spikes/kaniko-build/provision-vm.sh

# on macOS: cross-build (no Go toolchain in the VM; /Users is shared into it)
cd spikes/kaniko-build
GOOS=linux GOARCH=arm64 go build -o spike-linux .

# in the VM (root needed for containerd)
cd /Users/michael/Projects/kanea/spikes/kaniko-build
sudo ./spike-linux all         # every phase, every builder
sudo ./spike-linux build       # build + push + digest
sudo ./spike-linux cache       # cold vs warm build against a cache repo
sudo ./spike-linux hardening   # minimum privilege each builder needs
sudo ./spike-linux limits      # build under 1 GiB / 2 CPU cgroup caps
sudo ./spike-linux failure     # broken Dockerfile: exit code, logs, no push
sudo ./spike-linux daemon      # the CHOSEN path: rootless buildkitd host service
                               # (incl. Containerfile support + precedence)
sudo ./spike-linux clean       # remove build containers and empty the registry
```

## What the code is

| File | Role |
|---|---|
| `provision-vm.sh` | registry with basic auth, build contexts, builder images |
| `main.go` | subcommands, builder loop, PASS/FAIL bookkeeping |
| `builders.go` | the three builders as exact command lines + their requirements |
| `run.go` | runs one build as a containerd task at a chosen privilege level |
| `phases.go` | build / cache / hardening / limits / failure checks |
| `daemon.go` | the chosen path: rootless `buildkitd` host service driven by `buildctl` |
| `clean.go` | idempotent reset (also wipes the registry's storage) |
