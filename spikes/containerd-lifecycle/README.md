# Spike ② — containerd lifecycle, CNI, metrics, cgroup isolation

Throwaway M0 validation code (PRD §20). **Nothing here ships.** M1 reimplements the
validated patterns properly in `internal/runtime`.

## Questions this spike answers

1. **Task lifecycle** — can we drive pull → create → start → wait → kill → delete →
   restart with the raw `github.com/containerd/containerd/v2` client (no CRI, no k8s)?
2. **CNI from our own process** — can *our* code (not containerd, not kubelet) invoke
   CNI ADD/DEL against a task's netns and get working east-west + NAT'd outbound
   connectivity?
3. **Single `/v1/metrics` scrape** — does containerd's Prometheus endpoint expose
   per-task cgroup metrics (cpu/memory) for *all* allocs in one scrape — including
   tasks we placed under our own cgroup hierarchy (§5.2.11)?
4. **cgroup isolation** — can we build the PRD §5.2.11 hierarchy
   (`kanea.slice` floor via `memory.min` + `OOMScoreAdjust=-900`,
   `kanea-workloads.slice` collective ceiling, per-alloc `memory.max`/`cpu.max`/`pids.max`
   via the OCI spec) and does it hold under memory pressure, fork bombs, and CPU hogs?

## How to run (on the `kanea-spike` OrbStack VM, Ubuntu 24.04 arm64)

```sh
# one-time, inside the VM: install containerd 2.3.3, runc 1.5.1, CNI plugins 1.9.1
orb -m kanea-spike bash /Users/michael/Projects/kanea/spikes/containerd-lifecycle/provision-vm.sh

# on macOS: cross-build (no Go toolchain in the VM; /Users is shared into it)
cd spikes/containerd-lifecycle
GOOS=linux GOARCH=arm64 go build -o spike-linux .

# in the VM (repo dir is mounted at the same path; root needed for containerd/CNI/cgroups)
cd /Users/michael/Projects/kanea/spikes/containerd-lifecycle
sudo ./spike-linux lifecycle
sudo ./spike-linux metrics
sudo ./spike-linux cgroups
sudo ./spike-linux clean     # reset everything (containers, CNI, slices)
```

Results and go/no-go: see `REPORT.md`.
