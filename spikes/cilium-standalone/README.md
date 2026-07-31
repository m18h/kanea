# Spike ① — standalone Cilium (no Kubernetes)

Throwaway M0 validation code (PRD §20). **Nothing here ships.** M2 reimplements the
validated patterns properly in `internal/network`.

## Questions this spike answers

1. **CNI from our own process** — can *we* attach a containerd workload to Cilium
   (CNI `ADD` against a netns we control) with no kubelet and no k8s API server?
2. **Endpoint labels & identity** — can an alloc get a real security identity
   (project/service labels, kvstore-allocated) without Kubernetes pod metadata?
3. **Service load balancing** — can Kanea program eBPF service LB (frontend VIP +
   backends) and does it work east-west *and* from the host (the `kanea-edge` path)?
4. **Network policy** — can per-project default-deny isolation be imposed and
   enforced, and what happens when a bad policy is submitted?
5. **Hubble metrics** — Prometheus flow/drop/DNS metrics without a k8s ConfigMap?

Answers, versions and the go/no-go: **[`REPORT.md`](./REPORT.md)**.

## How to run (on the `kanea-spike` OrbStack VM, Ubuntu 24.04 arm64)

Requires spike ②'s VM (containerd 2.3.3, runc, CNI plugins).

```sh
# one-time, inside the VM: etcd 3.7.1 + cilium-agent 1.19.6 (privileged
# host-network containerd task) + cilium-cni extracted from the image
orb -m kanea-spike bash /Users/michael/Projects/kanea/spikes/cilium-standalone/provision-vm.sh

# on macOS: cross-build (no Go toolchain in the VM; /Users is shared into it)
cd spikes/cilium-standalone
GOOS=linux GOARCH=arm64 go build -o spike-linux .

# in the VM (root needed for containerd, CNI, netns)
cd /Users/michael/Projects/kanea/spikes/cilium-standalone
sudo ./spike-linux all        # net + lb + policy + hubble (25 checks)
sudo ./spike-linux net        # attach/labels/identity/connectivity only
sudo ./spike-linux lb         # + service load balancing
sudo ./spike-linux policy     # + project isolation
sudo ./spike-linux hubble     # + metrics and L7 DNS
sudo ./spike-linux hazard     # DESTRUCTIVE: kills the agent with a bad policy file
sudo ./spike-linux up         # leave four allocs running for poking around
sudo ./spike-linux clean      # remove containers, endpoints, netns, LB/policy state
```

## What the code is

| File | Role |
|---|---|
| `provision-vm.sh` | etcd + cilium-agent + cilium-cni + conflist + host mounts |
| `main.go` | subcommands, shared env, PASS/FAIL bookkeeping |
| `cilium.go` | agent REST client over the unix socket — **hand-rolled on purpose** (see REPORT §"No Go client") |
| `cni.go` | CNI ADD/DEL through the deployed `05-cilium.conflist` |
| `alloc.go` | netns → CNI → labels → identity → containerd task |
| `net.go` / `lb.go` / `policy.go` / `hubble.go` | the four check phases |
| `hazard.go` | blast radius of an invalid policy file |
| `clean.go` | idempotent reset |
