# Spike ⑧: user namespaces for workload allocs

**The question:** can a Kanea-shaped alloc run in a user namespace - container
uid 0 an unprivileged host uid - on Kanea's pinned containerd, with the
pre-created netns, the full hardening opt set, a rootfs whose ownership is
correct, and the host-side ownership arithmetic (the R24 volume chown, the
secrets tmpfs) shifted by the map? And what breaks: the PUID image class, and
host grants that cannot be honoured under a map (the R21 refusal the feature
would carry).

Gates the userns feature PRD §19.3 parks, the way spike ⑤ gates the datapath
and the wasm spike gates M11. Throwaway code: own `go.mod`, never imported by
the platform; the hardening opts and seccomp resolution are **copied** from
`internal/runtime/spec.go` / `seccomp.go` so a rejection names the opt the
shipping code would have to branch on.

## Prerequisites

- A Linux node running Kanea's containerd (any 2.x), run as root.
- Outbound registry access for two images: `alpine:3.20` (the probe) and
  `lscr.io/linuxserver/nginx` (the PUID/s6 check; `-puid-image ""` skips it).
- The spike uses its own containerd namespace (`kanea-spike-userns`), its own
  netns names (`spike-userns-*`) and `/tmp/kanea-spike-userns/`; it touches
  nothing of a running kanead's.

## Run

```bash
GOOS=linux go build -o spike-linux .
scp spike-linux <node>:
ssh <node> sudo ./spike-linux -socket /run/kanea/containerd.sock
ssh <node> sudo ./spike-linux clean     # removes everything the spike made
```

Copy the output into [REPORT.md](./REPORT.md). Do not fabricate results.

## The checks

| # | Check |
|---|---|
| A | Which rootfs strategy the node supports: does the overlay snapshotter advertise `remap-ids` (idmapped mounts, kernel ≥ 5.19), or is the recursive-chown copy the fallback? |
| B | Create + start under the full Kanea opt set (caps, NNP, seccomp, masked paths, namespaces, resources) **plus** the userns and its map; snapshot-prep cost recorded |
| C | The map is real both ways: host `/proc/<pid>/status` shows the base uid, `id -u` inside shows 0, a file written inside lands host-owned at the base |
| D | The task joins a kanead-style pre-created netns and **cannot modify it** (foreign-owned; the hardening bonus) |
| E | The port floor: the netns belongs to init, so the container's in-namespace `CAP_NET_BIND_SERVICE` cannot bind :80 - and v1.105's `ip_unprivileged_port_start=0` restores it. The sysctl is load-bearing for userns |
| F | The R24 arithmetic: a host dir chowned base+999 is writable by container uid 999; one chowned plain 999 is not. Every host-side chown must shift; host volumes (R15) stay incompatible |
| G | The secrets shape: a 0400 file owned base+999, bind-mounted read-only, readable by uid 999 and nobody else |
| H | A PUID/s6 image (linuxserver) boots under the compatible baseline inside the userns - the v1.56 crash-loop question with mapped ids |
| I | A root-owned host socket bind-mounted in stats as the overflow uid and is unusable: the evidence for refusing grants under a map (R21) |
| J | Exec works, in the driver's copy-the-process-spec shape (it is also how F/G impersonate the workload's uid) |
