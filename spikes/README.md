# M0 Spikes

Throwaway validation code for milestone **M0** (PRD §20). Nothing in here ships.

## Rules

- Each spike lives in its own subdirectory and produces a **written go/no-go report** (`REPORT.md` in the spike dir) before M1 starts.
- Spike code is **not** part of the main Go module (own `go.mod` per spike) and carries no quality gates — but also **no secrets, ever** (gitleaks still scans it).
- After the report is accepted, the spike is frozen as reference material, not evolved.

## Spikes (PRD §20, M0)

| # | Topic | Question to answer | Verdict |
|---|---|---|---|
| 1 | [Standalone Cilium](./cilium-standalone/REPORT.md) | CNI ADD from containerd, endpoint labels, service LB, network policy, Hubble metrics — all without k8s? | **GO** (25/25) — labels via agent API, LB/policy via file interfaces (the REST writes were removed in Cilium 1.18) |
| 2 | [containerd lifecycle](./containerd-lifecycle/REPORT.md) | Task lifecycle + CNI + single `/v1/metrics` scrape for all cgroup metrics? | **GO** (39/39) |
| 3 | [S3 FUSE mounts](./s3-fuse/REPORT.md) | s3fs vs goofys vs rclone — performance, reliability, unprivileged operation? | **GO** (45/48 + 9/9) — mountpoint-s3 default, s3fs read-write, goofys dropped, rclone rejected |
| 4 | [Image build task](./kaniko-build/REPORT.md) | Rootless kaniko executor as a containerd task: build, cache, push? | **GO** (26/27) — buildah default, kaniko archived → frozen fallback, BuildKit rejected |

All four reports drove PRD amendments (v1.5–v1.7). M1 is next.
