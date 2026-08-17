// Package runtime is the containerd driver: image pull (TLS-only registries,
// digest pinning), task lifecycle, per-alloc netns (CNI call), cgroup metrics
// (single /v1/metrics scrape), stdout/stderr capture with non-blocking drains,
// image/cache GC and disk watermark alerts. Workload hardening defaults are
// applied here (drop caps, no-new-privileges, seccomp: PRD §5.2.4, §14 A05).
package runtime
