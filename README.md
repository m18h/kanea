# Kanea

**Nomad's simplicity, eBPF's power, one binary.** Kanea is a lightweight container orchestration platform written in Go: services run on **containerd**, networking and load balancing are **standalone Cilium** (eBPF, no Kubernetes), TLS is automated with **Let's Encrypt**, and it ships a real-time **shadcn/ui dashboard**, an **MCP server** for AI agents, **GitOps pipelines** (kaniko), **eBPF-driven autoscaling**, and **S3-backed state replication** with backup/restore.

> **Status: pre-implementation.** The platform is fully specified; the next step is M0 (technical spikes). See the roadmap below.

## Documentation

| File | Content |
|---|---|
| [`PRD.md`](./PRD.md) | Product Requirements Document — the **north star** (v1.2) |
| [`AGENTS.md`](./AGENTS.md) | Conventions and binding constraints for contributors (human & AI) |
| [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) | Threat model (milestone M5) |
| [`docs/DR_RUNBOOK.md`](./docs/DR_RUNBOOK.md) | Disaster recovery runbook (milestone M10) |

## Roadmap (PRD §20)

M0 spikes (standalone Cilium, containerd, S3 FUSE, kaniko) → M1 runtime core → M2 networking & storage → M3 ingress/TLS/middleware → M4 dashboard → M5 auth & OWASP → M6 metrics & autoscaling → M7 GitOps & pipelines → M8 notifications → M9 MCP server → M10 hardening & packaging.

## Development

```bash
make help       # list targets
make build      # build ./bin/kanea
make test       # tests with -race
make check      # all gates (vet, test, lint, security, dashboard) — CI parity
make tools      # install dev tools (golangci-lint, gosec, govulncheck)
```

Requires Go (version in `go.mod`) and, for the dashboard (M4+), Node (`.nvmrc`).
