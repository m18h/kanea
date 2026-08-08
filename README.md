# Kanea

[![CI](https://github.com/m18h/kanea/actions/workflows/ci.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/ci.yml)
[![Release](https://github.com/m18h/kanea/actions/workflows/release.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8)](./go.mod)

**Container orchestration in one binary.**

Kanea is a lightweight container orchestration platform written in Go. Services run
on **containerd**, networking and load balancing are **standalone Cilium** (eBPF, no
Kubernetes at any layer), TLS is automated with **Let's Encrypt**, and it ships a
real-time **shadcn/ui dashboard**, an **MCP server** for AI agents, **GitOps
pipelines** (rootless BuildKit), **eBPF-driven autoscaling**, and **encrypted
S3-backed state replication** with backup and restore.

📖 **[Website →](https://m18h.github.io/kanea/)** · [PRD](./PRD.md) · [Threat model](./docs/THREAT_MODEL.md) · [DR runbook](./docs/DR_RUNBOOK.md)

## Install

```bash
curl -fsSL https://m18h.github.io/kanea/install.sh | bash
```

The installer fetches the binary, verifies it, and stops. Checksum verification is
mandatory and there is no flag to skip it; the Sigstore signature is verified too
when `cosign` is on `PATH`. It deliberately does not install containerd or Cilium,
does not generate keys, and does not start anything.

Prefer to do it by hand? Every release publishes
`kanea_<version>_linux_<arch>.tar.gz`, `checksums.txt`, and a **keyless cosign**
signature over the checksums:

```bash
VERSION=v0.1.0; ARCH=amd64
BASE=https://github.com/m18h/kanea/releases/download/$VERSION

curl -fLO $BASE/kanea_${VERSION#v}_linux_$ARCH.tar.gz
curl -fL -O $BASE/checksums.txt -O $BASE/checksums.txt.sig -O $BASE/checksums.txt.pem

cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp "https://github.com/m18h/kanea/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

sha256sum --ignore-missing -c checksums.txt
tar xzf kanea_${VERSION#v}_linux_$ARCH.tar.gz
sudo install -m 0755 kanea /usr/local/bin/kanea
```

There is no long-lived signing key to guard: the signature is bound by Sigstore to
the release workflow in this repository, and the proof is in a public transparency
log.

## Quickstart

```bash
# 1. Install containerd and cilium-agent (>= 1.18, pin 1.19.x) yourself.
#    Kanea does not choose their versions for you.

# 2. Check the node, run the master-key ceremony, write the systemd units.
#    The key is shown once — have somewhere to record it before you start.
sudo kanea init

# 3. Start the control plane and make yourself an admin.
sudo systemctl daemon-reload
sudo systemctl enable --now kanead
kanea user add <name> --role admin

# 4. Deploy something.
kanea run --image nginx:1.27-alpine --name web --project demo
kanea ui
```

`kanea doctor` verifies the node at any time — dependencies, versions, kvstore,
disk and clock.

## Requirements

| | |
|---|---|
| Platform | `linux/amd64`, `linux/arm64` |
| Kernel | ≥ 5.10, cgroups v2 unified hierarchy |
| containerd | ≥ 1.7 |
| cilium-agent | ≥ 1.18 (pin 1.19.x) |
| Clock | NTP-synchronised |
| Kubernetes | none, at any layer |

## Status

**M0–M10 complete.** The milestone table, what shipped in each, and the decisions a
change is most likely to trip over live in [`AGENTS.md`](./AGENTS.md) — one table,
one place to update.

## Documentation

| File | Content |
|---|---|
| [`PRD.md`](./PRD.md) | Product Requirements Document — the **north star** (v1.29) |
| [`AGENTS.md`](./AGENTS.md) | Conventions and binding constraints for contributors (human & AI) |
| [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) | Boundaries, adversaries, OWASP Top 10 as built |
| [`docs/DR_RUNBOOK.md`](./docs/DR_RUNBOOK.md) | Disaster recovery — read it before you need it |
| [`SECURITY.md`](./SECURITY.md) | How to report a vulnerability |

## Development

```bash
make help       # list targets
make build      # build ./bin/kanea
make test       # tests with -race
make check      # all gates (vet, test, lint, security, dashboard) — CI parity
make tools      # install dev tools (golangci-lint, gosec, govulncheck)
```

Requires Go (version in `go.mod`) and Node (`.nvmrc`) for the dashboard. `make
check` is what CI runs and what the release workflow runs before it builds
anything — a failure there is a failed release later, not a failed lint.

Contributions follow conventional commits, one logical change per PR, and the
binding constraints in [`AGENTS.md`](./AGENTS.md#binding-constraints-never-violate-these).
The PR template enforces them.

## License

[Apache-2.0](./LICENSE) © 2026 Michael K. Essandoh
