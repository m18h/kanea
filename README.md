<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./logo/kanea-mark-dark.svg">
  <img src="./logo/kanea-mark-light.svg" alt="Kanea" width="72" height="72">
</picture>

# Kanea

[![CI](https://github.com/m18h/kanea/actions/workflows/ci.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/ci.yml)
[![Release](https://github.com/m18h/kanea/actions/workflows/release.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8)](./go.mod)

**Container orchestration in one binary.**

Kanea is a lightweight container orchestration platform written in Go. Services run
on **containerd**, networking and load balancing are **Kanea's own eBPF datapath**, TLS comes from **Let's Encrypt, a per-node CA, or
certificates you already have**, and it ships a
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
when `cosign` is on `PATH`. It generates no keys and starts nothing.

`kanea init` then installs the runtime — containerd, `runc` and rootless
`buildkitd` — at versions pinned by SHA-256 in the binary (PRD §5.2.12). The
network layer needs no component: the eBPF datapath is compiled into `kanea`
itself (§5.2.5). It installs under its own prefix on its own socket, so a node that
ran Docker yesterday runs it tomorrow.

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
# 1. Check the node, install the runtime, run the master-key ceremony,
#    write the systemd units. The key is shown once — have somewhere to
#    record it before you start.
sudo kanea init

# 2. Start the control plane and make yourself an admin.
sudo systemctl daemon-reload
sudo systemctl enable --now kanead
kanea user add <name> --role admin

# 3. Deploy something.
kanea run --image nginx:1.27-alpine --name web --project demo
kanea ui
```

### On a home network

No public name, no port 80 reachable from the internet, and still real HTTPS. Point
a wildcard DNS record at the node, run the control plane with a local CA, and
install that CA once on each device:

```bash
sudo kanead --base-domain home.lan --tls-default self-signed
kanea ca show > kanea-ca.crt      # install on your phone, laptop, TV
```

Every service then answers at `<service>.<project>.home.lan` over HTTPS, with no
CA to reach and no rate limit to spend. `--tls-default` also takes `acme`,
`provided` (certificates you put on the node, granted per project through
`--tls-certs-config`) and `plaintext` — and a spec can override the node with
`expose { tls { mode = "…" } }`. A mode names a source, never a path.

Prefer a port to a name? Publish one, with or without a domain:

```hcl
network {
  port "http" { container = 8096 }

  publish "http" {
    host = 8096                                    # http://<node>:8096
    ip_restriction { allow = ["192.168.0.0/16"] }
  }
}
```

`mode = "tcp"` relays bytes instead, for Postgres, a game server, or anything
else that is not HTTP. Which ports a spec may claim is the node's decision
(`--publish-ports`, unprivileged by default), because a repository anyone can
push to must not be able to take :22.

If your LAN already uses `10.244.0.0/16`, move Kanea's:

```bash
sudo kanea init --node-cidr 10.90.0.0/24 --cluster-cidr 10.90.0.0/16
```

`kanea doctor` verifies the node at any time — components, versions against the
pinned matrix, bpffs, disk and clock. `kanea install --list` prints what is
pinned; `--dry-run` downloads and verifies every artefact without writing.

### Air-gapped nodes

A node with no egress is a supported installation, not a workaround. Build a
bundle where there is a network, carry it across, install from it — the same
hashes govern both paths:

```bash
kanea bundle create --arch amd64 -o kanea-bundle.tar.gz   # connected machine
sudo kanea init --bundle kanea-bundle.tar.gz              # air-gapped node
```

The bundle carries no hashes of its own. Its contents are verified against the
ones compiled into the installing node's binary — a bundle that supplied its own
would be a bundle that authenticates itself. Releases publish one per
architecture, covered by the same signed `checksums.txt`.

This covers Kanea's own components; your workload images still come from a
registry the node can reach.

## Requirements

| | |
|---|---|
| Platform | `linux/amd64`, `linux/arm64` |
| Kernel | ≥ 5.10, cgroups v2 unified hierarchy |
| Init system | systemd |
| Clock | NTP-synchronised |

That is the whole list. containerd, `runc` and rootless `buildkitd` are
installed by `kanea init` at pinned versions — Kanea supplies them, not you.
Already have a containerd you want to keep using? `kanea init --containerd
external` adopts it instead.

## Status

**M0–M10 complete.** The milestone table, what shipped in each, and the decisions a
change is most likely to trip over live in [`AGENTS.md`](./AGENTS.md) — one table,
one place to update.

## Documentation

| File | Content |
|---|---|
| [`PRD.md`](./PRD.md) | Product Requirements Document — the **north star** (v1.33) |
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
