<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./logo/kanea-mark-dark.svg">
  <img src="./logo/kanea-mark-light.svg" alt="Kanea" width="72" height="72">
</picture>

# Kanea

[![CI](https://github.com/m18h/kanea/actions/workflows/ci.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/ci.yml)
[![Release](https://github.com/m18h/kanea/actions/workflows/release.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/m18h/kanea?label=release)](https://github.com/m18h/kanea/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8)](./go.mod)

**Container orchestration in one binary.**

Kanea is a lightweight container orchestration platform written in Go. Services run
on **containerd**, networking and load balancing are **Kanea's own eBPF datapath**, TLS comes from **Let's Encrypt, a per-node CA, or
certificates you already have**, and it ships a
real-time **shadcn/ui dashboard**, an **MCP server** for AI agents, **GitOps
pipelines** (rootless BuildKit), **eBPF-driven autoscaling**, and **encrypted
S3-backed state replication** with backup and restore.

**[Website](https://m18h.github.io/kanea/)** · [PRD](./PRD.md) · [Threat model](./docs/THREAT_MODEL.md) · [DR runbook](./docs/DR_RUNBOOK.md)

## Install

```bash
curl -fsSL https://m18h.github.io/kanea/install.sh | sudo bash
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
VERSION=v0.8.1; ARCH=amd64
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
#    write the units, start kanead, and create your admin account — init
#    asks for a dashboard address (loopback by default) and a username,
#    then prints where everything is. The master key is shown once — have
#    somewhere to record it before you start.
sudo kanea init

# 2. Deploy something.
kanea run --image nginx:1.27-alpine --name web --project demo
kanea ui
```

The CLI talks to `kanead` over a root-owned socket. To use it without sudo, join
the `kanea` group init created and log in again — membership is root-equivalent,
exactly like docker's group:

```bash
sudo usermod -aG kanea $USER
```

Init ends with the node summary: the dashboard URL, your admin account, the
internal DNS address and the subnet layout. `--listen 0.0.0.0:8600` with
`--listen-cert`/`--listen-key` serves the dashboard beyond loopback (TLS is
required there, refused up front otherwise); `--admin-user` and a piped
password make it scriptable; `--no-start` writes the files and stops, which is
the pre-v0.5 behaviour.

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

### Granting what specs may use

Host directories and device/GPU passthrough are off until the node's owner says
otherwise — a spec *names* what it wants, and the node decides what is allowed.
Both grants live in one file, `/etc/kanea/kanea.hcl`, read once at daemon start
(`kanea init` already created the directory; no unit editing, and re-running
init never touches it):

```hcl
# /etc/kanea/kanea.hcl — the node's, never the repository's
storage {
  allowed_host_paths = ["/srv/kanea", "/dev/shm"]  # parents `host` volumes may use
}

device "gpu" {
  nodes = ["/dev/dri/card0", "/dev/dri/renderD128"]
  allow = ["media"]                                # projects that may claim it
}
```

```bash
sudo systemctl restart kanead                      # read once, at startup
```

Keep it root-owned and `0644` — kanead refuses a policy file anyone else could
have written. A spec then mounts with `storage "x" { type = "host" path = … }`
and claims the GPU with `device "dri" { grant = "gpu" }`; a grant the node does
not hold fails the alloc rather than starting without it.

### Functions

A wasm module can run as a service — a **function** (PRD §6.2 R25): always-on,
serving [wasi-http](https://github.com/WebAssembly/wasi-http), on the wasmtime
shim `kanea init` installs beside the rest of the runtime. It deploys, rolls
and scales like any service; what makes it a function is its triggers:

```hcl
function "resize-avatar" {
  project = "shop"
  module  = "registry.example.com/shop/resize-avatar:v3"  # FROM scratch + module

  trigger "http" {}                                # its FQDN — or, with no base
                                                   # domain, the edge's functions
                                                   # port: /<project>/<function>/
  trigger "event" { on = ["deploy.failed"] }       # POSTed matching events
  trigger "cron"  { schedule = "0 3 * * *" }       # five fields, UTC

  resources { memory = 64 }                        # a real cgroup cap
}
```

No volumes, devices, sockets, capabilities or `user` block — the sandbox
cannot honour them, so the spec cannot declare them. `kanea functions list`
and the dashboard's Functions page show triggers, invocation rate (from the
datapath's own counters, so service-to-function calls count too) and status.

**Authenticating requests.** An `expose` block — or a function's `trigger
"http"` — can require a credential, and the invoker can sign what it sends:

```hcl
expose {
  domains = ["api.example.com"]
  auth {
    jwt {
      algorithm      = "RS256"
      public_key_ref = "secret:shop/jwt-pub"    # a reference, never a key
      issuer         = "https://accounts.example.com"
      audience       = "shop-api"
    }
  }
}
```

`auth` takes `basic_ref` (bcrypt htpasswd), `bearer_ref` (tokens), or a `jwt`
block (HS256/RS256/ES256). Every field is a `secret:` reference — the edge is
handed hashes and public keys, never the tokens or passwords, and it fetches
no JWKS: keys are static and the algorithm is configured, not read from the
token. A `function` may also name a `signing_ref`, and every event/cron POST
then carries an HMAC (`X-Kanea-Signature`) the function verifies, exactly as
it would a Kanea webhook — so a function can trust that an invocation really
came from Kanea.

### Signing in with your directory

Local accounts (`kanea user add`) and OIDC have been there since M5; LDAP joins
them. Point `kanead` at the directory and map groups to roles — deny-by-default,
so a bind that maps to no group is refused:

```bash
sudo kanead … \
  --ldap-url ldaps://dc1.corp.example.com \
  --ldap-bind-dn "cn=kanea,ou=svc,dc=corp,dc=example,dc=com" \
  --ldap-bind-password secret:shared/ldap-bind \
  --ldap-user-base-dn "ou=people,dc=corp,dc=example,dc=com" \
  --ldap-user-filter "(sAMAccountName=%s)" \
  --ldap-admin-groups "cn=platform-admins,ou=groups,dc=corp,dc=example,dc=com" \
  --ldap-viewer-groups "cn=developers,ou=groups,dc=corp,dc=example,dc=com"
```

The same login form serves it. TLS is mandatory (`ldaps://`, or `ldap://` gets
StartTLS forced — there is no insecure flag), a local account with the same name
always wins, and the rate limiter runs before any bind, so Kanea cannot be used
to brute-force the directory. Directory identities are ephemeral: no account
record, just a session.

### Settings, from the dashboard

The dashboard's **Settings** page shows the node's configuration and lets an
admin change what changes at runtime: the **backup destination** (directory or
S3 — a new destination is probed with a test write before anything commits, so
a typo cannot silently stop working replication) and **notification channels**
(node-wide defaults plus per-project overrides, each with a test button).
Accounts, API tokens and the audit log live there too. What stays read-only is
what belongs to the unit — listen address, subnets, DNS, the published-port
policy — shown with a note saying so.

If your LAN already uses `10.244.0.0/16`, move Kanea's:

```bash
sudo kanea init --node-cidr 10.90.0.0/24 --cluster-cidr 10.90.0.0/16
```

Internal IPv6 is opt-in dual-stack: pass all three `*6` flags (they come as a
trio, ULA addressing recommended) and every alloc gets a v6 address beside its
v4, every service VIP gets a v6 twin, and the internal DNS answers AAAA:

```bash
sudo kanea init --node-cidr6 fd10:244::/64 --cluster-cidr6 fd10:244::/56 \
  --service-cidr6 fd10:245::/64
```

It is internal only — allocs get no v6 default route, so external IPv6 fails
fast and clients fall back to v4. A gRPC service is exposed by marking its
`expose` block with `protocol = "grpc"`; the edge then speaks HTTP/2 to it
end-to-end (TLS on :443 in front, h2c behind). WebSockets need nothing at all.

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

That is the whole list. containerd, `runc`, rootless `buildkitd` and the
wasmtime shim are installed by `kanea init` at pinned versions — Kanea
supplies them, not you.
Already have a containerd you want to keep using? `kanea init --containerd
external` adopts it instead.

## Status

**M0–M10 complete.** The milestone table, what shipped in each, and the decisions a
change is most likely to trip over live in [`AGENTS.md`](./AGENTS.md) — one table,
one place to update.

## Documentation

| File | Content |
|---|---|
| [`PRD.md`](./PRD.md) | Product Requirements Document — the **north star** (v1.53) |
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
The PR template enforces them; [`CONTRIBUTING.md`](./CONTRIBUTING.md) has the
full walk-through.

## License

[Apache-2.0](./LICENSE) © 2026 Michael K. Essandoh
