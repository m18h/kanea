<div align="center">

<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./logo/kanea-mark-dark.svg">
    <img src="./logo/kanea-mark-light.svg" alt="" width="42" height="42" align="top">
  </picture>
  &nbsp;Kanea
</h1>

<p align="center"><strong>Container orchestration in one binary.</strong></p>

<img src="./site/assets/shot-dashboard.webp" alt="The Kanea dashboard: counts for services, allocations, builds and events; sparklines for CPU, memory, load and running allocations; and panels for recent events, autoscaler decisions and backup replication" width="900">

Kanea is a lightweight container orchestration platform written in Go. Services run on **containerd**, networking and load balancing are **Kanea's own eBPF datapath**, TLS comes from **Let's Encrypt, a per-node CA, or certificates you already have**, and it ships a real-time **shadcn/ui dashboard**, an **MCP server** for AI agents, **GitOps pipelines** (rootless BuildKit), **eBPF-driven autoscaling**, and **encrypted S3-backed state replication** with backup and restore.

[![CI](https://github.com/m18h/kanea/actions/workflows/ci.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/ci.yml) [![Release](https://github.com/m18h/kanea/actions/workflows/release.yml/badge.svg)](https://github.com/m18h/kanea/actions/workflows/release.yml) [![Latest release](https://img.shields.io/github/v/release/m18h/kanea?label=release)](https://github.com/m18h/kanea/releases/latest) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE) [![Go](https://img.shields.io/badge/go-1.26-00ADD8)](./go.mod)

**[Website](https://m18h.github.io/kanea/)** · [PRD](./PRD.md) · [Threat model](./docs/THREAT_MODEL.md) · [DR runbook](./docs/DR_RUNBOOK.md)

</div>

## Install

```bash
curl -fsSL https://m18h.github.io/kanea/install.sh | sudo bash
```

The installer fetches the binary, verifies it, and stops. Checksum verification is
mandatory and there is no flag to skip it; the Sigstore signature is verified too
when `cosign` is on `PATH`. It generates no keys and starts nothing.

`kanea init` then installs the runtime (containerd, `runc` and rootless
`buildkitd`) at versions pinned by SHA-256 in the binary (PRD §5.2.12). The
network layer needs no component: the eBPF datapath is compiled into `kanea`
itself (§5.2.5). It installs under its own prefix on its own socket, so a node that
ran Docker yesterday runs it tomorrow.

Prefer to do it by hand? Every release publishes
`kanea_<version>_linux_<arch>.tar.gz`, an **SPDX SBOM** beside each archive
(plus `kanea_<version>_source.spdx.json` for the build's own graph, which is
where the embedded dashboard's npm dependencies are listed), `checksums.txt`,
and a **keyless cosign** signature over the checksums. The SBOMs are listed in
the checksums, so that one signature covers them too:

```bash
VERSION=v0.23.2; ARCH=amd64
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

### Homebrew (CLI)

```bash
brew tap m18h/kanea
brew trust m18h/kanea   # brew ≥ 6 refuses formulae from untrusted third-party taps
brew install kanea
```

Homebrew ships the CLI, not the node (PRD §5.2.12): on macOS you get the
authoring half, where `kanea plan` validates job specs with file-and-line
diagnostics and needs no daemon, while the platform itself runs on Linux. On a
Linux machine the formula installs the same full binary, but a *node* belongs
to the script above: root-owned at `/usr/local/bin`, where `kanea upgrade`
owns the swap. A brew-owned binary upgrades with `brew upgrade kanea`, then
`sudo kanea upgrade --no-fetch` for the restart-and-migrate half. The formula
lives in its own tap repository, [m18h/homebrew-kanea](https://github.com/m18h/homebrew-kanea),
and is regenerated from each release's `checksums.txt` by a workflow there;
the macOS install works from the first release that ships darwin archives.

## Quickstart

```bash
# 1. Check the node, install the runtime, run the master-key ceremony,
#    write the units, start kanead, and create your admin account. Init
#    asks for a dashboard address (loopback by default) and a username,
#    then prints where everything is. The master key is shown once, so
#    have somewhere to record it before you start.
sudo kanea init

# 2. Deploy something.
kanea run --image nginx:1.27-alpine --name web --project demo
kanea ui
```

The CLI talks to `kanead` over a root-owned socket. To use it without sudo, join
the `kanea` group init created and log in again. Membership is root-equivalent,
exactly like docker's group:

```bash
sudo usermod -aG kanea $USER
```

Init ends with the node summary: the dashboard URL, your admin account, the
internal DNS address and the subnet layout. TLS is required beyond loopback,
and init provisions it by default: a public listen address — answered at the
prompt or passed as a bare `--listen` — mints a 10-year self-signed pair at
`/etc/kanea/api.crt` and serves the API and dashboard with it. Bring your own
with `--listen-cert`/`--listen-key`, or override the default at any time via
the server config below. `--admin-user` and a piped
password make it scriptable; `--no-start` writes the files and stops, which is
the pre-v0.5 behaviour.

The listener can live in the server config instead of the unit (PRD §15.1),
with its TLS in the same vocabulary services use:

```hcl
# /etc/kanea/kanea.hcl
bind {
  api_addr   = "192.168.1.10:8600"
  api_tls    = "self-signed"       # or: acme (with api_domain), provided, plaintext
  # api_domain = "kanea.home.example"  # acme needs it; names a self-signed cert
  # api_cert   = "/etc/kanea/api.pem"  # provided only, always with api_key
  # api_key    = "/etc/kanea/api.key"
}
```

`self-signed` issues the listener's certificate from the node's own CA (the
one `kanea ca show` installs on your devices) with a real IP SAN, renewed
automatically; `acme` gets a Let's Encrypt certificate for `api_domain`
through the same account and renewal loop your services use; `provided` is
your own `api_cert`/`api_key` pair; `plaintext` is explicit HTTP, allowed
beyond loopback because you typed it and logged loudly. Init then skips the
listen question and renders no listen flags. Moving the API and dashboard later
is an edit to the file plus `systemctl restart kanead`, never a re-init. An
explicit `--listen` always wins, and `--listen none` keeps the node
socket-only regardless.

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
`--tls-certs-config`) and `plaintext`. A spec can override the node with
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
otherwise: a spec *names* what it wants, and the node decides what is allowed.
Both grants live in one file, `/etc/kanea/kanea.hcl`, read once at daemon start
(`kanea init` already created the directory; no unit editing, and re-running
init never touches it):

```hcl
# /etc/kanea/kanea.hcl: the node's, never the repository's
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

Keep it root-owned and `0644`, because kanead refuses a policy file anyone else
could have written. A spec then mounts with `storage "x" { type = "host" path = … }`
and claims the GPU with `device "dri" { grant = "gpu" }`; a grant the node does
not hold fails the alloc rather than starting without it.

A host path must already exist, so a typo cannot become a silently empty volume.
Add `create = true` to the storage block when you would rather Kanea made it,
still only inside a prefix you allowed above.

### Volumes

`kanea volume list` shows every storage resource with the mounts using it, their
measured usage and mount state. A `volume` block may declare `size = "10GiB"`,
which is a **budget rather than a quota**: Kanea measures the volume against it
and emits `volume.over_budget` (and `volume.under_budget` when it recovers), but
nothing enforces it: no quota mechanism exists on the node, and `nfs`, `smb`
and `s3` could not carry one anyway. Mounts notify too: `volume.mount_failed`
when one will not establish or stops answering, `volume.mount_recovered` when
the supervisor gets it back.

### Shared variables

Declare a value once and reference it anywhere in a spec as `${name}`, or as a
bare identifier where HCL takes an expression:

```hcl
variables {
  domain   = "shop.example.com"
  replicas = 3
}

service "web" {
  project = "shop"
  count   = replicas
  expose { domains = ["${domain}", "www.${domain}"] }
}
```

The same `kanea.hcl` above may carry a `variables` stanza of node-wide defaults
(a LAN domain, a registry host); the spec's own block wins on a collision, and
pipeline-supplied values like `${GIT_SHA_SHORT}` sit above both. Variables are
never secrets. The node's stanza is readable by any signed-in caller over
`GET /v1/vars`, so credentials stay `secret:` references.

It may also carry a `dns` stanza pinning the resolvers the internal DNS
forwards external names to (`dns { upstreams = ["1.1.1.1"] }`), for a node
whose `/etc/resolv.conf` is DHCP's to rewrite. An explicit `--dns-upstream`
flag wins; with neither, the daemon uses the host's own resolvers, exactly as
listed — including systemd-resolved's `127.0.0.53` stub, which is what a
stock Debian or Ubuntu server has and which `kanead` reaches from the host
like any other process, so no stanza is needed to boot such a node.

### Functions

A wasm module can run as a service, a **function** (PRD §6.2 R25): always-on,
serving [wasi-http](https://github.com/WebAssembly/wasi-http), on the wasmtime
shim `kanea init` installs beside the rest of the runtime. It deploys, rolls
and scales like any service; what makes it a function is its triggers:

```hcl
function "resize-avatar" {
  project = "shop"
  module  = "registry.example.com/shop/resize-avatar:v3"  # FROM scratch + module

  trigger "http" {}                                # its FQDN, or with no base
                                                   # domain, the edge's functions
                                                   # port: /<project>/<function>/
  trigger "event" { on = ["deploy.failed"] }       # POSTed matching events
  trigger "cron"  { schedule = "0 3 * * *" }       # five fields, UTC

  resources { memory = 64 }                        # a real cgroup cap
}
```

No volumes, devices, sockets, capabilities or `user` block: the sandbox
cannot honour them, so the spec cannot declare them. `kanea functions list`
and the dashboard's Functions page show triggers, invocation rate (from the
datapath's own counters, so service-to-function calls count too) and status.

**Authenticating requests.** An `expose` block, or a function's `trigger
"http"`, can require a credential, and the invoker can sign what it sends:

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
block (HS256/RS256/ES256). Every field is a `secret:` reference. The edge is
handed hashes and public keys, never the tokens or passwords, and it fetches
no JWKS: keys are static and the algorithm is configured, not read from the
token. A `function` may also name a `signing_ref`, and every event/cron POST
then carries an HMAC (`X-Kanea-Signature`) the function verifies, exactly as
it would a Kanea webhook, so a function can trust that an invocation really
came from Kanea.

### Signing in with your directory

Local accounts (`kanea user add`) and OIDC have been there from the start; LDAP
joins them. Point `kanead` at the directory and map groups to roles. It is deny-by-default,
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
StartTLS forced; there is no insecure flag), a local account with the same name
always wins, and the rate limiter runs before any bind, so Kanea cannot be used
to brute-force the directory. Directory identities are ephemeral: no account
record, just a session.

### The dashboard

A service page charts CPU, memory, request rate and p95 on a real time axis,
streams logs live (filterable, with copy, download and a full-screen view), and
shows every restart or deploy as **rollout progress**, which is the planner's
own spec-hash rule on the wire. It also opens a **shell into any running alloc**
from the browser, over the same exec websocket the CLI uses.

Every chart **arrives with its history already in it**: the recent window rides
the first frame of the same subscription that carries the live samples, so a
page draws its shape immediately instead of growing one point per scrape, and
the series survive navigating away and back. The per-alloc sparklines in the
allocs table are seeded the same way. When a chart genuinely has nothing, it
says **`no samples yet`** rather than "no data", which is also the honest
answer for the ten seconds after a `kanead` restart: every rate is a delta
between two readings, so none can exist until the second one lands.

The **Projects** page lists each namespace with its services, how many allocs
are actually running, where its spec comes from and when it last synced, with
a **Sync now** button for a git-backed project. That button does what the poll
loop does rather than deploying from the click. There is no "new project" button on
purpose: a project is the namespace a service declares itself into, so
deploying a service into a new name is how one comes to exist.

The **Storage** page shows every storage resource with the volumes mounted
against it: driver, target, host path, and measured usage against the `size`
budget a volume declared. A budget is measured, never enforced: nothing stops
a volume growing past it, and the number is the reason to go and look. Usage
that has not been measured shows a dash rather than a zero, which for an `s3`
volume is permanent: walking one costs a LIST per directory, so Kanea does not.

The **Settings** page shows the node's configuration and lets an
admin change what changes at runtime: the **backup destination** (directory or
S3, and a new destination is probed with a test write before anything commits,
so a typo cannot silently stop working replication) and **notification channels**
(node-wide defaults plus per-project overrides, each with a test button).
Accounts, API tokens and the audit log live there too, one tab each. What
stays read-only is what belongs to the unit: listen address, subnets, DNS and
the published-port policy, each shown with a note saying so.

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

It is internal only: allocs get no v6 default route, so external IPv6 fails
fast and clients fall back to v4. A gRPC service is exposed by marking its
`expose` block with `protocol = "grpc"`; the edge then speaks HTTP/2 to it
end-to-end (TLS on :443 in front, h2c behind). WebSockets need nothing at all.

`kanea doctor` verifies the node at any time: components, versions against the
pinned matrix, bpffs, disk and clock. `kanea install --list` prints what is
pinned; `--dry-run` downloads and verifies every artefact without writing.

### Air-gapped nodes

A node with no egress is a supported installation, not a workaround. Build a
bundle where there is a network, carry it across, install from it. The same
hashes govern both paths:

```bash
kanea bundle create --arch amd64 -o kanea-bundle.tar.gz   # connected machine
sudo kanea init --bundle kanea-bundle.tar.gz              # air-gapped node
```

The bundle carries no hashes of its own. Its contents are verified against the
ones compiled into the installing node's binary. A bundle that supplied its own
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
wasmtime shim are installed by `kanea init` at pinned versions. Kanea
supplies them, not you.
Already have a containerd you want to keep using? `kanea init --containerd
external` adopts it instead.

## Status

**Everything on this page is built and released.** Services and volumes,
ingress with TLS, the dashboard, accounts and directory sign-in, autoscaling,
GitOps pipelines, notifications, the MCP server, backup and restore, the
host-component installer, and wasm functions.

What is still owed before v1.0 is evidence rather than code: the runs no test
can stand in for, on a real node. `init` to a first HTTPS service inside the
five-minute budget, functions end to end, the 5.10 kernel floor, and S3 against
providers other than MinIO. Those are tracked, with dates, in
[`docs/VALIDATION.md`](./docs/VALIDATION.md).

The decisions a change is most likely to trip over live in
[`AGENTS.md`](./AGENTS.md), in one place to update.

## Documentation

| File | Content |
|---|---|
| [`PRD.md`](./PRD.md) | Product Requirements Document, the **north star** (v1.81) |
| [`AGENTS.md`](./AGENTS.md) | Conventions and binding constraints for contributors (human & AI) |
| [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) | Boundaries, adversaries, OWASP Top 10 as built |
| [`docs/DR_RUNBOOK.md`](./docs/DR_RUNBOOK.md) | Disaster recovery: read it before you need it |
| [`docs/VALIDATION.md`](./docs/VALIDATION.md) | What has been exercised on real hardware, with dates |
| [`SECURITY.md`](./SECURITY.md) | How to report a vulnerability |

## Development

```bash
make help       # list targets
make build      # build ./bin/kanea
make test       # tests with -race
make check      # all gates (vet, test, lint, security, dashboard), CI parity
make tools      # install dev tools (golangci-lint, gosec, govulncheck)
```

Requires Go (version in `go.mod`) and Node (`.nvmrc`) for the dashboard. `make
check` is what CI runs and what the release workflow runs before it builds
anything. A failure there is a failed release later, not a failed lint.

Contributions follow conventional commits, one logical change per PR, and the
binding constraints in [`AGENTS.md`](./AGENTS.md#binding-constraints-never-violate-these).
The PR template enforces them; [`CONTRIBUTING.md`](./CONTRIBUTING.md) has the
full walk-through.

## License

[Apache-2.0](./LICENSE) © 2026 Michael K. Essandoh
