# Security Policy

Kanea installs a daemon that runs as root, holds every secret on the node, and can
open a shell in any container on it. Vulnerability reports are taken seriously and
are welcome.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub Security Advisories:

👉 [Report a vulnerability](https://github.com/m18h/kanea/security/advisories/new)

If that is not available to you, email <michael@essandoh.dev>.

Please include what you need to make the finding actionable: affected version
(`kanea version`), the component (`kanead`, `kanea-edge`, the API, the dashboard,
the MCP server, the installer), reproduction steps, and what an attacker gains.

You should get an acknowledgement within **5 days** and an assessment within
**14 days**. Please give a fix a reasonable window before disclosing publicly;
if a report is valid and you would like credit in the advisory, say so.

## Supported versions

The **latest release** is supported. Kanea is pre-1.0 and there are no backported
security releases: fixes ship in the next tag.

## Scope

In scope — anything that crosses a boundary the platform claims to hold:

- Authentication or authorisation bypass on any API, websocket or MCP route
  (every one of them is deny-by-default; a route that is not is a bug).
- Anything that reveals a secret value — over the API, the MCP server, the
  dashboard, the audit log, or a log line.
- Escaping a workload's isolation: capabilities, seccomp, namespaces, the cgroup
  ceiling, or a volume mount reaching outside its storage.
- Crossing a project boundary — a spec, a synced repository, or a webhook that
  reaches another project's services, secrets or network.
- Breaking the release chain: the installer, the checksums, the Sigstore
  signature, or the archive encryption and its restore path.
- SSRF out of the notification or ACME egress paths.

Out of scope:

- Anything requiring an operator to already hold the master key or a root shell on
  the node — that is the trust the design starts from.
- Findings in containerd, Cilium, BuildKit or the kernel. Report those upstream;
  tell us if Kanea's defaults make them materially worse.
- Automated scanner output with no demonstrated impact.

## What is already written down

[`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) documents the boundaries, the
adversaries considered, and the OWASP Top 10 mapping as built. Reading it first
will tell you which assumptions are load-bearing — and a report that breaks one of
them is exactly the report worth sending.
