# Kanea Threat Model

**Status:** written during M5 (auth & OWASP pass). It describes what is built
as of M5; every control below is code with a test unless it says otherwise, and
anything not yet defended says which milestone defends it.

Baseline: [`PRD.md`](../PRD.md) §14 (OWASP mapping) and
[`AGENTS.md`](../AGENTS.md) binding constraints. When this document and the code
disagree, one of them is wrong — say which in the PR.

---

## 1. What is being defended

Kanea runs other people's code on one machine and gives a small number of people
control over it. Three things follow, and they shape everything below:

- **Workloads are hostile by assumption.** A container is a thing built from a
  Containerfile somebody wrote. It is inside the trust boundary of the node's
  kernel and outside every other one.
- **The control plane is root.** `kanead` talks to containerd and Cilium over
  sockets that are root-equivalent by design. There is no meaningful privilege
  boundary between "compromised kanead" and "compromised node", so the
  boundaries worth defending are the ones *in front of* it.
- **The operators are few and identifiable.** v1 has two roles and no
  delegation. That makes authorization simple enough to enforce in one place,
  which at this scale is worth more than expressiveness.

### Assets, in the order an attacker would want them

| Asset | Where it lives | What losing it means |
|---|---|---|
| Secrets master key | `data_dir/master.key`, 0600 | Every stored secret, and every encrypted backup, becomes readable |
| Stored secrets | `secrets` bucket, XChaCha20-Poly1305 | Database passwords, registry and DNS credentials |
| Session and token material | `kv` bucket, hashed | Impersonation of an operator |
| TLS private keys | `certs` bucket → `/run/kanea-edge/certs.json` 0640 | Traffic interception for the served names |
| Platform state | `state.db` (bbolt) | What runs, where, and with what access |
| Audit trail | `audit` bucket, hash-chained | The ability to say what happened |
| The node itself | containerd + Cilium sockets | Everything above, plus the workloads |

### Trust boundaries

```
 internet
    │                    ← boundary 1: anyone with a network route
 kanea-edge   (own user, CAP_NET_BIND_SERVICE only, no Store handle)
    │                    ← boundary 2: the edge cannot write state
 kanead       (root; API on a 0600 unix socket + an optional TLS listener)
    │                    ← boundary 3: auth middleware, deny-by-default
 Store / containerd / cilium-agent
    │                    ← boundary 4: per-alloc namespaces, all caps dropped
 workload containers
```

Boundary 2 is the one most orchestrators do not have. The edge holds no database
handle and no write access to anything; it serves a projection `kanead`
publishes. An edge compromise costs traffic on the names it terminates — it does
not cost the cluster.

---

## 2. Adversaries

| Adversary | Reaches | Assumed capability |
|---|---|---|
| **Internet scanner** | Edge :80/:443, the API listener if exposed | Automated, high volume, no credentials |
| **Authenticated viewer** | Every read route | Curiosity, and a browser someone else may control |
| **Compromised workload** | The pod network, the node's kernel | Arbitrary code as the container's user |
| **Malicious job spec** | The HCL parser, the scheduler | Whatever the spec language allows |
| **Stolen operator browser** | Session cookie; CSRF token if XSS lands | Anything the role allows |
| **Rogue AI agent (MCP)** | The MCP tool surface — **not built, M9** | A valid token and no judgement |
| **Node-local root** | Everything | Out of scope: see §6 |

---

## 3. What is defended, and how

### 3.1 Getting in (A01, A05, A07)

Every route on the control API passes through one wrapper that authenticates,
authorizes, checks CSRF on cookie mutations and records the outcome
(`internal/api/auth.go`). Exactly two routes are public: health and login. That
is a property of the middleware, not of the deployment — a request presenting no
credential is refused whether or not auth is configured.

A caller is one of three things:

1. **A bearer token** — 256 bits, stored as a SHA-256 hash so a leaked database
   yields nothing usable; revocable server-side, expiry-bound.
2. **A session cookie** — `HttpOnly`, `Secure` by default, `SameSite=Lax`,
   12-hour absolute expiry, revocable server-side. Mutations additionally
   require a double-submit CSRF token, because SameSite is a property of the
   browser rather than of this server.
3. **The local unix socket** — 0600, owned by the daemon's user. Reaching it
   means being someone who can already replace the binary and read the master
   key, so it is admitted as admin and recorded as `socket`, never as a person.

**Loopback is not local.** Only the unix socket confers that identity. Someone
reaching 127.0.0.1 through a forwarded port, an SSH tunnel or a co-tenant
container is not this host's root and gets no credit for the address.

**Rate limits, two tiers** (`internal/ratelimit`): 30/min per source on the
public routes, 600/min on the authenticated ones, keyed separately so an
anonymous flood cannot spend an operator's allowance. The check runs *before*
authentication — login costs ~250 ms of bcrypt by design, and bounding that
after paying for it is not a rate limit. Failed logins are additionally locked
out per account *and* per source: per-source alone lets a botnet spread an
attack, per-account alone lets one address work through every account.

**The listener refuses itself** rather than being unsafe. No account configured
means no network listener; non-loopback without TLS means no listener. Both
refuse the *listener* and not the daemon, because the socket has to keep working
— it is where the first account gets created.

### 3.2 Staying out (A01)

Mutations require the admin role. The one exception is logging out, declared as
an explicit `selfService` opt-out so that a mutating route which says nothing
about roles is admin-only by omission rather than open by omission.

Secrets are **write-only over the API**: there is no read route, and the
interface the API server holds cannot express one. Enforcement by absence, not
by a permission check that could be misconfigured.

The live websocket is authenticated like everything else and additionally checks
`Origin` — allowlist plus same-origin — which is what stops a cross-site socket
hijack riding the session cookie.

### 3.3 Secrets (A02)

Referenced, never inlined (`secret:project/name`), project-scoped at validation
time, encrypted at rest with XChaCha20-Poly1305 under a master key in a 0600
file, injected into workloads through tmpfs files by default. A value never
reaches a log, an API response, or an audit entry: the audit log's redaction
filter runs on every entry rather than at call sites, because a filter each
caller must remember is one that gets forgotten in the path that mattered.

**Losing `master.key` loses every secret and every encrypted backup.** The
escrow ceremony that makes this survivable is M10. Until then it is the sharpest
edge in the system, and the daemon says so on first run.

### 3.4 Accountability (A09)

Every mutation, every auth event, and every refusal that presented a credential
is appended to a hash-chained audit log in the Store. Editing or removing an
entry breaks every entry after it and `Verify` names the first break — which is
what makes a signed export worth anything, since signing the head of a chain
attests to the whole history.

Two deliberate gaps, stated rather than hidden:

- An entry is written *after* the handler runs, because the outcome is half of
  what makes it useful. The window where the action lands and the record does
  not requires the Store to fail between two writes; it is logged at error level
  and counted (`api.AuditFailures`). Closing it properly means writing the entry
  in the same Store batch as the mutation it describes.
- A request presenting **no** credential is refused without a record. An audit
  log an anonymous caller can grow without limit is a disk-exhaustion vector
  wearing a compliance hat.

### 3.5 Workloads (A01, A04)

Every alloc runs with all capabilities dropped, `no-new-privileges`, the default
seccomp profile, private PID and IPC namespaces, and mandatory cpu/memory/pids
limits — no container is ever unlimited, and the v1 spec has no `privileged`
escape hatch. The control plane holds a cgroups v2 `memory.min` floor, so a
workload cannot OOM-kill the reconciler that would otherwise restart it.

Network policy is deny-by-default per project: an unlabelled endpoint is
`reserved:init`, which denies both directions.

### 3.6 The browser (A03, A05)

The dashboard is served with a strict CSP that has no `unsafe-inline` for script
— possible because the SPA is self-contained by construction (`go:embed`, no
CDN). Daemon-supplied strings render through React's escaping. Security headers
are applied to the whole mux rather than per route, so a handler added later
cannot forget them.

### 3.7 Identity providers (A07)

OIDC login checks four things independently, because each catches something the
others do not: **PKCE** (an intercepted authorization code cannot be redeemed),
**state** (a callback matches a login this daemon started), **nonce** (an ID
token minted for a *different* login is refused even though it verifies), and
**claim mapping** (deny-by-default — a provider saying who someone is does not
say what they may do). The post-login return path is bounded to this origin,
rejecting `//host` and `/\host` alike, because an open redirect on a login page
is a phishing hop with this daemon's name on it.

### 3.8 Git push webhooks (A01, A08)

`POST /v1/webhooks/git/{project}` is **the only route authenticated by something
other than §13**, and the exception is structural rather than convenient: a push
notification comes from GitHub or GitLab, not from a person, so no session
cookie and no bearer token can carry it. Calling it public would be wrong — it
is authenticated, just differently.

What guards it:

- **A per-project HMAC.** The signature is verified over the **raw request
  body** before anything is parsed, with a constant-time comparison, against a
  secret named by `git.webhook_secret_ref`. A body that has been through a
  decoder is no longer the bytes that were signed, which is why the handler
  reads bytes and hands bytes over.
- **A separate secret from the deploy key.** `auth_ref` lets Kanea read the
  repository; `webhook_secret_ref` lets the repository tell Kanea something.
  Reusing one for the other would put a credential that can read source into a
  header on every push.
- **An unsigned delivery is refused,** never treated as an anonymous ping.
- **Replays are rejected** by delivery id, within a bounded, time-evicted cache.
  A retry of a delivery already processed answers **200**, not an error, because
  an error makes the provider retry a push that was already handled — forever.
- **The body is bounded** before it is read, because the sender chooses its size.
- **Every refusal is audited** as a security event with the same weight as a
  rejected token: a stream of them is someone guessing a secret.
- **The response says nothing.** A refused delivery gets a status and "not
  authorised"; which check failed is logged locally and never returned.

A valid delivery does **not** deploy anything by itself. It marks the project
for the sync loop, which then re-reads the source over the credential Kanea
holds — so a forged-but-somehow-valid delivery still cannot inject content, only
ask Kanea to look at a repository it already trusts. A push to a branch other
than the watched one is accepted and ignored.

**The project boundary is enforced at sync, not at delivery.** A synced spec
that declares services in another project is refused outright (PRD §10.1,
v1.23). Without that, write access to one project's git source would be write
access to every service on the node — the cross-project escalation R5 blocks for
secrets, arriving through a different door.

### 3.9 Outbound notifications (A10)

Everything above defends what reaches *in*. Notifications are the one subsystem
that deliberately reaches *out*, on the say-so of a job spec — which is server-
side request forgery unless it is bounded. A spec is not always written by the
person who owns the node, and the addresses worth reaching from inside one are
exactly those a firewall was meant to protect: `169.254.169.254`, the rest of
the internal network, localhost.

- **https only**, and **private, loopback, link-local, multicast and
  unique-local destinations are refused**, with an explicit opt-out for an
  operator genuinely running an internal chat server.
- **The address check runs at dial time, on every resolved candidate.** A
  hostname is not a destination: the same name can resolve publicly when it is
  validated and to 127.0.0.1 when it is connected to, and a name answering with
  both a public and a private address is how a check on one result is bypassed.
- **Redirects are refused.** An allowed target answering `302` to the metadata
  service would otherwise walk past every check above.
- **NAT64 (`64:ff9b::/96`) is decoded**, because it carries an IPv4 address in
  its low 32 bits and every ordinary predicate calls it public.

**Channel credentials are `secret:` references, project-scoped like every
other** (R3, R5) — bot tokens, signing keys, SMTP passwords, and Slack/Discord
incoming-webhook URLs, the last because that URL *is* the credential. Telegram's
token necessarily sits in the request URL, so its transport errors are replaced
with the channel name rather than returned: an error carrying the URL would put
a bot token in the daemon log.

Two things in the mail path are Kanea's rather than the standard library's.
**Header injection**: a subject carries a service name and an error string,
either of which can hold a newline, and a newline in a header is a second header
— an alert becomes a way to add recipients. **Dot-stuffing**: a line that is a
single `.` ends the DATA command, so an event message containing one would
truncate the mail and leave the rest to be read as SMTP commands.

Notifications are also a **denial-of-service surface pointed at Kanea itself**.
Emitting never blocks the emitter, per-channel rate limits keep a crash-looping
fleet from getting the bot blocked, and events coalesce into digests — so a
storm produces one message rather than one per alloc, and a full queue drops
with a counter rather than growing without bound.

---

## 4. Attack walkthroughs

**A scanner finds the API listener.** Health answers; everything else is 401.
Thirty requests a minute, then 429 with `Retry-After`. Nothing is written to the
audit log, so the log cannot be used to fill the disk. If no account is
configured, the listener does not exist at all.

**A tenant points a notification webhook at the metadata service.** The scheme
check refuses anything but https at parse time. If the target is an https name
that resolves to `169.254.169.254`, the dialer refuses it at connect time, on
every candidate address the name returns. If a public target answers 302 to it,
the redirect is refused. Nothing is fetched and nothing is returned to the
caller — a failed delivery is logged, not echoed.

**Someone forges a push webhook.** Without the project's webhook secret the
HMAC fails, the delivery is refused with 401 and audited, and nothing is read or
built. With a *replayed* valid delivery the id is already in the cache and the
answer is 200 with no work done. Even a delivery that passes every check only
schedules a sync: the content that would be deployed comes from the repository
Kanea clones with its own credential, not from the request body.

**An operator's laptop opens a malicious page.** It cannot read the session
cookie (`HttpOnly`), cannot set the CSRF header cross-origin without a preflight
the browser refuses, and cannot open the live socket (`Origin`). A cross-site
form post carries the cookie and nothing else — exactly the request the CSRF
check rejects.

**A workload is compromised.** No capabilities, no escalation, no route to
another project's services (policy), no cloud metadata (egress policy), no way
to exhaust the node (cgroup ceiling). It can reach what its project's policy
allows, which is the point of declaring it.

**A bearer token is stolen.** It carries a role; a viewer token reads and
nothing else. Every use is audited with the token id, and revocation takes
effect on the next request because the check is a Store lookup, not a signature.

**The audit trail is tampered with.** Editing an entry breaks the chain there
and `Verify` names it. Truncating the tail is the case a chain alone does not
catch — that is what the signed periodic export (M10) is for.

---

## 5. OWASP §14 status as built

| | Control | State |
|---|---|---|
| A01 | Deny-by-default on every route, roles, CSRF, WS origin | **Built** |
| A02 | Secrets encrypted at rest, bcrypt passwords, TLS on the listener | **Built** — listener TLS is operator-supplied |
| A03 | HCL schema validation, DNS-1123 names, no shell interpolation | **Built** |
| A04 | Secure-by-default config; this document | **Built** |
| A05 | Security headers, CSP, hardened workload defaults | **Built** |
| A06 | `govulncheck`, `gosec`, `gitleaks`, `npm audit` in CI | **Built** |
| A07 | Login and global rate limits, token expiry, OIDC + PKCE | **Built** |
| A08 | Digest pinning honoured; release signing | **Partial** — signing is M10 |
| A09 | Hash-chained audit log, retention | **Built** — signed export is M10 |
| A10 | Metadata-endpoint egress policy | **Built** — git/webhook SSRF rules are M7/M8 |

---

## 6. Out of scope, deliberately

- **Node-local root.** Anyone root on the host owns the daemon, the master key
  and the container runtime. Nothing here defends against that, and pretending
  otherwise would mean designing around a boundary that does not exist.
- **Kernel container escape.** Kanea drops capabilities, applies seccomp and
  namespaces every alloc; a kernel bug past all of that is the kernel's boundary,
  not Kanea's. The mitigation is patching, which `kanea doctor` (M10) checks.
- **Hostility between projects on one node.** Projects are isolated by network
  policy and cgroups, not by virtualisation. v1 is a single-team platform;
  a project is an organisational boundary that happens to be enforced, not a
  security boundary being sold as one.
- **Denial of service by an authenticated admin.** An admin can stop every
  service. That is the job.
- **Physical access and disk theft.** Nothing here survives it except what full-
  disk encryption provides, which is the operating system's to configure.

---

## 7. Known residual risks

| Risk | Why it remains | Milestone |
|---|---|---|
| Master key loss is unrecoverable | Escrow ceremony not built | M10 |
| Audit tail truncation is undetectable | Needs the signed export | M10 |
| An audit entry can be lost if the Store fails mid-request | Needs an audited apply in one Store batch | — |
| API listener TLS is operator-supplied | ACME for the control plane is not wired | M10 |
| The MCP tool surface is not covered here | Not built | M9 |
| GitHub OAuth carries no signed identity | Deliberately not shipped (PRD v1.19) | — |
