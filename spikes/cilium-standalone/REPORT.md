# REPORT; Spike ①: standalone Cilium (no Kubernetes)

**Date:** 2026-07-30 · **Verdict: GO on all five questions, but only on Cilium ≥ 1.18, and not through the interfaces the PRD assumes** · **PRD amendments required: yes (§5.2.5, §7.1, §22 R1, §23.2; see the last section)**

This was PRD §22's **#1 technical risk**. Standalone Cilium works, end to end, for
everything Kanea needs. The surprise is *how*: the two write APIs the PRD builds on
(service LB, policy import) **were removed in Cilium 1.18**, and their non-k8s
replacements are **watched files**, not REST calls. Endpoint labelling is also not
what the PRD assumes: CNI args cannot carry labels at all.

## Environment

| | |
|---|---|
| Host | OrbStack VM `kanea-spike` (Ubuntu 24.04, arm64), 18 vCPU / 8 GiB |
| Kernel | 7.0.11-orbstack, cgroups v2, systemd PID 1 |
| Runtime | containerd **2.3.3**, runc **1.5.1** (from spike ②) |
| Cilium | **1.19.6**: `quay.io/cilium/cilium:v1.19.6` @ `sha256:0df5b275…ac92`, run as a privileged host-network containerd task |
| kvstore | etcd **3.7.1** on 127.0.0.1:2379 (single node), `--identity-allocation-mode=kvstore` |
| Datapath | native routing, `--enable-k8s=false`, KPR **true**, Maglev, IPAM cluster-pool from `--ipv4-range=10.200.1.0/24` |
| Image | `docker.io/library/busybox:1.37` |

Provision: `provision-vm.sh` (pinned, sha256-verified). Reproduce: `README.md`.
Result: **`spike all` = 25/25 PASS, three consecutive clean runs**; `spike hazard` 2/2.

---

## Q1; CNI ADD from our own process: **GO**

```
✓ attach spike-web-1  1.15s   ✓ attach spike-web-2  123ms   ✓ attach spike-client  313ms
PASS  CNI ADD created one Cilium endpoint per alloc   4/4, key = external-identifiers.container-id
PASS  endpoint IPv4 matches the CNI result            spike-web-1=10.200.1.71
PASS  workload joins the pre-created netns            inet 10.200.1.162/32 scope global eth0
PASS  east-west: client -> web-1                      (eBPF datapath, no policy yet)
PASS  north-south: alloc -> internet (masquerade)     1.1.1.1:80
```

The attach sequence that works, and the order matters:

```
ip netns add <alloc>  →  CNI ADD (cilium-cni)  →  PATCH endpoint labels  →  containerd task start
```

- **Network before start, not after.** Between CNI ADD and the label patch the endpoint
  carries `reserved:init`, and init endpoints are **policy-enforced (deny) in both
  directions**. A workload started in that window has its traffic dropped. Spike ②'s
  "pre-create persistent netns" note is therefore not just tidy: it is required.
- **Alloc IDs must be ≥ 5 characters.** Cilium derives the temporary interface name from
  the first 5 characters of `"<containerID>:<ifname>"`; a shorter ID leaks the `:` into an
  interface name and CNI ADD fails with a bare `invalid argument` from the kernel. Kanea's
  DNS-1123 names satisfy this, but the ID must never be truncated below 5 chars.
- Lookup key for alloc → endpoint is `GET /v1/endpoint/container-id:<alloc-id>`; the agent
  also records `cni-attachment-id = "<id>:eth0"`.
- `cilium-cni` does not bring `lo` up inside the netns. Kanea must (`ip link set lo up`).

## Q2; Endpoint labels and identity: **GO, but not via CNI**

```
PASS  identity labels set via agent API replace reserved:init
        k8s:io.kubernetes.pod.namespace=shop unspec:kanea=true unspec:project=shop unspec:service=web
PASS  identity allocated from the etcd kvstore        web=1851 client=2180 other=20741
PASS  identical labels share one identity             web-1=1851 web-2=1851 client=2180
PASS  no residual init enforcement once labels are set  policy-enabled="none"
```

**The PRD's assumption that labels ride in on CNI args is wrong.** In
`plugins/cilium-cni/cmd/endpoint.go` the plugin builds its `EndpointChangeRequest` with a
hardcoded `Labels: models.Labels{}` and forwards only `K8S_POD_NAME/NAMESPACE/UID`
(verified identical in 1.17.18 and 1.19.6). There is no CNI-level hook for custom labels.

Labels must come from a second call, and **which call matters**:

| Call | Effect |
|---|---|
| `PATCH /v1/endpoint/{id}` with `{"labels":[…],"state":"waiting-for-identity"}` | ✅ **replaces** the identity label set → `reserved:init` gone, identity allocated, enforcement drops to `none`. `state` is a required field (422 / code 602 without it). |
| `PATCH /v1/endpoint/{id}/labels` with `{"user":[…]}` | ❌ merges *custom* labels only; `reserved:init` survives and the endpoint stays under init policy (all traffic denied). |

Two further findings:

- **`project` must also be published as a k8s namespace label.** Cilium rewrites every
  `fromEndpoints`/`toEndpoints` selector (`pkg/k8s/apis/cilium.io/utils`): a clusterwide
  policy gets `k8s:io.kubernetes.pod.namespace Exists` injected, a namespaced one gets
  `=<ns>`. Endpoints without that label match **no peer selector at all**: every rule
  silently denies everything, which is exactly the failure this spike hit before adding
  `k8s:io.kubernetes.pod.namespace=<project>`. Mapping **project → namespace label** puts
  Kanea on the same policy semantics every Cilium user relies on.
  `--policy-default-local-cluster=false` is also required, else selectors additionally
  demand `k8s:io.cilium.k8s.policy.cluster=default`.
- **The label PATCH is retryable, not fatal.** Roughly 1 attach in 8 returned
  `500 "error while regenerating endpoint"` because the CNI-created endpoint was still
  regenerating. Bounded retry (6 × 300 ms backoff, 4xx treated as a real error) made three
  consecutive full runs green.

## Q3; Service load balancing: **GO via `--lb-state-file`, the REST API is gone**

```
✓ write lb-state.json (2 backends, atomic rename)
PASS  service programmed from the state file and realized by the agent  frontend=10.201.0.1:80 backends=2
PASS  east-west LB spreads across both backends (Maglev)   web-1=11 web-2=9 err=0
PASS  host -> service VIP works (kanea-edge north-south path)  web-1=5 web-2=5 err=0
PASS  backend removal converges (all traffic to the survivor)  web-1=10 web-2=0
PASS  emptying the state file removes the frontend
```

`PUT /v1/service/{id}` and `DELETE /v1/service/{id}` **existed in 1.17 and were removed in
1.18** (`pkg/client/service.go` keeps only `GetServices`). On 1.19 the call returns
`404 path /v1/service/1 was not found`. Services now come from data sources feeding a
StateDB-based LB control plane.

The supported non-k8s data source is **`--lb-state-file=<path>.json|yaml`**: a watched file
holding Kubernetes-*shaped* `Service` + `EndpointSlice` objects (schema only; no API
server, no CRDs, no client-go). Verified properties:

- ClusterIP frontends outside the endpoint CIDR work (10.201.0.1:80 → backends on 10.200.1.0/24).
- Maglev spreads connections across backends; **host → VIP works** thanks to socket LB
  (`--kube-proxy-replacement=true`), which is what `kanea-edge` needs.
- Backend add/remove and full deletion converge in well under the 15 s poll budget.
- **Writes must be atomic** (`rename(2)` into place): Cilium's own test data states this is
  required of production users; the watcher reacts to fsnotify events and would otherwise
  read a partial file.

## Q4; Network policy: **GO via `--static-cnp-path`, the REST API is gone**

```
PASS  baseline: cross-project reachable before policy
✓ install CCNP yaml (atomic rename into watched dir)
PASS  policy loaded by the agent (no CRDs, no API server)   policy revision 3 -> 4
PASS  intra-project traffic still allowed (client -> web)
PASS  cross-project traffic denied (other -> web)           exit=1
PASS  enforcement visible on the endpoint model             policy-enabled="ingress"
PASS  host endpoint healthy under policy                    reserved:host state=ready
PASS  deleting the file withdraws the policy
```

`PUT/DELETE /v1/policy` are gone in 1.18+ (`405 method PUT is not allowed, but [GET] are`;
even `GET /v1/policy` is marked deprecated "will be removed in v1.19"), and
`cilium-dbg policy import/delete` went with them. The replacement is
**`--static-cnp-path=<dir>`**: a watched directory of CiliumNetworkPolicy YAML files.

- A file with empty `metadata.namespace` is treated as a **CiliumClusterwideNetworkPolicy**.
- File names must be DNS-1123 subdomains ending in `.yaml`; anything else is ignored,
  which conveniently makes `.<name>.tmp` + rename a safe atomic write.
- Withdrawing a policy = deleting its file. Policy revision is observable via `GET /v1/policy`.

**Hazard; an invalid policy file kills the agent** (`spike hazard`, 2/2):

```
PASS  invalid policy file is fatal to cilium-agent   API unreachable ~2s after the write
PASS  agent recovers once the bad file is removed
```

`pkg/policy/directory/watcher.go` calls `logging.Fatal()` when a file fails to translate:
both on fsnotify events *and* during the startup directory scan, so a bad file left on disk
turns into a **crash loop**. This is the sharpest operational finding of the spike: Kanea
must validate every generated policy before it reaches the watched directory, write it
atomically, and treat that directory as owned exclusively by `kanead`. PRD §5.2.5's "bad
policy must never lock out the host endpoints" is now a hard requirement with teeth: the
failure mode is worse than a rejected import, it is a downed agent.

## Q5; Hubble metrics without k8s: **GO**

```
PASS  hubble metrics endpoint serves Prometheus text (no k8s)  :9965 -> 39107 bytes
PASS  flows observed                       hubble_flows_processed_total=2631
PASS  policy drops observed                hubble_drop_total=84
INFO  other configured metric families     hubble_tcp_flags_total=852 hubble_port_distribution_total=638
PASS  DNS proxied and observed at L7        hubble_dns_queries_total=4
```

- `--hubble-metrics` is **space-separated inside one value** (`--hubble-metrics='dns drop
  tcp flow port-distribution'`). Comma-separated is parsed as a single unknown metric name
  and repeating the flag keeps only the last occurrence: both fail *silently* except for one
  `level=warn "Skipping unknown hubble metric"` line, leaving a metrics endpoint that serves
  200 OK with no flow data. Worth a `kanea doctor` check.
- L7 DNS visibility works through the standalone DNS proxy with a `toFQDNs` + `rules.dns`
  policy: PRD §7.1's "or delegated to Cilium's standalone DNS proxy" option is real.
  (Kanea's built-in resolver remains the preferred path; this is a validated fallback.)

## No Go client: Kanea must speak the REST API directly

PRD §23.2 lists `github.com/cilium/cilium` (API client) as a dependency. **It should not be
imported.** The module's `go.mod` requires the Kubernetes client graph (`k8s.io/client-go`
and friends) and ships `replace` directives that consumers do not inherit: dragging it in
contradicts AGENTS.md constraint #10 ("no client-go, no kube imports, ever") and inflates
the dependency/CVE surface for a project whose release gates are `govulncheck`/`gosec`.

The spike therefore speaks the agent API over `/var/run/cilium/cilium.sock` with `net/http`
and ~60 lines of hand-written structs (`cilium.go`). Everything Kanea needs is covered by
four calls, all stable and all `GET`/`PATCH`:

| Need | Call |
|---|---|
| alloc → endpoint | `GET /v1/endpoint/container-id:<id>` |
| identity labels | `PATCH /v1/endpoint/container-id:<id>` |
| verify LB state | `GET /v1/service` |
| verify policy state | `GET /v1/policy` (deprecated: prefer endpoint `policy-enabled`) |

Everything else is files: `lb-state.json` and `policies/*.yaml`.

## Footprint (PRD §21: total platform ≤ 1 GiB)

| Process | RSS |
|---|---|
| `cilium-agent` (Hubble on, Envoy embedded) | **152.8 MiB** |
| `containerd` | 41.9 MiB |
| `etcd` | 23.0 MiB |
| `containerd-shim` (per alloc) | 11.3 MiB |

≈ 218 MiB before `kanead`/`kanea-edge`, with Hubble **enabled**. The §21 budget holds, but
cilium-agent is the single largest resident component: the PRD's "Hubble off by default"
default is the right one, and the 1 GiB `system_reserve_memory` floor (§5.2.11) must cover
the agent, not just Kanea's own processes.

## Version floor: **≥ 1.18, pin 1.19.x**

- **1.17** has the writable service and policy APIs but neither `--lb-state-file` nor
  `--static-cnp-path`. It is now three minors behind 1.20 and effectively out of support:
  building v1 on it would put an unpatched component behind Kanea's own CVE release gates
  (AGENTS.md #7). Rejected.
- **1.18/1.19** have the file-based interfaces this spike validated. Recommendation: floor at
  **≥ 1.18**, pin and test **1.19.6**, and keep the version matrix (PRD §15.4) enforcing it;
  * these interfaces changed once already and can change again.

## Fallback status

PRD §22 R1's fallback (bridge CNI + edge-proxy LB) is **not needed**. All five capabilities
are available on 1.19.6; the risk is now "the non-k8s interfaces are file-based and were
churned in 1.18", which the version matrix plus `kanea doctor` handle.

---

## PRD amendments required

1. **§5.2.5**: service LB is programmed via **`--lb-state-file`** (atomic rename, k8s-shaped
   Service/EndpointSlice JSON), not `PUT /v1/service/{id}`; network policy via
   **`--static-cnp-path`** (validated, atomically-written CNP YAML), not `PUT /v1/policy`;
   endpoint labels via **`PATCH /v1/endpoint/{id}`** after CNI ADD and **before task start**,
   not via CNI args. Add the agent flags this needs
   (`--kube-proxy-replacement=true`, `--policy-default-local-cluster=false`,
   `--identity-allocation-mode=kvstore`, `--ipv4-range`).
2. **§5.2.5 / §14**: the policy directory is a **fatal-on-malformed** input: Kanea validates
   before writing, writes atomically, and owns the directory. A bad file is an agent crash
   loop, not a rejected import.
3. **§7.1 / §6.2**: a project's identity labels include
   `k8s:io.kubernetes.pod.namespace=<project>`; without it every policy selector matches
   nothing. Document project ≡ namespace.
4. **§22 R1**: retire "endpoint labels via CNI args" and the "partially de-risked" wording;
   record the spike result, the new interfaces, and the residual risk (file-based interfaces,
   churned in 1.18).
5. **§23.2**: drop `github.com/cilium/cilium` as a dependency (pulls client-go; violates
   constraint #10); replace with "agent REST API over the unix socket, hand-rolled client".
   Bump `cilium-agent` from **≥ 1.17** to **≥ 1.18 (tested 1.19.6)**.
6. **§21**: note that cilium-agent alone is ~150 MiB RSS with Hubble on, inside the 1 GiB
   control-plane reserve.

## M2 implementation notes (carry these into `internal/network`)

- Attach order: `netns → CNI ADD → label PATCH (retry on 5xx) → lo up → task start`.
- Detach order: CNI DEL **before** the netns disappears (spike ② lesson holds).
- Alloc IDs ≥ 5 chars; never truncate below that for the CNI container ID.
- Both file interfaces need write-temp-then-`rename(2)`; temp names must not end in
  `.yaml`/`.json` in the watched paths.
- Batch LB updates by rewriting the whole state file (that *is* the batching primitive);
  `--lb-state-file-interval` (default 1 s) is the settle window.
- Derived-state rebuild (PRD §5.2.5) is straightforward: wipe kvstore, re-emit
  `lb-state.json` + `policies/*.yaml` from the Store, re-attach endpoints.
- `kanea doctor` checks worth having: agent version in the supported matrix,
  `--hubble-metrics` actually parsed (scrape for `hubble_flows_processed_total`),
  KPR enabled, policy directory owned and clean.
