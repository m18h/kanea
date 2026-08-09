// Package scaling implements the metrics pipeline and the autoscaling
// evaluator (PRD §9).
//
// Three sources feed one in-memory time series, and the order is deliberate:
//
//   - **containerd** — one Prometheus scrape covering every cgroup on the node,
//     for cpu, memory and pids. See containerd.go.
//   - **kanea-edge** — per-service request rates and latency percentiles, the
//     *primary* signal for exposed services because the edge is already in the
//     request path. See edge.go.
//   - **the datapath** — east-west connects and drops from the eBPF datapath's
//     own per-CPU counters (PRD v1.36), on by default because reading a pinned
//     map costs nothing per request. What it adds is the traffic the edge
//     never sees: service-to-service calls inside the node. See datapath.go.
//
// The evaluator (evaluator.go) turns those into replica counts with HPA-style
// proportional rules plus the guardrails §9.2 requires, and the loop (loop.go)
// applies them through the reconciler rather than acting on containers itself.
package scaling
