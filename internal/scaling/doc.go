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
//   - **Hubble** — east-west flows and policy drops, opt-in and off by default.
//     Its L7 parsing costs CPU per request and its ring buffer drops flows
//     under load, so it loses fidelity exactly when the numbers matter; and
//     cilium-agent with Hubble on was the largest resident process M0 measured.
//     What it adds is the traffic the edge never sees. See hubble.go.
//
// The evaluator (evaluator.go) turns those into replica counts with HPA-style
// proportional rules plus the guardrails §9.2 requires, and the loop (loop.go)
// applies them through the reconciler rather than acting on containers itself.
package scaling
