// Package reconciler implements the convergence loop: desired state (Store)
// to actual state (containerd/datapath/edge), plus the Scheduler interface
// (v1: LocalScheduler). Includes health-gated rollouts, restart backoff,
// drift repair, and the global circuit breaker. (PRD §5.2.2, §4.3.)
package reconciler
