// Package scaling implements the metrics pipeline (compressed in-memory TS)
// and the autoscaling evaluator: HPA-style proportional rules, stabilization
// windows, scale-step guardrails, cooldowns. Edge-proxy L7 metrics are the
// primary signal for exposed services; Hubble/eBPF is opt-in east-west.
// (PRD §9.)
package scaling
