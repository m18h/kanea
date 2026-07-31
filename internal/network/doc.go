// Package network is the standalone-Cilium driver: CNI setup, endpoint
// lifecycle with project/service labels, eBPF service LB via the agent API,
// network policies, and embedded DNS (authoritative for the internal zone
// only). Cilium state is DERIVED state — rebuilt from the Store on restore,
// never persisted. No Kubernetes dependencies, ever. (PRD §5.2.5, §7.)
package network
