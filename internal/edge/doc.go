// Package edge implements kanea-edge, the separate ingress process: L7
// routing (Host → Cilium frontend IP), TLS termination with Let's Encrypt
// certs, the middleware chain (IP restriction → rate limit → headers),
// hardening timeouts, and per-service L7 metrics. It reads routes/certs from
// the Store and must survive kanead restarts. (PRD §5.2.6, §7.2, §7.2.1, §7.3.)
package edge
