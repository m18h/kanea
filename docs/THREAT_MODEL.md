# Kanea Threat Model

> **Status: stub.** To be written during **milestone M5** (auth & OWASP pass, PRD §20).
> Baseline: PRD §14 (OWASP Top 10 mapping) and AGENTS.md "Binding constraints".

## Planned contents

1. System overview & trust boundaries (public edge ↔ kanea-edge ↔ kanead ↔ Store; API/WS/MCP surfaces; containerd/Cilium sockets = root-equivalent)
2. Assets (state, secrets, certs, master key, images, pipeline creds)
3. Threat actors & abuse cases (external attacker, compromised workload, malicious project spec, rogue AI agent via MCP, supply chain)
4. STRIDE analysis per component
5. Mitigations mapped to PRD §14 controls
6. Residual risks & accepted risks (PRD §22)
