## What & why

<!-- One logical change per PR. Link the milestone (PRD §20) this belongs to. -->

## Checklist

- [ ] This change follows `PRD.md`, or the PRD was amended first in this PR (AGENTS.md constraint #1)
- [ ] `make check` passes locally (vet, test, lint, security gates)
- [ ] No secrets/credentials added (gitleaks-clean); secrets are `secret:`-referenced, never inlined
- [ ] Metrics/logs did not touch the Store; mutations go through `Store` with monotonic indexes
- [ ] New API/WS/MCP routes are deny-by-default behind auth middleware
- [ ] Tests added/updated (table-driven; reconciler & jobspec >80% coverage)
- [ ] Docs updated (`PRD.md`, `AGENTS.md`, `docs/`) where behavior changed
