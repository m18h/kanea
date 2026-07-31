# Kanea Disaster Recovery Runbook

> **Status: stub.** To be written during **milestone M10** (hardening & packaging, PRD §20).
> Baseline: PRD §15.3 (S3 state replication & backup/restore).

## Planned contents

1. **Step 0 — key recovery:** restore the escrowed master key (key ceremony output). Without it, all S3 backups are unreadable.
2. Fresh-node restore procedure (`kanea restore --from s3://…`, first-boot auto-restore)
3. Recovery order: master key → Store snapshot + CDC segment replay → Cilium kvstore rebuild (derived state, never restored) → parallel image pulls → endpoint recreation (exposed services first) → edge routes
4. Targets: RPO ≤ 5 min; RTO control plane ≤ 15 min, workload convergence best-effort
5. Backup verification (CI restore test) & periodic DR drills
6. Failure playbooks: etcd corruption, disk full, cert expiry, registry outage
