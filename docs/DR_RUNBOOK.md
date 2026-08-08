# Kanea Disaster Recovery Runbook

> Baseline: PRD §15.3 (S3 state replication & backup/restore) and §15.4
> (upgrades & schema migration). This document describes what the code does
> today; where something is not yet built, it says so rather than describing a
> plan as a procedure.

---

## 0. Before anything else: the master key

**Every archive Kanea writes is encrypted with a key derived from
`<data-dir>/master.key`. Without that file, every backup is unreadable, and
there is no recovery path — not a slow one, not an expensive one, none.**

That is not a policy choice that can be revisited during an incident. The
archives are sealed with XChaCha20-Poly1305 under a key derived from that file;
there is no escrow held by anyone else and no recovery service.

So step zero of any recovery is: **find the master key.**

- If the node's disk survived: it is at `/var/lib/kanea/master.key`, mode 0600.
- If it did not: it is wherever you put the copy.

To check that the copy you found is the right one without restoring anything:

```bash
kanea backup list          # on any node with the key and the destination
```

Each archive's manifest carries a `key_id` — a non-secret fingerprint derived
from the master key. If the id in the manifest does not match the key you hold,
a restore refuses with a message saying exactly that, rather than failing with
an authentication error you would have to interpret.

`kanea init` runs the escrow ceremony: it prints the key once and requires you
to type it back before it writes anything. That is deliberately not a y/n
prompt — the point is to establish that you actually recorded it.

> **If you did not use `kanea init`,** the daemon generated the key on first use
> and logged a warning. Nothing enforced a copy. Take one now, on every node:
>
> ```bash
> cp /var/lib/kanea/master.key /somewhere/safe/   # then store it properly
> ```

---

## 1. What is backed up, and what is not

| Backed up | Not backed up |
|---|---|
| The whole Store: projects, services, allocs, certs, secrets, pipelines, audit log, accounts and tokens | Container images — re-pulled from the registry |
| Change segments between snapshots (RPO bound) | The Cilium kvstore — **derived state, rebuilt from desired state, never restored** (§18) |
| | Workload logs and metrics — file and in-memory pipelines, by design (constraint #2) |
| | Container filesystems and local volume contents |

Two consequences worth internalising before you need them:

- **A restore brings back the platform's intent, not its data.** Local volumes
  are not in an archive. If a service keeps state in a volume, that volume needs
  its own backup, and Kanea does not take one for you.
- **Workload convergence is best-effort and registry-bound.** The control plane
  comes back in minutes; every image has to be pulled again, and registry
  bandwidth dominates from there.

---

## 2. Targets

| | Target | What decides it |
|---|---|---|
| **RPO** | ≤ 5 minutes | Change segments ship every 60 s by default (`--backup-segment-interval`) |
| **RTO — control plane** | ≤ 15 minutes | Restore is a download, a decrypt and a replay |
| **RTO — workloads** | Best effort | Image pulls; a registry mirror helps most |

Check the first one is actually true on your node *before* you need it:

```bash
kanea backup list
```

The header reports when replication last succeeded. "Last segment: 40 minutes
ago" on a busy node means the destination is unreachable and nobody noticed.

---

## 3. Fresh-node restore

The procedure for a node whose disk is gone.

### 3.1 Prepare the new node

Install the same Kanea version the archives were written by (the manifest
records it: `kanea backup list` shows it once the destination is reachable).
Install containerd and Cilium per the version matrix.

**Do not start `kanead` yet.** A daemon that starts on an empty data directory
initialises a new, empty store and generates a *new* master key — which is the
one mistake in this document that cannot be undone, because the new key will not
open the old archives.

### 3.2 Put the master key back

```bash
install -d -m 0700 /var/lib/kanea
install -m 0600 /path/to/your/master.key /var/lib/kanea/master.key
```

Mode 0600 is enforced: the daemon refuses to start with a key that group or
other can read.

### 3.3 Restore the state

Offline, without a running daemon:

```bash
# From a directory (another disk, an NFS mount, a rotated drive)
kanea restore --from /mnt/backups

# From an S3-compatible bucket
kanea restore \
  --from s3://kanea-backups/node-1 \
  --s3-endpoint https://s3.eu-west-1.amazonaws.com \
  --s3-region eu-west-1 \
  --s3-access-key AKIA... \
  --s3-secret-key-file /root/.kanea-s3-secret
```

The secret key comes from a **file**, never an argument: everything in `argv` is
world-readable through `/proc/<pid>/cmdline` and lands in shell history.

By default this restores the newest archive and replays every change segment
above it. To pin an older one:

```bash
kanea backup list                       # needs a running daemon
kanea restore --from … --snapshot 20260808T120000Z
```

The command prints what it restored, at what index, and how many changes it
replayed.

### 3.4 Start the daemon

```bash
systemctl start kanead
```

From here it is an ordinary startup. The reconciler reads desired state and
converges: the Cilium kvstore is rebuilt from that state rather than restored,
images are pulled, endpoints are recreated, and edge routes come back as
services become healthy. There is no separate "recovery mode", which is the
point — coming back from a backup is the same code path as starting up.

---

## 4. Restore onto a running node

For a node that is up but wrong — a bad apply, a deletion nobody meant.

```bash
kanea backup list
kanea restore --snapshot 20260808T113000Z    # note: no --from
systemctl restart kanead
```

Without `--from`, `kanea restore` **stages** the restore rather than performing
one: it verifies the archive while there is still someone to tell, writes a
request, and tells you that a restart is what applies it. A restore happens on a
stopped node because the daemon holds the database open; the restart is where
that becomes true.

At the next start, before anything opens the Store, the daemon **moves the
current state aside** (`state.db.before-restore-<timestamp>`) and restores. If
the restore turns out to be the wrong archive, what was there is still there.

To cancel a staged restore before restarting:

```bash
rm /var/lib/kanea/restore-request.json
```

---

## 5. First-boot auto-restore

A node with no state at all and a destination configured can restore itself:

```bash
kanead --backup-s3 s3://kanea-backups/node-1 … --restore-if-empty
```

Off by default, deliberately. Bringing an entire platform's state back because a
directory looked empty is not something to do without being asked.

---

## 6. Verification and drills

**Verify an archive without the key.** Hashes are over the ciphertext, so
"are the bytes intact" is answerable before you go looking for the key:

```bash
kanea backup verify 20260808T120000Z
```

**Drill the restore.** Verification proves the bytes; it does not prove the
procedure. Restore to a scratch path on a machine that is not production:

```bash
kanea restore --from /mnt/backups --target /tmp/drill.db --data-dir /var/lib/kanea
```

Do this on a schedule. A backup nobody has restored is a hypothesis.

---

## 7. Failure playbooks

### A segment cannot be read

A replay that meets a segment it cannot decrypt **stops** and reports the index
it reached. It does not skip it: replaying past a gap produces a state that
never existed, because a delete in the missing segment never happens and the
record it removed comes back to be started by the reconciler.

Accept the snapshot alone if that is the better of the two:

```bash
kanea restore --from … --skip-replay
```

This loses every change after the snapshot. The command warns; the log records
it.

### The key does not match

```
backup: wrong master key: archive 20260808T120000Z was encrypted under key
a1b2c3d4…, this node holds e5f6a7b8…
```

You have a key, but not *the* key. Look for another copy. Nothing on the node
will make this archive readable.

### The schema is newer than the binary

```
store: invalid: on-disk schema v2 is newer than this binary's v1 — upgrade kanea
```

Refused on purpose. An older binary writing to a newer database drops the fields
the newer version added, on the first update, permanently. Install the newer
Kanea.

### A migration failed

The daemon takes a local copy before migrating and names it in the log:

```
state.db.pre-v2-20260808T120000Z
```

To roll back: stop `kanead`, move that copy over `state.db`, and run the previous
binary. The schema version is only bumped inside the migration's own
transaction, so a failed migration leaves the database on the old version and
the next start retries against the same state.

### Replication has silently stopped

`kanea backup list` reports the last successful segment and snapshot and the
failure count since start.

The replicator also emits `backup.failed` when replication starts failing and
`backup.succeeded` when it recovers — **on transitions only**, so a destination
that has been down since yesterday is one message rather than one a minute. Put
them in a project's `notifications { on = [...] }` filter and this becomes
something that tells you rather than something you check.

---

## 8. What is not yet built

Stated here rather than discovered during an incident:

- **`kanea upgrade`.** §15.4's binary-upgrade flow — drain the edge, restart it,
  then restart kanead — is not implemented as a command. The state-migration
  half is (see "A migration failed" above); the orchestration half is
  `systemctl restart kanea-edge kanead` by hand.
- **Signed archives.** Archives are authenticated (AEAD) and hashed, so
  tampering is detected on read. There is no separate signature, so an archive
  cannot be attributed to a node cryptographically.
- **Multipart upload.** An archive above 5 GiB is refused by name rather than
  split. A single node's Store is far below that; a node that reaches it needs
  this built.
- **Interoperability beyond MinIO.** CI runs the S3 client against MinIO, which
  verifies SigV4 — so the signature is known to be one a real service accepts.
  AWS S3, R2, B2 and Wasabi have not been in the loop, and each has its own
  quirks around addressing style and region handling.
