# Kanea Disaster Recovery Runbook

> How to get a node's state back: from a backup, onto a new machine or the
> same one. This document describes what the code does today; where something
> is not built, it says so rather than describing a plan as a procedure.

---

## 0. Before anything else: the master key

**Every archive Kanea writes is encrypted with a key derived from
`<data-dir>/master.key`. Without that file, every backup is unreadable, and
there is no recovery path. Not a slow one, not an expensive one, none.**

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

Each archive's manifest carries a `key_id`, a non-secret fingerprint derived
from the master key. If the id in the manifest does not match the key you hold,
a restore refuses with a message saying exactly that, rather than failing with
an authentication error you would have to interpret.

The manifest is **authenticated** as well: a restore verifies the manifest
itself against the key before trusting anything in it, so someone who can
write to the bucket cannot roll you back to an older genuine archive by
swapping manifests. Archives written by early releases carry no
authentication code and restore with a loud warning instead. When you see it,
treat the archive's age as unverified, and confirm the id and created-at are
the state you mean to roll back to before letting the replay run.

A restore also refuses a segment chain with a hole in it (a segment deleted
from the bucket). It says which index the state is good up to, and
`--skip-replay` restores the snapshot alone if that is what you want.

`kanea init` runs the escrow ceremony: it prints the key once and requires you
to type it back before it writes anything. That is deliberately not a y/n
prompt: the point is to establish that you actually recorded it.

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
| The whole Store: projects, services, allocs, certs (including the self-signed CA at `ca/self-signed`), secrets, pipelines, audit log, accounts and tokens | Container images, re-pulled from the registry |
| Change segments between snapshots (RPO bound) | The datapath's pinned BPF maps, which are **derived state, repopulated from desired state, never restored** |
| | Workload logs and metrics, which are file and in-memory pipelines by design |
| | Container filesystems and local volume contents |

Two consequences worth internalising before you need them:

- **A restore brings back the platform's intent, not its data.** Local volumes
  are not in an archive. If a service keeps state in a volume, that volume needs
  its own backup, and Kanea does not take one for you.
- **Workload convergence is best-effort and registry-bound.** The control plane
  comes back in minutes; every image has to be pulled again, and registry
  bandwidth dominates from there.
- **A restore with no archive means a new self-signed CA.** The CA lives in the
  Store and travels in the encrypted archive, so a real restore brings it back
  and every device that trusted it still trusts it. Rebuilding a node from
  scratch instead mints a fresh one, and **every phone, laptop and TV that had
  the old certificate installed has to be re-trusted**, with `kanea ca show` on
  the new node, installed again everywhere. That is a cost measured in devices, not
  minutes, and it is the reason the CA is in the archive rather than being a
  key-ceremony artefact like the master key.
- **`/etc/kanea` is not in the archive.** The node config
  `/etc/kanea/kanea.hcl` (listeners, subnets, the host-path allowlist, device
  and socket grants, `provider` and `certificate` blocks) is a file on the
  node. So are the certificates an operator provided and the credential files
  `provider` blocks name. Node policy lives outside the archive by design, so
  restoring a node means restoring `/etc/kanea` too: back it up with the rest
  of `/etc`.

---

## 2. Targets

| | Target | What decides it |
|---|---|---|
| **RPO** | ≤ 5 minutes | Change segments ship every 60 s by default (`backup.segment_interval`) |
| **RTO, control plane** | ≤ 15 minutes | Restore is a download, a decrypt and a replay |
| **RTO, workloads** | Best effort | Image pulls; a registry mirror helps most |

Check the first one is actually true on your node *before* you need it:

```bash
kanea backup list
```

The header reports when replication last succeeded. "Last segment: 40 minutes
ago" on a busy node means the destination is unreachable and nobody noticed.
The dashboard's Settings page shows the same numbers beside the destination.

**Where the destination is decided.** The `backup` stanza in
`/etc/kanea/kanea.hcl` is the starting point. A destination saved from the
dashboard's Settings page (or `PUT /v1/settings/backup`) is stored in the
Store and wins over the stanza; deleting it reverts to `kanea.hcl`. That is
the only place in Kanea where two sources can disagree, and the rest of this
runbook refers back to this paragraph.

Changing the destination at runtime is safe by construction: the new
destination is probed with a real test write *before* anything commits, the
old one receives a final segment ship, and the new one gets an immediate full
snapshot.

One consequence for an incident: when reconstructing which bucket a dead node
was shipping to, `kanea.hcl` alone is not the answer, because a saved
destination may have superseded it. `kanea backup list` on a live node, or the
newest archive's manifest in whichever bucket you find, is authoritative. The
offline `kanea restore --from` always takes its destination explicitly and is
unaffected.

---

## 3. Fresh-node restore

The procedure for a node whose disk is gone.

### 3.1 Prepare the new node

Install the same Kanea version the archives were written by (the manifest
records it: `kanea backup list` shows it once the destination is reachable).

Then install the host components:

```bash
kanea install                              # pinned versions, from upstream
kanea install --bundle ./kanea-bundle.tar.gz   # or from a bundle, no egress
```

The version matrix is compiled into that binary, so installing the *right*
Kanea version installs the right containerd with it, and carries the eBPF
datapath inside itself, which is one fewer thing to reconstruct correctly under
time pressure. `kanea doctor --offline`
confirms it before you go further.

If the disaster you are recovering from also took your network, the bundle is
the path: build it on any machine that can reach the internet, carry it in.
Keep one alongside the master key if the node is somewhere a network cannot be
assumed.

**Do not start `kanead` yet.** A daemon that starts on an empty data directory
initialises a new, empty store and generates a *new* master key. That is the
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
converges: the datapath's maps are repopulated from that state rather than
restored, images are pulled, allocs are re-attached, and edge routes come back
as services become healthy. There is no separate "recovery mode", which is the
point: coming back from a backup is the same code path as starting up.

---

## 4. Restore onto a running node

For a node that is up but wrong: a bad apply, a deletion nobody meant.

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

**A staged restore reads its destination from `kanea.hcl`, and only a
directory works.** The restore runs before the Store is open, so it cannot
see a destination saved from the dashboard and cannot resolve the `secret:`
reference in `backup.s3.secret_key`. What happens instead:

| Destination | At the restart |
|---|---|
| `backup.dir` in `kanea.hcl` | The restore runs. |
| `backup.s3` in `kanea.hcl` | kanead stops with `backup: S3 credentials are required`. The current state is untouched. |
| Saved from the dashboard only | kanead stops with `a restore is staged but no backup destination is configured`. The current state is untouched. |

In the last two cases the request stays staged and kanead will not start
until you cancel it. To restore from S3, cancel the request, stop kanead, and
use the offline form from §3.3 with `--from s3://…`.

To cancel a staged restore:

```bash
rm /var/lib/kanea/restore-request.json
```

---

## 5. First-boot auto-restore

A node with no state at all and a destination in the `backup` stanza of
`/etc/kanea/kanea.hcl` can restore itself when `backup.restore_if_empty` is set:

```hcl
backup {
  restore_if_empty = true
  s3 {
    url        = "s3://kanea-state/prod/node-a"
    endpoint   = "https://s3.eu-central-1.amazonaws.com"
    region     = "eu-central-1"
    access_key = "AKIAEXAMPLE"
    secret_key = "secret:shared/backup-s3"
  }
}
```

It has the limit §4 describes, for the same reason: this step runs before the
Store is opened, so it has only what is on the disk. That is `kanea.hcl` and
the master key, which must already be back at `<data_dir>/master.key`. With
the S3 destination above, kanead stops at start with
`backup: S3 credentials are required` rather than restoring. A `backup.dir`
destination needs no credential and restores as described. To bring a blank
node back from S3, use the offline `kanea restore --from s3://…` from §3.3,
which takes the secret key from a file.

Off by default, deliberately. Bringing an entire platform's state back because a
directory looked empty is not something to do without being asked.

---

## 6. Verification and drills

**Verify an archive.** `kanea backup verify` asks the running daemon to check
one archive in the current destination:

```bash
kanea backup verify 20260808T120000Z
```

It checks the manifest's authentication code against the node's key, then the
snapshot's size and SHA-256 against the manifest. The hash is over the
ciphertext, so nothing is decrypted. It does not read the change segments and
it does not prove the archive restores; the drill below does that.

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
store: invalid: on-disk schema v2 is newer than this binary's v1; upgrade kanea
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
`backup.succeeded` when it recovers, **on transitions only**, so a destination
that has been down since yesterday is one message rather than one a minute. Put
them in a project's `notifications { on = [...] }` filter and this becomes
something that tells you rather than something you check.

---

## 8. Limits, stated so they are not discovered during an incident

- **Interoperability is established against MinIO only.** CI runs the S3 client
  against MinIO, which verifies SigV4, so the signature is known to be one a
  real service accepts, **in both addressing styles**: path-style and
  virtual-hosted are separate signatures, because virtual-hosted moves the
  bucket into the host header and the host header is signed. What remains
  untested is the services themselves: AWS S3, R2, B2 and Wasabi have not been
  in the loop, and each has quirks around region handling and what it does with
  a request the others accept. **After configuring a new destination, take a
  backup and verify it** (`kanea backup create`, then `kanea backup verify
  <id>`) before you rely on it. Saving a destination from the dashboard
  already probes it with a test write; a destination written into `kanea.hcl`
  gets no probe until the first snapshot.
- **An archive above 5 GiB is refused rather than split.** Multipart upload is
  not implemented. A single node's Store is orders of magnitude below the limit;
  the error names the number if you ever meet it.
- **Archives are authenticated, not signed.** Tampering is detected on read
  because every chunk is AEAD-sealed and the manifest carries a hash. There is
  no signature, so an archive cannot be cryptographically attributed to the node
  that wrote it, which matters only for a bucket several nodes write to.
- **Local volumes are not in an archive.** See §1. A service that keeps data in
  a volume needs its own backup for that volume.
- **A restore at start works only from a directory.** A staged restore and
  first-boot auto-restore both read `backup.dir`; with an S3 destination use
  the offline `kanea restore --from` (§4, §5).
