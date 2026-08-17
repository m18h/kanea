import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import { StatTile } from '@/components/StatTile'
import {
  createBackup,
  fetchBackups,
  stageRestore,
  verifyBackup,
  type Backup,
} from '@/lib/api'
import { describeArchive, formatTime, isStale, replicationLag } from '@/lib/backups'
import { formatBytes, relativeAge } from '@/lib/state'
import { useSession } from '@/hooks/useSession'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'

type VerifyVerdict = { state: 'checking' } | { state: 'ok' } | { state: 'failed'; message: string }

/**
 * Backups (PRD §15.3).
 *
 * The page leads with replication health rather than with the archive list,
 * because "when did this last succeed" is the number that decides whether a
 * backup strategy is real, and the one an operator normally does not have
 * until the restore, at which point it is too late to be useful.
 *
 * Integrity is verify-on-demand: a verify decrypts and reads the whole
 * archive, so a column that auto-verified thirty of them on page load would be
 * a self-inflicted denial of service. The verdict is remembered for the
 * session, no longer: nothing persists it.
 *
 * "Stage" writes a restore request the daemon acts on at its next start; an
 * in-place restore deliberately does not exist (§15.3). The offline path is
 * `kanea restore` at a terminal.
 */
export function Backups() {
  const client = useQueryClient()
  const { session, csrf } = useSession()
  const [error, setError] = useState('')
  const [verdicts, setVerdicts] = useState<Record<string, VerifyVerdict>>({})
  const [staged, setStaged] = useState<string | null>(null)
  const [confirmStage, setConfirmStage] = useState<string | null>(null)

  const backups = useQuery({
    queryKey: ['backups'],
    queryFn: ({ signal }) => fetchBackups(signal),
    refetchInterval: 30_000,
  })

  const take = useMutation({
    mutationFn: () => createBackup('from the dashboard', csrf),
    onSuccess: () => {
      setError('')
      void client.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const check = useMutation({
    mutationFn: (id: string) => verifyBackup(id),
    onMutate: (id) => setVerdicts((v) => ({ ...v, [id]: { state: 'checking' } })),
    onSuccess: (_data, id) => setVerdicts((v) => ({ ...v, [id]: { state: 'ok' } })),
    onError: (err: Error, id) =>
      setVerdicts((v) => ({ ...v, [id]: { state: 'failed', message: err.message } })),
  })

  const stage = useMutation({
    mutationFn: (id: string) => stageRestore(id, csrf),
    onSuccess: (_resp, id) => {
      setError('')
      setStaged(id)
    },
    onError: (err: Error) => setError(err.message),
  })

  const canWrite = session?.role === 'admin'
  const archives = backups.data?.backups ?? []
  const replication = backups.data?.replication
  const pager = usePagination(archives)

  if (backups.isSuccess && backups.data === null) {
    // Distinct from "no archives yet", and the difference matters enormously:
    // one is a node that has not been backed up, the other is a node that
    // cannot be.
    return (
      <section className="space-y-3">
        <PageHeader title="Backups" />
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          No backup destination is configured on this daemon. Its state exists only on
          its own disk: a disk failure would lose all of it. Set{' '}
          <code className="font-mono text-xs">--backup-dir</code> or{' '}
          <code className="font-mono text-xs">--backup-s3</code>, then read{' '}
          <code className="font-mono text-xs">docs/DR_RUNBOOK.md</code>.
        </p>
      </section>
    )
  }

  const stale = isStale(replication?.last_segment_at)
  const totalBytes = archives.reduce((sum, a) => sum + a.snapshot.size, 0)

  return (
    <section className="space-y-4">
      <PageHeader
        title="Backups"
        subtitle={replication?.sink ? `AEAD archives → ${replication.sink}` : undefined}
        actions={
          canWrite ? (
            <Button
              className="font-semibold"
              disabled={take.isPending}
              onClick={() => take.mutate()}
            >
              {take.isPending ? 'Taking a snapshot…' : 'Snapshot now'}
            </Button>
          ) : undefined
        }
      />

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {backups.isError ? (
        <p className="text-sm text-destructive">Cannot read the archive list.</p>
      ) : null}

      {backups.data ? (
        <div className="grid gap-4 sm:grid-cols-3">
          <StatTile
            label="Replication lag"
            value={replicationLag(replication?.last_segment_at)}
            tone={stale || (replication?.failures ?? 0) > 0 ? 'error' : 'ok'}
            sub={
              (replication?.failures ?? 0) > 0
                ? `${replication?.failures} failure(s)`
                : stale
                  ? 'stale; RPO target is five minutes'
                  : `shipped to index ${replication?.shipped_to ?? 0}`
            }
          />
          <StatTile
            label="Retained archives"
            value={archives.length}
            sub={archives.length > 0 ? `${formatBytes(totalBytes)} total` : undefined}
          />
          <StatTile
            label="Last snapshot"
            value={
              replication?.last_snapshot_at ? relativeAge(replication.last_snapshot_at) : 'never'
            }
            sub={
              replication?.last_snapshot_at
                ? `ago · ${formatTime(replication.last_snapshot_at)}`
                : undefined
            }
          />
        </div>
      ) : null}

      {stale ? (
        <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          Changes have not shipped recently. The RPO target is five minutes; anything
          written since the last segment would be lost.
        </p>
      ) : null}

      {backups.isSuccess && archives.length === 0 ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          There are no archives. Nothing on this node has been backed up.
        </p>
      ) : null}

      {archives.length > 0 ? (
        <Card className="py-2">
          <Table>
            <THead>
              <tr>
                <TH className="pt-2">Archive</TH>
                <TH className="pt-2">Size</TH>
                <TH className="pt-2">Contents</TH>
                <TH className="pt-2">Integrity</TH>
                <TH className="pt-2">S3</TH>
                <TH className="pt-2 text-right">Restore</TH>
              </tr>
            </THead>
            <TBody>
              {pager.pageItems.map((archive) => (
                <ArchiveRow
                  key={archive.id}
                  archive={archive}
                  shippedTo={replication?.shipped_to ?? 0}
                  verdict={verdicts[archive.id]}
                  onVerify={() => check.mutate(archive.id)}
                  staged={staged === archive.id}
                  confirming={confirmStage === archive.id}
                  canWrite={canWrite}
                  onStage={() => {
                    if (confirmStage !== archive.id) {
                      setConfirmStage(archive.id)
                      return
                    }
                    setConfirmStage(null)
                    stage.mutate(archive.id)
                  }}
                />
              ))}
            </TBody>
          </Table>
          <div className="px-3">
            <PaginationControls state={pager} />
          </div>
        </Card>
      ) : null}

      {staged ? (
        <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          <span className="font-mono">{staged}</span> is staged. Nothing has been restored
          yet: the daemon performs it at its next start, before anything opens the Store.
        </p>
      ) : null}

      <p className="text-xs text-muted-foreground">
        A staged restore is applied at the next daemon start. For an offline or
        disaster-recovery restore, use <code className="font-mono">kanea restore</code> at a
        terminal: see <code className="font-mono">docs/DR_RUNBOOK.md</code>.
      </p>
    </section>
  )
}

function ArchiveRow({
  archive,
  shippedTo,
  verdict,
  onVerify,
  staged,
  confirming,
  canWrite,
  onStage,
}: {
  archive: Backup
  shippedTo: number
  verdict: VerifyVerdict | undefined
  onVerify: () => void
  staged: boolean
  confirming: boolean
  canWrite: boolean
  onStage: () => void
}) {
  // Derived per archive, not global: a segment index at or past this archive's
  // means the sink holds everything this archive needs.
  const replicated = archive.index <= shippedTo

  return (
    <TR>
      <TD>
        <span className="block font-mono text-xs">{archive.id}</span>
        <span className="block font-mono text-[11px] text-muted-foreground">
          {formatTime(archive.created_at)}
        </span>
      </TD>
      <TD className="whitespace-nowrap font-mono text-xs tabular-nums">
        {formatBytes(archive.snapshot.size)}
      </TD>
      <TD className="text-xs text-muted-foreground">{describeArchive(archive)}</TD>
      <TD>
        {verdict === undefined ? (
          <Button size="sm" variant="outline" className="h-7 px-2 text-xs" onClick={onVerify}>
            Verify
          </Button>
        ) : verdict.state === 'checking' ? (
          <span className="text-xs text-muted-foreground">checking…</span>
        ) : verdict.state === 'ok' ? (
          <Badge variant="ok" className="font-mono text-[11px]">
            verified
          </Badge>
        ) : (
          <Badge variant="error" className="font-mono text-[11px]" title={verdict.message}>
            failed
          </Badge>
        )}
      </TD>
      <TD>
        <span
          className={`font-mono text-xs ${replicated ? 'text-status-ok' : 'text-muted-foreground'}`}
        >
          {replicated ? 'replicated' : 'pending'}
        </span>
      </TD>
      <TD className="text-right">
        {staged ? (
          <Badge variant="outline-warn" className="font-mono text-[11px]">
            staged
          </Badge>
        ) : (
          <Button
            size="sm"
            variant="outline"
            className={`h-7 px-2 text-xs ${confirming ? 'border-status-warn text-status-warn' : ''}`}
            disabled={!canWrite}
            title={canWrite ? undefined : 'Requires the admin role'}
            onClick={onStage}
          >
            {confirming ? 'Confirm stage?' : 'Stage'}
          </Button>
        )}
      </TD>
    </TR>
  )
}
