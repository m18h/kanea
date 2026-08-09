import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import {
  createBackup,
  fetchBackups,
  verifyBackup,
  type Backup,
  type ReplicationStatus,
} from '@/lib/api'
import { describeArchive, formatTime, isStale, when } from '@/lib/backups'
import { useSession } from '@/hooks/useSession'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'

/**
 * Backups (PRD §15.3).
 *
 * The page leads with replication health rather than with the archive list,
 * because "when did this last succeed" is the number that decides whether a
 * backup strategy is real — and the one an operator normally does not have
 * until the restore, at which point it is too late to be useful.
 *
 * There is no restore button. A restore replaces everything on the node and
 * happens on a stopped one; it belongs to `kanea restore`, where the operator
 * is already at a terminal and can read what it says. A button that discards a
 * platform's entire state is not a button.
 */
export function Backups() {
  const client = useQueryClient()
  const { session } = useSession()
  const [error, setError] = useState('')

  const backups = useQuery({
    queryKey: ['backups'],
    queryFn: ({ signal }) => fetchBackups(signal),
    refetchInterval: 30_000,
  })

  const take = useMutation({
    mutationFn: () => createBackup('from the dashboard'),
    onSuccess: () => {
      setError('')
      void client.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const check = useMutation({
    mutationFn: (id: string) => verifyBackup(id),
    onSuccess: () => setError(''),
    onError: (err: Error) => setError(err.message),
  })

  const canWrite = session?.role === 'admin'
  const pager = usePagination(backups.data?.backups ?? [])

  if (backups.isSuccess && backups.data === null) {
    // Distinct from "no archives yet", and the difference matters enormously:
    // one is a node that has not been backed up, the other is a node that
    // cannot be.
    return (
      <section className="space-y-3">
        <h1 className="text-xl font-semibold tracking-tight">Backups</h1>
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          No backup destination is configured on this daemon. Its state exists only on
          its own disk — a disk failure would lose all of it. Set{' '}
          <code className="font-mono text-xs">--backup-dir</code> or{' '}
          <code className="font-mono text-xs">--backup-s3</code>, then read{' '}
          <code className="font-mono text-xs">docs/DR_RUNBOOK.md</code>.
        </p>
      </section>
    )
  }

  const archives = backups.data?.backups ?? []

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold tracking-tight">Backups</h1>
        {canWrite ? (
          <button
            type="button"
            disabled={take.isPending}
            onClick={() => take.mutate()}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
          >
            {take.isPending ? 'Taking a snapshot…' : 'Back up now'}
          </button>
        ) : null}
      </div>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {backups.isError ? (
        <p className="text-sm text-destructive">Cannot read the archive list.</p>
      ) : null}

      {backups.data ? <Replication status={backups.data.replication} /> : null}

      {backups.isSuccess && archives.length === 0 ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          There are no archives. Nothing on this node has been backed up.
        </p>
      ) : null}

      {archives.length > 0 ? (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/40 text-left text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">Archive</th>
                <th className="px-3 py-2 font-medium">Taken</th>
                <th className="px-3 py-2 font-medium">Index</th>
                <th className="px-3 py-2 font-medium">Reason</th>
                <th className="px-3 py-2 font-medium">Contents</th>
                <th className="px-3 py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {pager.pageItems.map((archive) => (
                <ArchiveRow
                  key={archive.id}
                  archive={archive}
                  onVerify={() => check.mutate(archive.id)}
                  verifying={check.isPending && check.variables === archive.id}
                  verified={check.isSuccess && check.variables === archive.id}
                />
              ))}
            </tbody>
          </table>
          <PaginationControls state={pager} className="px-3 pb-3" />
        </div>
      ) : null}

      <p className="text-xs text-muted-foreground">
        Restoring is deliberately not a button here: it replaces everything on this node
        and happens on a stopped one. Use <code className="font-mono">kanea restore</code>.
      </p>
    </section>
  )
}

function ArchiveRow({
  archive,
  onVerify,
  verifying,
  verified,
}: {
  archive: Backup
  onVerify: () => void
  verifying: boolean
  verified: boolean
}) {
  return (
    <tr className="border-b last:border-0">
      <td className="px-3 py-2 font-mono text-xs">{archive.id}</td>
      <td className="px-3 py-2">{formatTime(archive.created_at)}</td>
      <td className="px-3 py-2 font-mono text-xs">{archive.index}</td>
      <td className="px-3 py-2 text-muted-foreground">{archive.reason ?? '—'}</td>
      <td className="px-3 py-2 text-xs text-muted-foreground">{describeArchive(archive)}</td>
      <td className="px-3 py-2 text-right">
        <button
          type="button"
          onClick={onVerify}
          disabled={verifying}
          className="rounded-md border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50"
        >
          {verifying ? 'Checking…' : verified ? 'Intact' : 'Verify'}
        </button>
      </td>
    </tr>
  )
}

function Replication({ status }: { status: ReplicationStatus }) {
  const stale = isStale(status.last_segment_at)
  return (
    <div className="rounded-md border p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-sm font-medium">Replication</span>
        <Badge variant={status.failures > 0 || stale ? 'error' : 'ok'}>
          {status.failures > 0 ? `${status.failures} failure(s)` : stale ? 'stale' : 'healthy'}
        </Badge>
      </div>
      <dl className="mt-2 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
        <Field label="Destination" value={status.sink || 'not configured'} mono />
        <Field label="Shipped to index" value={String(status.shipped_to)} mono />
        <Field label="Last snapshot" value={when(status.last_snapshot_at)} />
        <Field label="Last change segment" value={when(status.last_segment_at)} />
      </dl>
      {stale ? (
        <p className="mt-2 text-xs text-destructive">
          Changes have not shipped recently. The RPO target is five minutes; anything
          written since the last segment would be lost.
        </p>
      ) : null}
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? 'font-mono text-xs' : ''}>{value}</dd>
    </div>
  )
}
