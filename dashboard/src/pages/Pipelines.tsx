import { useQuery } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import { Link } from '@/lib/router'
import { fetchRuns, isRunFinished, type Run } from '@/lib/api'
import { runStateLabel, runStateVariant, runDuration, shortSHA } from '@/lib/pipelines'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'

/**
 * The pipeline list (PRD §10.2).
 *
 * Polled rather than live: a build takes minutes and the list changes when one
 * starts or ends, so a few seconds of staleness is invisible. Adding a
 * websocket topic for it would put a subscription on the daemon for a page that
 * is mostly still.
 */
export function Pipelines() {
  const runs = useQuery({
    queryKey: ['runs'],
    // 200, not 50: the list paginates client-side now, and a bounded page of
    // history is exactly what "why did Tuesday's deploy fail" needs.
    queryFn: ({ signal }) => fetchRuns({ limit: 200 }, signal),
    // Faster while something is running: an operator watching a build wants to
    // see it move, and once everything is finished there is nothing to see.
    refetchInterval: (query) =>
      (query.state.data ?? []).some((run) => !isRunFinished(run)) ? 2_000 : 15_000,
  })

  const list = runs.data ?? []
  const pager = usePagination(list)
  // The queue serialises builds and refuses when full (§10.2): one slot, in
  // use whenever a run is going.
  const building = list.some((run) => run.state === 'running')

  return (
    <div className="space-y-4">
      <PageHeader
        title="Pipelines"
        subtitle="in-process git sync · rootless BuildKit"
        actions={
          <Badge variant={building ? 'outline-warn' : 'muted'} className="font-mono">
            Build slots {building ? 1 : 0} / 1 {building ? 'in use' : 'idle'}
          </Badge>
        }
      />

      {runs.isError ? (
        <Card className="p-4 text-sm text-muted-foreground">Could not read pipeline runs.</Card>
      ) : list.length === 0 ? (
        <Card className="p-4 text-sm text-muted-foreground">
          No builds yet. A service with a <span className="font-mono">build</span> block builds on
          a push to its watched branch, or on <span className="font-mono">kanea build</span>.
        </Card>
      ) : (
        <Card className="py-2">
          <Table>
            <THead>
              <tr>
                <TH className="pt-2">Repository</TH>
                <TH className="pt-2">Trigger</TH>
                <TH className="pt-2">Commit</TH>
                <TH className="pt-2">Status</TH>
                <TH className="pt-2">Duration</TH>
              </tr>
            </THead>
            <TBody>
              {pager.pageItems.map((run) => (
                <RunRow key={`${run.project}/${run.service}/${run.id}`} run={run} />
              ))}
            </TBody>
          </Table>
          <div className="px-3">
            <PaginationControls state={pager} />
          </div>
        </Card>
      )}

      <Card className="flex items-center gap-2.5 p-3 text-sm text-muted-foreground">
        <ShieldCheck size={16} aria-hidden className="shrink-0" />
        <span>
          Webhooks verified with HMAC · builds are refused when the slot is busy, never silently
          queued
        </span>
      </Card>
    </div>
  )
}

function RunRow({ run }: { run: Run }) {
  return (
    <TR>
      <TD className="font-mono">
        <Link
          to={`/pipelines/${encodeURIComponent(run.project)}/${encodeURIComponent(
            run.service,
          )}/${encodeURIComponent(run.id)}`}
          className="hover:underline"
        >
          {run.project}/{run.service}
        </Link>
      </TD>
      <TD className="text-muted-foreground">
        {run.trigger}
        {run.triggered_by ? ` · ${run.triggered_by}` : ''}
      </TD>
      <TD className="font-mono text-muted-foreground">
        {/* ref @ sha, not a commit message: runs do not store one, and the
            checkout is identified by exactly these two facts. */}
        {run.ref ? `${run.ref} @ ` : ''}
        {shortSHA(run.commit)}
      </TD>
      <TD>
        <Badge variant={runStateVariant(run.state)} className="font-mono text-[11px]">
          {runStateLabel(run.state)}
        </Badge>
      </TD>
      <TD className="font-mono tabular-nums text-muted-foreground">{runDuration(run)}</TD>
    </TR>
  )
}
