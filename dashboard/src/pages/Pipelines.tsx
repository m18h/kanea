import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import { FilterChips } from '@/components/FilterChips'
import { SortHeader } from '@/components/SortHeader'
import { Link } from '@/lib/router'
import { fetchRuns, isRunFinished, type Run } from '@/lib/api'
import { runStateLabel, runStateVariant, runDuration, runDurationMs, shortSHA } from '@/lib/pipelines'
import { matchesQuery } from '@/lib/search'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { sortItems, useSort } from '@/hooks/useSort'

/** The wire states as chips, labelled the way the status pills read
 * (runStateLabel): a running run is "building", a succeeded one is "ok". */
const stateFilters = [
  { value: 'all', label: 'all' },
  { value: 'running', label: 'building' },
  { value: 'queued', label: 'queued' },
  { value: 'succeeded', label: 'ok' },
  { value: 'failed', label: 'failed' },
  { value: 'cancelled', label: 'cancelled' },
] as const
type StateFilter = (typeof stateFilters)[number]['value']

/** Ascending status sort reads live-first, then what needs attention. */
const stateRank: Record<string, number> = {
  running: 0,
  queued: 1,
  failed: 2,
  succeeded: 3,
  cancelled: 4,
}

type SortKey = 'repository' | 'status' | 'duration'

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

  const [query, setQuery] = useState('')
  const [state, setState] = useState<StateFilter>('all')
  const sort = useSort<SortKey>()

  const list = runs.data ?? []
  const filtered = list.filter(
    (run) =>
      (state === 'all' || run.state === state) &&
      matchesQuery(
        query,
        `${run.project}/${run.service}`,
        run.ref,
        run.commit,
        run.trigger,
        run.triggered_by,
      ),
  )
  const sorted = sortItems(filtered, sort, {
    repository: (run) => `${run.project}/${run.service}`,
    status: (run) => stateRank[run.state],
    duration: (run) => runDurationMs(run),
  })
  const pager = usePagination(sorted, {
    resetKey: `${query} ${state} ${sort.key ?? ''} ${sort.dir}`,
  })
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
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <FilterChips options={stateFilters} value={state} onChange={setState} />
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search repo, ref or commit…"
              aria-label="Search pipeline runs"
              className="h-8 w-56 text-xs"
            />
          </div>

          {sorted.length === 0 ? (
            <Card className="p-4 text-sm text-muted-foreground">No runs match that filter.</Card>
          ) : (
            <Card className="py-2">
              <Table>
                <THead>
                  <tr>
                    <SortHeader sort={sort} sortKey="repository" className="pt-2">
                      Repository
                    </SortHeader>
                    <TH className="pt-2">Trigger</TH>
                    <TH className="pt-2">Commit</TH>
                    <SortHeader sort={sort} sortKey="status" className="pt-2">
                      Status
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="duration" className="pt-2">
                      Duration
                    </SortHeader>
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
        </>
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
