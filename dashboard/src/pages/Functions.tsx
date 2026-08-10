import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import { FilterChips } from '@/components/FilterChips'
import { SortHeader } from '@/components/SortHeader'
import { StatTile } from '@/components/StatTile'
import { StatusDot } from '@/components/StatusDot'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { sortItems, useSort } from '@/hooks/useSort'
import {
  Topic,
  fetchFunctions,
  statsSampleSchema,
  type FunctionView,
} from '@/lib/api'
import { matchesQuery } from '@/lib/search'
import { formatBytes, formatMetric } from '@/lib/state'

/** The statuses internal/api's functions route derives (active / idle /
 * trapping / stopped), as chips. */
const statusFilters = [
  { value: 'all', label: 'all' },
  { value: 'active', label: 'active' },
  { value: 'idle', label: 'idle' },
  { value: 'trapping', label: 'trapping' },
  { value: 'stopped', label: 'stopped' },
] as const
type StatusFilter = (typeof statusFilters)[number]['value']

/** Ascending status sort reads problems-first. */
const statusRank: Record<string, number> = { trapping: 0, active: 1, idle: 2, stopped: 3 }

type SortKey = 'function' | 'invocations' | 'memory' | 'status'

/**
 * Functions (v1.39): wasm functions — services underneath, so detail, restart
 * and scale all live on the service pages; this page is what makes them
 * findable as what they are. The invocation rate is the datapath's connect
 * counter (§9.1): it sees east-west calls and invoker POSTs the edge never
 * does, and a dash means "not measured", never zero.
 */
export function Functions() {
  const functions = useQuery({
    queryKey: ['functions'],
    queryFn: ({ signal }) => fetchFunctions(signal),
    refetchInterval: 10_000,
  })

  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const sort = useSort<SortKey>()

  const list = functions.data?.functions ?? []
  const filtered = list.filter(
    (fn) =>
      (status === 'all' || fn.status === status) &&
      matchesQuery(query, `${fn.project}/${fn.service}`, fn.module),
  )
  const sorted = sortItems(filtered, sort, {
    function: (fn) => `${fn.project}/${fn.service}`,
    // "No datapath sample" sorts after every measured rate, both ways.
    invocations: (fn) => fn.invocations_per_minute,
    memory: (fn) => fn.memory_bytes,
    status: (fn) => statusRank[fn.status],
  })
  const pager = usePagination(sorted, {
    resetKey: `${query} ${status} ${sort.key ?? ''} ${sort.dir}`,
  })

  // The tiles summarise everything declared, not the filtered view: "Active
  // 3/9" must not become "3/3" because the reader is looking at a subset.
  const measured = list.filter((f) => f.invocations_per_minute !== undefined)
  const totalRate = measured.reduce((sum, f) => sum + (f.invocations_per_minute ?? 0), 0)
  const active = list.filter((f) => f.status === 'active').length
  const failures = list.reduce((sum, f) => sum + (f.invoker?.failures ?? 0), 0)
  const dropped = functions.data?.invoker_dropped ?? 0

  return (
    <div className="space-y-4">
      <PageHeader
        title="Functions"
        subtitle="WASM · wasmtime · long-running wasi-http services"
        actions={
          <Link to="/services/new">
            <Button className="font-semibold">Deploy function</Button>
          </Link>
        }
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <StatTile
          label="Invocations / min"
          value={measured.length > 0 ? Math.round(totalRate).toLocaleString() : '—'}
          sub={
            measured.length > 0
              ? `across ${measured.length} measured function${measured.length === 1 ? '' : 's'}`
              : 'no datapath samples yet'
          }
        />
        <StatTile
          label="Active"
          value={`${active}/${list.length}`}
          sub="running · healthy where probed"
          tone={list.length > 0 && active === list.length ? 'ok' : 'default'}
        />
        <StatTile
          label="Invoker failures"
          value={failures}
          sub={dropped > 0 ? `${dropped} events dropped by the queue` : 'retries exhausted, total'}
          tone={failures > 0 || dropped > 0 ? 'error' : 'default'}
        />
      </div>

      {functions.error ? (
        <Card className="p-4 text-sm text-destructive">{String(functions.error)}</Card>
      ) : functions.isPending ? (
        <Card className="p-4 text-sm text-muted-foreground">Loading…</Card>
      ) : list.length === 0 ? (
        <Card className="p-4 text-sm text-muted-foreground">
          No functions yet. A <code className="font-mono">function</code> block in a job spec
          declares one — a wasm module the platform runs for you.
        </Card>
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <FilterChips options={statusFilters} value={status} onChange={setStatus} />
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search name or module…"
              aria-label="Search functions"
              className="h-8 w-56 text-xs"
            />
          </div>

          {sorted.length === 0 ? (
            <Card className="p-4 text-sm text-muted-foreground">
              No functions match that filter.
            </Card>
          ) : (
            <Card className="py-2">
              <Table>
                <THead>
                  <tr>
                    <SortHeader sort={sort} sortKey="function" className="pt-2">
                      Function
                    </SortHeader>
                    <TH className="pt-2">Trigger</TH>
                    <SortHeader sort={sort} sortKey="invocations" className="pt-2">
                      Inv/min
                    </SortHeader>
                    {/* P95 rides a per-row stats subscription; the page never
                        holds it, so it cannot sort by it. */}
                    <TH className="pt-2">P95</TH>
                    <SortHeader sort={sort} sortKey="memory" className="pt-2">
                      Mem cap
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="status" className="pt-2">
                      Status
                    </SortHeader>
                  </tr>
                </THead>
                <TBody>
                  {pager.pageItems.map((fn) => (
                    <FunctionRow key={`${fn.project}/${fn.service}`} fn={fn} />
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

      <p className="text-xs text-muted-foreground">
        Functions run on the wasmtime shim in a deny-by-default sandbox: filesystem, devices and
        host sockets are refused at the spec (R25). Memory caps are cgroup limits — real, not
        advisory.
      </p>
    </div>
  )
}

function FunctionRow({ fn }: { fn: FunctionView }) {
  const tone =
    fn.status === 'active'
      ? ('ok' as const)
      : fn.status === 'trapping'
        ? ('error' as const)
        : ('muted' as const)

  return (
    <TR>
      <TD>
        {/* A function is a service underneath: the detail page is the service's. */}
        <Link to={`/services/${fn.project}/${fn.service}`} className="group block">
          <span className="font-medium group-hover:underline">
            {fn.project}/{fn.service}
          </span>
          {/* Module refs come from a job spec and render as text (§14 A03). */}
          <span className="block font-mono text-xs text-muted-foreground">{fn.module}</span>
        </Link>
      </TD>
      <TD>
        <TriggerChips fn={fn} />
      </TD>
      <TD className="font-mono tabular-nums">
        {fn.invocations_per_minute === undefined ? '—' : Math.round(fn.invocations_per_minute)}
      </TD>
      <P95Cell project={fn.project} service={fn.service} />
      <TD className="font-mono tabular-nums">{formatBytes(fn.memory_bytes)}</TD>
      <TD>
        <StatusDot tone={tone} label={fn.status} />
      </TD>
    </TR>
  )
}

/** TriggerChips renders each declared trigger the way the spec means it. */
function TriggerChips({ fn }: { fn: FunctionView }) {
  const chips: string[] = []
  if (fn.http) {
    chips.push(fn.domains && fn.domains.length > 0 ? `http · ${fn.domains[0]}` : 'http')
  }
  for (const ev of fn.events ?? []) chips.push(`event · ${ev.on.join(', ')}`)
  for (const cr of fn.crons ?? []) chips.push(`cron · ${cr.schedule}`)
  if (chips.length === 0) return <span className="font-mono text-xs text-muted-foreground">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {chips.map((chip) => (
        <Badge key={chip} variant="accent" className="font-mono text-[11px]">
          {chip}
        </Badge>
      ))}
    </div>
  )
}

/** P95Cell rides the same stats topic the Services page uses — a function is a
 * service, so its latency series already exists. */
function P95Cell({ project, service }: { project: string; service: string }) {
  const stats = useLiveTopic({ topic: Topic.Stats, project, service }, statsSampleSchema)
  const p95 = stats.data?.p95_latency_ms
  return (
    <TD className="font-mono tabular-nums">
      {p95 === undefined ? '—' : formatMetric(p95, ' ms')}
    </TD>
  )
}
