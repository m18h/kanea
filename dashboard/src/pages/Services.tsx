import { useState } from 'react'
import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { TableSkeleton } from '@/components/Skeletons'
import { Input } from '@/components/ui/input'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import { StatusDot } from '@/components/StatusDot'
import { FilterChips } from '@/components/FilterChips'
import { SortHeader } from '@/components/SortHeader'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import {
  Topic,
  allocsResponseSchema,
  servicesResponseSchema,
  statsSampleSchema,
  type Alloc,
  type Service,
} from '@/lib/api'
import {
  formatBytes,
  formatMetric,
  groupAllocs,
  serviceHealth,
  serviceStatusTone,
} from '@/lib/state'
import { matchesQuery } from '@/lib/search'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { sortItems, useSort } from '@/hooks/useSort'

/** When a service declares no p95 target, red starts here. */
const defaultP95AlarmMs = 500

/** The status words serviceStatusTone can produce, as filter chips. */
const statusFilters = [
  { value: 'all', label: 'all' },
  { value: 'running', label: 'running' },
  { value: 'scaling', label: 'scaling' },
  { value: 'degraded', label: 'degraded' },
  { value: 'stopped', label: 'stopped' },
] as const
type StatusFilter = (typeof statusFilters)[number]['value']

/** Ascending status sort reads problems-first: the reader clicking it is
 * looking for what is wrong, not for the alphabet. */
const statusRank: Record<string, number> = { degraded: 0, scaling: 1, running: 2, stopped: 3 }

type SortKey = 'service' | 'status' | 'allocs'

/** Services lists what is declared and how much of it is actually running. */
export function Services() {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const sort = useSort<SortKey>()

  // Functions are services underneath (v1.39) but have a page of their own —
  // one record, shown as what it is, on exactly one list.
  const list = (services.data?.services ?? []).filter((s) => s.function == null)
  const byService = groupAllocs(allocs.data?.allocs ?? [])

  // Status is computed once per service, up here, because filtering and
  // sorting need it before any row renders. The stats columns (CPU, mem, RPS,
  // P95) are deliberately not sortable: each row holds its own bounded stats
  // subscription, so the page never has those numbers to sort by.
  const rows = list.map((svc) => {
    const svcAllocs = byService.get(`${svc.Project}/${svc.Service}`) ?? []
    return { svc, allocs: svcAllocs, status: serviceStatusTone(serviceHealth(svc, svcAllocs)) }
  })
  const filtered = rows.filter(
    (row) =>
      (status === 'all' || row.status.word === status) &&
      matchesQuery(query, `${row.svc.Project}/${row.svc.Service}`, row.svc.Image),
  )
  const sorted = sortItems(filtered, sort, {
    service: (row) => `${row.svc.Project}/${row.svc.Service}`,
    status: (row) => statusRank[row.status.word],
    allocs: (row) => row.allocs.filter((a) => a.state === 'running').length,
  })
  const pager = usePagination(sorted, {
    resetKey: `${query} ${status} ${sort.key ?? ''} ${sort.dir}`,
  })

  const allocCount = allocs.data?.allocs?.length ?? 0

  return (
    <div className="space-y-4">
      <PageHeader
        title="Services"
        subtitle={`${list.length} service${list.length === 1 ? '' : 's'} · ${allocCount} alloc${allocCount === 1 ? '' : 's'}`}
        actions={
          <Link to="/services/new">
            <Button className="font-semibold">Deploy service</Button>
          </Link>
        }
      />

      {services.error ? (
        <Card className="p-4 text-sm text-destructive">{services.error}</Card>
      ) : !services.connected && !services.data ? (
        <TableSkeleton rows={6} cols={8} />
      ) : list.length === 0 ? (
        <Card className="p-4 text-sm text-muted-foreground">Nothing deployed yet.</Card>
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <FilterChips options={statusFilters} value={status} onChange={setStatus} />
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search name or image…"
              aria-label="Search services"
              className="h-8 w-56 text-xs"
            />
          </div>

          {sorted.length === 0 ? (
            // Distinct from "nothing deployed": services exist, the filter
            // hides all of them, and only one of those is fixed by deploying.
            <Card className="p-4 text-sm text-muted-foreground">
              No services match that filter.
            </Card>
          ) : (
            <Card className="py-2">
              <Table>
                <THead>
                  <tr>
                    <SortHeader sort={sort} sortKey="service" className="pt-2">
                      Service
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="status" className="pt-2">
                      Status
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="allocs" className="pt-2">
                      Allocs
                    </SortHeader>
                    <TH className="pt-2">CPU</TH>
                    <TH className="pt-2">Mem</TH>
                    <TH className="pt-2">RPS</TH>
                    <TH className="pt-2">P95</TH>
                    <TH className="pt-2">Autoscale</TH>
                  </tr>
                </THead>
                <TBody>
                  {pager.pageItems.map((row) => (
                    <ServiceRow
                      key={`${row.svc.Project}/${row.svc.Service}`}
                      service={row.svc}
                      allocs={row.allocs}
                      status={row.status}
                    />
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
    </div>
  )
}

function ServiceRow({
  service,
  allocs,
  status,
}: {
  service: Service
  allocs: Alloc[]
  status: ReturnType<typeof serviceStatusTone>
}) {
  const running = allocs.filter((a) => a.state === 'running').length
  const metrics = service.Scaling?.metrics ?? []

  return (
    <TR>
      <TD>
        <Link to={`/services/${service.Project}/${service.Service}`} className="group block">
          <span className="font-medium group-hover:underline">
            {service.Project}/{service.Service}
          </span>
          {/* Every value here comes from a job spec and is rendered as text. */}
          <span className="block font-mono text-xs text-muted-foreground">{service.Image}</span>
        </Link>
      </TD>
      <TD>
        <StatusDot tone={status.tone} label={status.word} />
      </TD>
      <TD className="font-mono tabular-nums">
        {running}/{service.Count}
      </TD>
      <StatsCells project={service.Project} service={service.Service} p95Target={p95Target(service)} />
      <TD>
        {metrics.length > 0 ? (
          <Badge variant="accent" className="font-mono text-[11px]">
            {metrics.map((m) => m.name).join(' · ')}
          </Badge>
        ) : (
          <span className="font-mono text-xs text-muted-foreground">off</span>
        )}
      </TD>
    </TR>
  )
}

/** p95Target is the point where the table paints latency red: a quarter over
 * the service's own declared target, or a fixed alarm when it declares none. */
function p95Target(service: Service): number {
  const rule = service.Scaling?.metrics?.find((m) => m.name === 'p95')
  return rule ? rule.target * 1.25 : defaultP95AlarmMs
}

/** memoryText prefers real bytes (summed across allocs) over percent-of-limit,
 * and a dash over either when nothing was measured. */
function memoryText(s: { memory?: number | undefined; allocs?: { memory_bytes?: number | undefined }[] | null | undefined } | null): string {
  const bytes = (s?.allocs ?? []).reduce<number | undefined>(
    (sum, a) => (a.memory_bytes === undefined ? sum : (sum ?? 0) + a.memory_bytes),
    undefined,
  )
  if (bytes !== undefined) return formatBytes(bytes)
  if (s?.memory !== undefined) return formatMetric(s.memory, '%')
  return '—'
}

/**
 * StatsCells is per-row so each row holds its own stats subscription. The page
 * is bounded by pagination (10 by default, at most 100), and every
 * subscription rides the one shared socket — a bounded cost for live numbers
 * in the table.
 */
function StatsCells({
  project,
  service,
  p95Target,
}: {
  project: string
  service: string
  p95Target: number
}) {
  const stats = useLiveTopic({ topic: Topic.Stats, project, service }, statsSampleSchema)
  const s = stats.data

  // A dash for a gap, never a zero: "no data" and "no load" are different
  // facts, and each column renders the difference.
  return (
    <>
      <TD className="font-mono tabular-nums">
        {s?.cpu === undefined ? '—' : formatMetric(s.cpu, '%')}
      </TD>
      <TD className="font-mono tabular-nums">{memoryText(s)}</TD>
      <TD className="font-mono tabular-nums">{s?.rps === undefined ? '—' : Math.round(s.rps)}</TD>
      <TD
        className={`font-mono tabular-nums ${
          s?.p95_latency_ms !== undefined && s.p95_latency_ms > p95Target ? 'text-status-error' : ''
        }`}
      >
        {s?.p95_latency_ms === undefined ? '—' : formatMetric(s.p95_latency_ms, ' ms')}
      </TD>
    </>
  )
}
