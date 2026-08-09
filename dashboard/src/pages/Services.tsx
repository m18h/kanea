import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import { StatusDot } from '@/components/StatusDot'
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
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'

/** When a service declares no p95 target, red starts here. */
const defaultP95AlarmMs = 500

/** Services lists what is declared and how much of it is actually running. */
export function Services() {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  const list = services.data?.services ?? []
  const byService = groupAllocs(allocs.data?.allocs ?? [])
  const pager = usePagination(list)

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
      ) : !services.connected ? (
        <Card className="p-4 text-sm text-muted-foreground">Connecting…</Card>
      ) : list.length === 0 ? (
        <Card className="p-4 text-sm text-muted-foreground">Nothing deployed yet.</Card>
      ) : (
        <Card className="py-2">
          <Table>
            <THead>
              <tr>
                <TH className="pt-2">Service</TH>
                <TH className="pt-2">Status</TH>
                <TH className="pt-2">Allocs</TH>
                <TH className="pt-2">CPU</TH>
                <TH className="pt-2">Mem</TH>
                <TH className="pt-2">RPS</TH>
                <TH className="pt-2">P95</TH>
                <TH className="pt-2">Autoscale</TH>
              </tr>
            </THead>
            <TBody>
              {pager.pageItems.map((svc) => (
                <ServiceRow
                  key={`${svc.Project}/${svc.Service}`}
                  service={svc}
                  allocs={byService.get(`${svc.Project}/${svc.Service}`) ?? []}
                />
              ))}
            </TBody>
          </Table>
          <div className="px-3">
            <PaginationControls state={pager} />
          </div>
        </Card>
      )}
    </div>
  )
}

function ServiceRow({ service, allocs }: { service: Service; allocs: Alloc[] }) {
  const running = allocs.filter((a) => a.state === 'running').length
  const status = serviceStatusTone(serviceHealth(service, allocs))
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
