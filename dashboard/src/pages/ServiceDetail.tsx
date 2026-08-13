import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Pencil, Play, RotateCw, Square } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ChartSkeleton, TableSkeleton } from '@/components/Skeletons'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { BackChip } from '@/components/BackChip'
import { EventRow } from '@/components/EventRow'
import { KeyValue } from '@/components/KeyValue'
import { LogViewer } from '@/components/LogViewer'
import { MetricChartPanel } from '@/components/MetricChartPanel'
import { PageHeader } from '@/components/PageHeader'
import { Sparkline } from '@/components/Sparkline'
import { StatusDot } from '@/components/StatusDot'
import { useLiveLog, MaxLogLines } from '@/hooks/useLiveLog'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { useSession } from '@/hooks/useSession'
import { useSeries, useTimedSeries } from '@/hooks/useSeries'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { Link } from '@/lib/router'
import {
  Topic,
  allocsResponseSchema,
  fetchEvents,
  fetchStatsHistory,
  restartService,
  scaleService,
  servicesResponseSchema,
  statsSampleSchema,
  type Alloc,
  type AllocStats,
  type EdgeBreakdown,
  type KaneaEvent,
  type Service,
  type StatsHistory,
  type StatsSample,
} from '@/lib/api'
import { parseScaleDecision } from '@/lib/events'
import {
  allocStateVariant,
  formatBytes,
  formatClock,
  groupAllocs,
  groupCodes,
  relativeAge,
  serviceHealth,
  serviceStatusTone,
} from '@/lib/state'

/** How long a live "no such service" answer must hold before it is believed. */
const notFoundGraceMs = 750

export function ServiceDetail({ project, service }: { project: string; service: string }) {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)
  const stats = useLiveTopic({ topic: Topic.Stats, project, service }, statsSampleSchema)

  const events = useQuery({
    queryKey: ['events', project],
    queryFn: ({ signal }) => fetchEvents({ project, limit: 100 }, signal),
    refetchInterval: 15_000,
  })

  // Seed once and never refetch: live samples take over from where the
  // history ends, and re-fetching would splice the same window twice.
  const seed = useQuery({
    queryKey: ['stats-history', project, service],
    queryFn: ({ signal }) => fetchStatsHistory({ project, service }, signal),
    staleTime: Infinity,
    retry: false,
  })

  const key = `${project}/${service}`
  const desired = (services.data?.services ?? []).find(
    (s) => s.Project === project && s.Service === service,
  )
  const mine = groupAllocs(allocs.data?.allocs ?? []).get(key) ?? []
  const allocPager = usePagination(mine)

  // "Not found" only after the absence has held for a moment on a live
  // connection. A reconnect's first frames can briefly disagree with the
  // store, and flashing a Not-found card over a service that exists reads as
  // an outage.
  const missing = services.connected && services.data !== null && !desired
  const [notFound, setNotFound] = useState(false)
  // Render-time reset (the documented derived-state pattern): the moment the
  // service is back, the verdict is void.
  if (!missing && notFound) setNotFound(false)
  useEffect(() => {
    if (!missing) return
    const timer = setTimeout(() => setNotFound(true), notFoundGraceMs)
    return () => clearTimeout(timer)
  }, [missing])

  if (notFound) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Not found</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          No service <span className="font-mono">{key}</span> is deployed.
        </CardContent>
      </Card>
    )
  }

  // Still connecting: hold the page's shape with skeletons rather than
  // rendering four empty panels that pop full a beat later.
  if (!services.data && !desired) {
    return (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <BackChip to="/services">Services</BackChip>
          <PageHeader title={<span className="font-mono">{service}</span>} subtitle={key} />
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <Card key={i} className="p-4">
              <ChartSkeleton big />
            </Card>
          ))}
        </div>
        <TableSkeleton rows={3} cols={6} />
      </div>
    )
  }

  const health = desired ? serviceHealth(desired, mine) : null
  const status = health ? serviceStatusTone(health) : null
  const myEvents = (events.data?.events ?? []).filter(
    (e) => !e.service || e.service === service,
  )

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <BackChip to="/services">Services</BackChip>
        <PageHeader
          title={<span className="font-mono">{service}</span>}
          subtitle={
            <span className="inline-flex items-center gap-3">
              {status ? <StatusDot tone={status.tone} label={status.word} /> : null}
              <span>{desired?.Image ?? ''}</span>
            </span>
          }
        />
        <div className="ml-auto">
          {desired ? <ServiceActions project={project} service={service} desired={desired} /> : null}
        </div>
      </div>

      <StatsPanel sample={stats.data} history={seed.data ?? null} />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Allocations</CardTitle>
            </CardHeader>
            <CardContent>
              {mine.length === 0 ? (
                <p className="text-sm text-muted-foreground">No allocations.</p>
              ) : (
                <Table>
                  <THead>
                    <tr>
                      <TH className="pl-0">Allocation</TH>
                      <TH>State</TH>
                      <TH>CPU</TH>
                      <TH>Mem</TH>
                      <TH>Restarts</TH>
                      <TH>Age</TH>
                    </tr>
                  </THead>
                  <TBody>
                    {allocPager.pageItems.map((alloc) => (
                      <AllocRow
                        key={alloc.id}
                        alloc={alloc}
                        stats={(stats.data?.allocs ?? []).find((a) => a.alloc_id === alloc.id)}
                        at={stats.data?.at ?? ''}
                      />
                    ))}
                  </TBody>
                </Table>
              )}
              <PaginationControls state={allocPager} />
            </CardContent>
          </Card>

          <LogPanel project={project} service={service} />

          <EdgePanel edge={stats.data?.edge} />
        </div>

        <div className="space-y-4">
          <AutoscalePanel desired={desired} events={myEvents} />
          <SpecPanel desired={desired} />
          <Card>
            <CardHeader>
              <CardTitle>Recent events</CardTitle>
            </CardHeader>
            <CardContent>
              {myEvents.length === 0 ? (
                <p className="text-sm text-muted-foreground">Nothing recorded yet.</p>
              ) : (
                myEvents.slice(0, 5).map((e) => <EventRow key={e.id} event={e} />)
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

/**
 * ServiceActions is the lifecycle row: edit spec, start, stop, restart.
 *
 * Stop and start are scales (to zero and back), restart bumps the generation —
 * every button writes desired state and the reconciler converges, so nothing
 * here is a second path to the runtime. The buttons stay visible for a viewer
 * but disabled: a viewer who does not know they are a viewer reads a missing
 * button as a broken dashboard.
 */
function ServiceActions({
  project,
  service,
  desired,
}: {
  project: string
  service: string
  desired: Service
}) {
  const { session, csrf } = useSession()
  const admin = session?.role === 'admin'

  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmStop, setConfirmStop] = useState(false)

  // What "start" should scale back to: the last non-zero count this page saw.
  // The daemon does not remember it — a stopped service's record says zero —
  // so this is a courtesy with a safe fallback of one.
  const lastCount = useRef(1)
  useEffect(() => {
    if (desired.Count > 0) lastCount.current = desired.Count
  }, [desired.Count])

  // An armed stop disarms itself: a button left reading "confirm stop?" for
  // minutes is a trap for the next person at the keyboard.
  useEffect(() => {
    if (!confirmStop) return
    const timer = setTimeout(() => setConfirmStop(false), 4000)
    return () => clearTimeout(timer)
  }, [confirmStop])

  const run = (name: string, action: () => Promise<void>) => {
    setBusy(name)
    setError(null)
    action()
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(null))
  }

  const stopped = desired.Count === 0
  const disabled = !admin || busy !== null
  const title = admin ? undefined : 'Requires the admin role'

  return (
    <div className="flex items-center gap-2">
      {error ? (
        <span className="max-w-64 truncate text-xs text-destructive" title={error}>
          {error}
        </span>
      ) : null}
      <Link to={`/services/${project}/${service}/edit`}>
        <Button size="sm" variant="outline">
          <Pencil size={14} />
          Edit spec
        </Button>
      </Link>
      {stopped ? (
        <Button
          size="sm"
          disabled={disabled}
          title={title}
          onClick={() => run('start', () => scaleService(project, service, lastCount.current, csrf))}
        >
          <Play size={14} />
          {busy === 'start' ? 'Starting…' : 'Start'}
        </Button>
      ) : (
        <>
          <Button
            size="sm"
            variant="outline"
            disabled={disabled}
            title={title}
            onClick={() => run('restart', () => restartService(project, service, csrf))}
          >
            <RotateCw size={14} />
            {busy === 'restart' ? 'Restarting…' : 'Restart'}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={disabled}
            title={title}
            className={confirmStop ? 'border-destructive text-destructive hover:bg-destructive/10' : ''}
            onClick={() => {
              if (!confirmStop) {
                setConfirmStop(true)
                return
              }
              setConfirmStop(false)
              run('stop', () => scaleService(project, service, 0, csrf))
            }}
          >
            <Square size={14} />
            {busy === 'stop' ? 'Stopping…' : confirmStop ? 'Confirm stop?' : 'Stop'}
          </Button>
        </>
      )}
    </div>
  )
}

/** AutoscalePanel renders the declared policy and the last decision. */
function AutoscalePanel({
  desired,
  events,
}: {
  desired: Service | undefined
  events: KaneaEvent[]
}) {
  const policy = desired?.Scaling
  const metrics = policy?.metrics ?? []
  const lastDecision = events.map(parseScaleDecision).find((d) => d !== null)

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle>Autoscale</CardTitle>
        {metrics.length > 0 ? (
          <Badge variant="accent" className="font-mono text-[11px]">
            {metrics.map((m) => m.name).join(' · ')}
          </Badge>
        ) : (
          <span className="font-mono text-xs text-muted-foreground">off</span>
        )}
      </CardHeader>
      <CardContent>
        {metrics.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No scaling rules declared. The count is whatever the spec (or an
            operator) says.
          </p>
        ) : (
          <>
            <KeyValue label="Signals" mono>
              {metrics.map((m) => m.name).join(' · ')}
            </KeyValue>
            <KeyValue label="Targets" mono>
              {metrics.map((m) => `${m.name} ≤ ${m.target}${metricUnit(m.name)}`).join(' · ')}
            </KeyValue>
            <KeyValue label="Bounds" mono>
              min {policy?.min ?? 0} · max {policy?.max ?? 0}
            </KeyValue>
            <KeyValue label="Last decision" mono>
              {lastDecision ? (
                <span className="text-status-ok">
                  {lastDecision.from !== undefined && lastDecision.to !== undefined
                    ? `${lastDecision.from} → ${lastDecision.to} · `
                    : ''}
                  {formatClock(lastDecision.at)}
                </span>
              ) : (
                <span className="text-muted-foreground">none recorded</span>
              )}
            </KeyValue>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function metricUnit(name: string): string {
  if (name === 'p95' || name === 'p50' || name === 'p99') return 'ms'
  if (name === 'cpu' || name === 'memory') return '%'
  return ''
}

/** SpecPanel is the declared record, key facts only. */
function SpecPanel({ desired }: { desired: Service | undefined }) {
  if (!desired) return null
  const publish = desired.Publish ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Spec</CardTitle>
      </CardHeader>
      <CardContent>
        <KeyValue label="Image" mono>
          <span className="break-all">{desired.Image}</span>
        </KeyValue>
        <KeyValue label="Replicas" mono>
          {desired.Count}
        </KeyValue>
        <KeyValue label="Resources" mono>
          {/* Zero means unbounded (R11, v1.58) — "0m · 0 B" would read as
              nothing allowed when it means everything available. */}
          {desired.Resources.CPUMillis > 0 ? `${desired.Resources.CPUMillis}m` : "all cores"} ·{" "}
          {desired.Resources.MemoryBytes > 0 ? formatBytes(desired.Resources.MemoryBytes) : "all memory"}
        </KeyValue>
        {desired.Expose ? (
          <KeyValue label="Expose" mono>
            :{desired.Expose.Port} → edge
          </KeyValue>
        ) : null}
        {desired.Expose ? (
          <KeyValue label="Domains" mono>
            <span className="break-all">
              {(desired.Expose.Domains ?? []).join(', ') || 'auto-generated'}
            </span>
          </KeyValue>
        ) : null}
        {publish.length > 0 ? (
          <KeyValue label="Published" mono>
            {publish.map((p) => `:${p.Host}`).join(' · ')}
          </KeyValue>
        ) : null}
        {(desired.DependsOn ?? []).length > 0 ? (
          <KeyValue label="Depends on" mono>
            {(desired.DependsOn ?? []).join(', ')}
          </KeyValue>
        ) : null}
      </CardContent>
    </Card>
  )
}

/**
 * EdgePanel shows what the edge saw (PRD §9.1.1): the status-code split and
 * the bytes moved.
 *
 * Rendered only when the edge has actually reported this service. A service
 * with no `expose` block is not reachable from outside, and a panel of zeroes
 * for it would read as "nobody is using this" rather than "this was never
 * measured" — the same distinction the metric gauges draw by being absent.
 */
function EdgePanel({ edge }: { edge?: EdgeBreakdown | undefined }) {
  if (!edge) return null

  const classes = groupCodes(edge.codes)
  const total = classes.reduce((sum, c) => sum + c.count, 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Edge traffic</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          {classes.length === 0 ? (
            <span className="text-muted-foreground">No requests recorded yet.</span>
          ) : (
            classes.map((c) => (
              <Badge key={c.klass} variant={c.variant}>
                {c.klass} · {c.count.toLocaleString()}
              </Badge>
            ))
          )}
        </div>
        <dl className="grid gap-4 sm:grid-cols-3">
          <Total label="Requests" value={total.toLocaleString()} />
          <Total label="Received" value={formatBytes(edge.request_bytes)} />
          <Total label="Sent" value={formatBytes(edge.response_bytes)} />
        </dl>
      </CardContent>
    </Card>
  )
}

function Total({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      {/* Cumulative for the life of the edge process, not a rate — the panel
          says "Requests", never "Requests/s", so the two are not confused. */}
      <dd className="font-mono text-sm tabular-nums">{value}</dd>
    </div>
  )
}

/**
 * StatsPanel shows the service-level numbers a scaling rule is written against
 * (PRD §6.1), so the graph and the policy talk about the same quantities.
 */
function StatsPanel({
  sample,
  history,
}: {
  sample: StatsSample | null
  history: StatsHistory | null
}) {
  const at = sample?.at ?? ''
  const cpu = useTimedSeries(sample?.cpu, at, history, 'cpu')
  const memory = useTimedSeries(sample?.memory, at, history, 'memory')
  const rps = useTimedSeries(sample?.rps, at, history, 'rps')
  const p95 = useTimedSeries(sample?.p95_latency_ms, at, history, 'p95_latency_ms')

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* CPU and memory are percentages of the declared limit, so the scale
          is fixed at 100: a flat 2% line and a flat 90% one must not look
          the same. Rate and latency have no natural ceiling and scale to
          their own range. */}
      <Card className="p-4">
        <MetricChartPanel label="CPU" unit="%" series={cpu} scale="percent" latest={sample?.cpu} tone={1} big />
      </Card>
      <Card className="p-4">
        <MetricChartPanel label="Memory" unit="%" series={memory} scale="percent" latest={sample?.memory} tone={2} big />
      </Card>
      <Card className="p-4">
        <MetricChartPanel label="Requests / s" unit="/s" series={rps} scale="auto" latest={sample?.rps} tone={3} big />
      </Card>
      <Card className="p-4">
        <MetricChartPanel label="p95 latency" unit=" ms" series={p95} scale="auto" latest={sample?.p95_latency_ms} tone={4} big />
      </Card>
    </div>
  )
}

/** AllocRow is one alloc, with its own resource history. */
function AllocRow({
  alloc,
  stats,
  at,
}: {
  alloc: Alloc
  stats: AllocStats | undefined
  at: string
}) {
  const cpu = useSeries(stats?.cpu, at)
  const memory = useSeries(stats?.memory, at)
  const tone = allocStateVariant(alloc.state)

  return (
    <TR>
      <TD className="pl-0 font-mono text-xs">{alloc.id}</TD>
      <TD>
        <StatusDot
          tone={tone === 'ok' ? 'ok' : tone === 'warn' ? 'warn' : tone === 'error' ? 'error' : 'muted'}
          label={alloc.state}
        />
      </TD>
      <TD>
        <Sparkline points={cpu} max={100} unit="%" tone={1} className="h-6 w-24" label={`CPU for ${alloc.id}`} />
      </TD>
      <TD>
        <Sparkline points={memory} max={100} unit="%" tone={2} className="h-6 w-24" label={`Memory for ${alloc.id}`} />
      </TD>
      <TD className="font-mono tabular-nums">
        {alloc.restarts ?? 0}
        {alloc.last_exit_at ? (
          <span className="text-muted-foreground"> ({relativeAge(alloc.last_exit_at)})</span>
        ) : null}
      </TD>
      <TD className="font-mono tabular-nums">{relativeAge(alloc.created_at)}</TD>
    </TR>
  )
}

/** LogPanel streams the service's output over the shared socket. */
function LogPanel({ project, service }: { project: string; service: string }) {
  const { lines, error, dropped } = useLiveLog(project, service)
  const [filter, setFilter] = useState('')
  const [follow, setFollow] = useState(true)

  // Memoized: at ten thousand buffered lines the filter is no longer free,
  // and this re-runs on every stats frame otherwise.
  const shown = useMemo(() => {
    if (!filter) return lines
    const needle = filter.toLowerCase()
    return lines.filter((l) => l.line.toLowerCase().includes(needle))
  }, [lines, filter])
  const viewerLines = useMemo(
    () =>
      shown.map((entry, i) => ({
        key: `${entry.alloc_id}-${i}`,
        prefix: allocSuffix(entry.alloc_id),
        text: entry.line,
      })),
    [shown],
  )

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3 space-y-0">
        <div className="flex items-baseline gap-2">
          <CardTitle>Logs</CardTitle>
          <span className="font-mono text-xs text-muted-foreground">tail · all allocs · live</span>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="search"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter"
            aria-label="Filter log lines"
            className="rounded-md border bg-background px-2 py-1 text-xs"
          />
          <label className="flex items-center gap-1 text-xs text-muted-foreground">
            <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
            Follow
          </label>
        </div>
      </CardHeader>
      <CardContent>
        {error ? <p className="pb-2 text-sm text-destructive">{error}</p> : null}
        <LogViewer
          lines={viewerLines}
          live
          follow={follow}
          tintSeverity
          toolbar={{ copy: true, download: { filename: `${project}-${service}.log` } }}
          emptyText={lines.length === 0 ? 'Waiting for output…' : 'No lines match the filter.'}
          notice={
            dropped > 0 ? (
              <p className="pb-2 text-xs text-muted-foreground">
                {dropped} earlier line{dropped === 1 ? '' : 's'} dropped (showing the most recent{' '}
                {MaxLogLines}).
              </p>
            ) : undefined
          }
        />
      </CardContent>
    </Card>
  )
}

/** allocSuffix shortens an alloc id to its index, which is what distinguishes
 * one line from another within a service. */
function allocSuffix(id: string): string {
  const idx = id.lastIndexOf('-')
  return idx === -1 ? id : id.slice(idx + 1)
}
