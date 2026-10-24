import { useQuery } from '@tanstack/react-query'
import { ArrowRight, DatabaseBackup } from 'lucide-react'
import { Link } from '@/lib/router'
import { Card } from '@/components/ui/card'
import { AttentionBanner } from '@/components/AttentionBanner'
import { EventRow } from '@/components/EventRow'
import { PageHeader } from '@/components/PageHeader'
import { Sparkline } from '@/components/Sparkline'
import { StatStrip, type StatCell } from '@/components/StatStrip'
import { StatusDot } from '@/components/StatusDot'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { seriesKey, useTimedSeries, type TimedSeries } from '@/hooks/useSeries'
import { seriesStatus, type SeriesStatus } from '@/lib/seriesStatus'
import {
  Topic,
  allocsResponseSchema,
  fetchBackups,
  fetchEvents,
  fetchHealth,
  fetchNodeStats,
  fetchRuns,
  fetchVolumes,
  nodeSampleSchema,
  servicesResponseSchema,
  type Alloc,
  type Service,
  type StatsHistory,
} from '@/lib/api'
import { isStale, replicationLag } from '@/lib/backups'
import {
  formatBytes,
  formatUptime,
  groupAllocs,
  serviceHealth,
  serviceRecency,
  type Health,
} from '@/lib/state'

/**
 * The Dashboard is the "should I worry" page, in the mockup's order: the
 * things that need attention first (banners), then the counts, the node's
 * own numbers, the services beside what just happened, and one line on
 * whether the state is safely somewhere else.
 */
export function Overview() {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 10_000,
  })

  // Live over the socket the page is already holding (v1.79), with its own
  // seed on the first frame, so the utilisation cells draw a populated window
  // on arrival instead of growing one point per ten seconds from empty.
  const node = useLiveTopic(
    {
      topic: Topic.Node,
      history: true,
      history_series: ['cpu', 'memory', 'gpu_util', 'gpu_vram', 'load1', 'allocs_running'],
    },
    nodeSampleSchema,
  )

  // One release of fallback for a daemon that predates the topic; without it
  // an upgrade lag would blank the strip rather than merely slow it down.
  const nodeRest = useQuery({
    queryKey: ['node-stats'],
    queryFn: ({ signal }) => fetchNodeStats(signal),
    enabled: !node.up,
    refetchInterval: node.up ? false : 10_000,
  })
  const nodeStats = node.data ?? nodeRest.data

  const runs = useQuery({
    queryKey: ['runs'],
    queryFn: ({ signal }) => fetchRuns({ limit: 200 }, signal),
    refetchInterval: 15_000,
  })

  const events = useQuery({
    queryKey: ['events', ''],
    queryFn: ({ signal }) => fetchEvents({ limit: 200 }, signal),
    refetchInterval: 5_000,
  })

  const backups = useQuery({
    queryKey: ['backups'],
    queryFn: ({ signal }) => fetchBackups(signal),
    refetchInterval: 30_000,
  })

  const volumes = useQuery({
    queryKey: ['volumes'],
    queryFn: ({ signal }) => fetchVolumes(signal),
    refetchInterval: 30_000,
  })

  // Functions are services too, but every surface counts them under
  // Functions: the sidebar and the Services page both filter them out, so
  // this page must agree rather than show a number one higher.
  const list = (services.data?.services ?? []).filter((s) => s.function == null)
  const byService = groupAllocs(allocs.data?.allocs ?? [])
  const statuses = list.map((svc) => {
    const mine = byService.get(`${svc.Project}/${svc.Service}`) ?? []
    return { svc, allocs: mine, health: serviceHealth(svc, mine) }
  })
  const unsettled = statuses.filter((s) => !s.health.settled)
  const healthy = statuses.length - unsettled.length

  // The card shows the few services that changed most recently; the Services
  // page has all of them. Sorted on a copy so the banners below keep reading
  // statuses in store order, and tie-broken by name because most nodes deploy
  // several services at once - an unstable comparator would let every socket
  // frame reorder the card.
  const recentServices = statuses
    .map((s) => ({ s, at: serviceRecency(s.allocs) }))
    .sort(
      (a, b) =>
        b.at - a.at ||
        `${a.s.svc.Project}/${a.s.svc.Service}`.localeCompare(
          `${b.s.svc.Project}/${b.s.svc.Service}`,
        ),
    )
    .slice(0, 6)
    .map(({ s }) => s)

  const allAllocs = allocs.data?.allocs ?? []
  const running = allAllocs.filter((a) => a.state === 'running').length

  const building = (runs.data ?? []).filter((r) => r.state === 'running').length

  const feed = events.data?.events ?? []
  const dayAgo = (events.dataUpdatedAt || 0) - 24 * 60 * 60 * 1000
  const recent = feed.filter((e) => Date.parse(e.at) >= dayAgo)
  const warns = recent.filter((e) => e.severity === 'warning').length
  const errors = recent.filter((e) => e.severity === 'error').length

  // A storage resource is over budget when any of its mounts is: one banner
  // per resource, worded from its worst mount, because three mounts of one
  // NFS export over budget is one fact about one export.
  const overBudget = (volumes.data ?? []).flatMap((storage) => {
    const over = (storage.mounts ?? []).filter((m) => m.state === 'over')
    const worst = over.sort((a, b) => (b.used_bytes ?? 0) - (a.used_bytes ?? 0))[0]
    return worst ? [{ storage, mount: worst }] : []
  })

  const subtitle =
    services.data === undefined
      ? undefined
      : unsettled.length === 0
        ? `All ${statuses.length} service${statuses.length === 1 ? '' : 's'} healthy`
        : `${healthy} of ${statuses.length} services healthy · ${unsettled.length} need${unsettled.length === 1 ? 's' : ''} attention`

  const meta =
    health.data?.uptime_seconds !== undefined
      ? `up ${formatUptime(health.data.uptime_seconds)}${node.connected ? ' · live' : ''}`
      : undefined

  return (
    <div className="space-y-5">
      <PageHeader title="Dashboard" subtitle={subtitle} meta={meta} />

      {/* What needs looking at, before any number: a page that buries its
          one warning under four healthy counts reads as healthy. */}
      {(unsettled.length > 0 || overBudget.length > 0 || nodeStats?.breaker_open) && (
        <div className="space-y-2">
          {nodeStats?.breaker_open ? (
            <AttentionBanner tone="error" label="Breaker open" to="/events" subject="autoscaler">
              scaling and rollouts are paused until events quiet down
            </AttentionBanner>
          ) : null}
          {unsettled.slice(0, 3).map(({ svc, allocs: mine, health: h }) => (
            <AttentionBanner
              key={`${svc.Project}/${svc.Service}`}
              tone="warn"
              label="Warning"
              to={`/services/${svc.Project}/${svc.Service}`}
              subject={`${svc.Project}/${svc.Service}`}
            >
              {h.label}, {mine.filter((a) => a.state === 'running').length} of {svc.Count} replica
              {svc.Count === 1 ? '' : 's'} ready
            </AttentionBanner>
          ))}
          {overBudget.slice(0, 2).map(({ storage, mount }) => (
            <AttentionBanner
              key={`${storage.project}/${storage.name}`}
              tone="error"
              label="Over budget"
              to="/storage"
              subject={`${storage.project}/${storage.name}`}
            >
              {mount.used_bytes !== undefined && mount.size_bytes !== undefined
                ? `${formatBytes(mount.used_bytes)} used of a ${formatBytes(mount.size_bytes)} budget`
                : 'a mount is over its declared budget'}
            </AttentionBanner>
          ))}
        </div>
      )}

      <StatStrip
        cells={[
          {
            label: 'Services',
            value: statuses.length,
            sub: unsettled.length === 0 ? 'all healthy' : `${healthy} healthy`,
          },
          { label: 'Allocations', value: allAllocs.length, sub: `${running} running` },
          {
            label: 'Builds',
            value: building,
            tone: building > 0 ? 'primary' : 'default',
            sub: building > 0 ? 'slot 1/1 in use' : 'slot 0/1 · idle',
          },
          {
            label: 'Events · 24h',
            value: recent.length,
            sub: `${warns} warn · ${errors} error`,
          },
        ]}
      />

      <UtilisationStrip
        node={nodeStats}
        history={node.data?.history ?? null}
        seeded={node.data?.history !== undefined || node.data?.history_omitted === true}
        connected={node.connected}
      />

      <div className="grid items-start gap-x-6 gap-y-4 lg:grid-cols-5">
        <section className="lg:col-span-2">
          <div className="mb-2 flex items-baseline justify-between">
            <h2 className="text-sm font-semibold">Services</h2>
            <Link to="/services" className="font-mono text-xs text-muted-foreground hover:text-foreground">
              All services →
            </Link>
          </div>
          <Card className="divide-y divide-border/60 px-3">
            {statuses.length === 0 ? (
              <p className="py-3 text-sm text-muted-foreground">No services yet.</p>
            ) : (
              recentServices.map((s) => (
                <ServiceLine key={`${s.svc.Project}/${s.svc.Service}`} {...s} />
              ))
            )}
          </Card>
        </section>

        <section className="lg:col-span-3">
          <div className="mb-2 flex items-baseline justify-between">
            <h2 className="text-sm font-semibold">Activity</h2>
            <Link to="/events" className="font-mono text-xs text-muted-foreground hover:text-foreground">
              All events →
            </Link>
          </div>
          {feed.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing has happened yet.</p>
          ) : (
            feed.slice(0, 6).map((e) => <EventRow key={e.id} event={e} />)
          )}
        </section>
      </div>

      <BackupsLine backups={backups.data} />
    </div>
  )
}

/** ServiceLine is one row of the dashboard's service list: dot, name, the
 * settling word, ready count. Compact on purpose - the Services page has
 * the full table. */
function ServiceLine({ svc, allocs: mine, health }: { svc: Service; allocs: Alloc[]; health: Health }) {
  const ready = mine.filter((a) => a.state === 'running').length
  const word = health.settled && svc.Count > 0 ? 'running' : health.label
  return (
    <Link
      to={`/services/${svc.Project}/${svc.Service}`}
      className="flex items-center gap-2.5 py-2.5 transition-colors hover:bg-muted/40"
    >
      <StatusDot tone={health.settled ? 'ok' : 'warn'} />
      <span className="min-w-0 truncate font-mono text-sm">
        {svc.Project}/{svc.Service}
      </span>
      <span
        className={`ml-auto shrink-0 text-xs ${health.settled ? 'text-muted-foreground' : 'text-status-warn'}`}
      >
        {word}
      </span>
      <span className="w-10 shrink-0 text-right font-mono text-xs tabular-nums">
        {ready}/{svc.Count}
      </span>
    </Link>
  )
}

/**
 * UtilisationStrip is the node's own numbers (procfs, 5 s live) as the
 * mockup's second instrument row: big value, quiet denominator, a bare
 * sparkline. The GPU cell exists only when a GPU is visible: a GPU-less
 * node gets three cells, not an empty fourth; absence is not a 0% card.
 */
function UtilisationStrip({
  node,
  history,
  seeded,
  connected,
}: {
  node: ReturnType<typeof nodeSampleSchema.parse> | undefined
  history: StatsHistory | null
  seeded: boolean
  connected: boolean
}) {
  const machine = node?.node
  const at = machine?.at ?? node?.at ?? ''
  const cpu = useTimedSeries(seriesKey('node', 'cpu'), machine?.cpu_percent, at, history, 'cpu')
  const memory = useTimedSeries(
    seriesKey('node', 'memory'), machine?.memory_percent, at, history, 'memory')
  const load = useTimedSeries(seriesKey('node', 'load1'), machine?.load1, at, history, 'load1')
  const gpuUtil = useTimedSeries(
    seriesKey('node', 'gpu_util'), machine?.gpu_util_percent, at, history, 'gpu_util')
  const gpuVram = useTimedSeries(
    seriesKey('node', 'gpu_vram'), machine?.gpu_vram_percent, at, history, 'gpu_vram')

  // One verdict for the strip: every cell is fed by the same poll and the
  // same seed, so they are never empty for different reasons.
  const status = seriesStatus({ points: cpu.times.length, seeded, connected })

  const memUsed =
    machine?.memory_total_bytes !== undefined && machine.memory_available_bytes !== undefined
      ? machine.memory_total_bytes - machine.memory_available_bytes
      : undefined

  const gpus = machine?.gpus ?? []
  const hasGPU =
    gpus.length > 0 ||
    gpuVram.values.some((v) => v !== null) ||
    gpuUtil.values.some((v) => v !== null)

  const cells: StatCell[] = [
    {
      label: 'CPU',
      meta: machine ? `${machine.cores} cores` : undefined,
      value: machine?.cpu_percent !== undefined ? `${Math.round(machine.cpu_percent)}%` : '–',
      chart: <StripSpark series={cpu} max={100} unit="%" label="CPU" tone={1} status={status} />,
    },
    {
      label: 'Memory',
      meta:
        machine?.memory_total_bytes !== undefined
          ? `of ${formatBytes(machine.memory_total_bytes)}`
          : undefined,
      value: memUsed !== undefined ? formatBytes(memUsed) : '–',
      chart: (
        <StripSpark series={memory} max={100} unit="%" label="Memory" tone={2} status={status} />
      ),
    },
    {
      label: 'Load (1m)',
      meta: node !== undefined ? `${node.running} allocs` : undefined,
      value: machine?.load1 !== undefined ? machine.load1.toFixed(2) : '–',
      chart: <StripSpark series={load} unit="" label="Load" tone={3} status={status} />,
    },
  ]
  if (hasGPU) {
    cells.push({
      label: 'GPU',
      meta:
        machine?.gpu_vram_percent !== undefined
          ? `VRAM ${Math.round(machine.gpu_vram_percent)}%`
          : (gpus.map((g) => g.name).join(', ') || undefined),
      value:
        machine?.gpu_util_percent !== undefined
          ? `${Math.round(machine.gpu_util_percent)}%`
          : '–',
      chart: (
        <StripSpark series={gpuUtil} max={100} unit="%" label="GPU" tone={5} status={status} />
      ),
    })
  }

  return <StatStrip className={hasGPU ? '' : 'lg:grid-cols-3'} cells={cells} />
}

/** StripSpark adapts a timed series to the Sparkline the strip cells draw:
 * values only, gaps kept as gaps. */
function StripSpark({
  series,
  max,
  unit,
  label,
  tone,
  status,
}: {
  series: TimedSeries
  max?: number | undefined
  unit: string
  label: string
  tone: 1 | 2 | 3 | 4 | 5
  status: SeriesStatus
}) {
  return (
    <Sparkline
      points={series.values.map((v) => (v === null ? undefined : v))}
      max={max}
      unit={unit}
      tone={tone}
      status={status}
      label={`${label} history`}
      className="h-7 w-full"
    />
  )
}

/** BackupsLine is the mockup's one-line answer to "is the state safely
 * somewhere else": a status word and three facts, the whole row a link. */
function BackupsLine({
  backups,
}: {
  backups: Awaited<ReturnType<typeof fetchBackups>> | undefined
}) {
  if (backups === undefined) return null

  if (backups === null) {
    return (
      <Card className="px-4 py-3">
        <Link to="/backups" className="flex items-center gap-3 text-sm">
          <DatabaseBackup size={15} aria-hidden className="shrink-0 text-status-error" />
          <span className="font-medium text-status-error">No backup destination configured</span>
          <span className="hidden text-muted-foreground sm:inline">
            this node's state exists only on its own disk
          </span>
          <ArrowRight size={14} aria-hidden className="ml-auto shrink-0 text-muted-foreground" />
        </Link>
      </Card>
    )
  }

  const stale = isStale(backups.replication.last_segment_at)
  const failures = backups.replication.failures
  const latest = backups.backups[0]
  const trouble = stale || failures > 0

  return (
    <Card className="px-4 py-3">
      <Link to="/backups" className="flex items-center gap-3 text-sm">
        <DatabaseBackup
          size={15}
          aria-hidden
          className={`shrink-0 ${trouble ? 'text-status-error' : 'text-muted-foreground'}`}
        />
        <span className={`font-medium ${trouble ? 'text-status-error' : ''}`}>
          {failures > 0
            ? `Backups: ${failures} replication failure${failures === 1 ? '' : 's'}`
            : stale
              ? 'Backups stale'
              : 'Backups in sync'}
        </span>
        <span className="hidden min-w-0 truncate font-mono text-xs text-muted-foreground md:inline">
          {latest ? `last archive ${formatBytes(latest.snapshot.size)}` : 'no archive yet'}
          {' · '}CDC lag {replicationLag(backups.replication.last_segment_at)}
          {' · '}AEAD encrypted
        </span>
        <ArrowRight size={14} aria-hidden className="ml-auto shrink-0 text-muted-foreground" />
      </Link>
    </Card>
  )
}
