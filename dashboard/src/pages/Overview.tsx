import { useQuery } from '@tanstack/react-query'
import { Link } from '@/lib/router'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { KeyValueSkeleton } from '@/components/Skeletons'
import { EventRow } from '@/components/EventRow'
import { KeyValue } from '@/components/KeyValue'
import { MetricChartPanel } from '@/components/MetricChartPanel'
import { PageHeader } from '@/components/PageHeader'
import { StatTile } from '@/components/StatTile'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { useTimedSeries } from '@/hooks/useSeries'
import {
  Topic,
  allocsResponseSchema,
  fetchBackups,
  fetchEvents,
  fetchHealth,
  fetchNodeStats,
  fetchRuns,
  fetchStatsHistory,
  servicesResponseSchema,
  type NodeStats,
  type StatsHistory,
} from '@/lib/api'
import { isStale, replicationLag } from '@/lib/backups'
import { parseScaleDecision, type ScaleDecision } from '@/lib/events'
import {
  formatBytes,
  formatClock,
  formatUptime,
  groupAllocs,
  serviceHealth,
} from '@/lib/state'

/**
 * The Dashboard is the "should I worry" page: counts, node utilisation, the
 * last few events, the autoscaler's recent decisions, and backup health.
 */
export function Overview() {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 10_000,
  })

  const node = useQuery({
    queryKey: ['node-stats'],
    queryFn: ({ signal }) => fetchNodeStats(signal),
    refetchInterval: 10_000,
  })

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

  // Seed once; the poll takes over from where the history ends.
  const seed = useQuery({
    queryKey: ['stats-history', 'node'],
    queryFn: ({ signal }) => fetchStatsHistory('node', signal),
    staleTime: Infinity,
    retry: false,
  })

  // Functions are services too, but every surface counts them under
  // Functions: the sidebar badge and the Services page both filter them
  // out, so the tile must agree rather than show a number one higher.
  const list = (services.data?.services ?? []).filter((s) => s.function == null)
  const byService = groupAllocs(allocs.data?.allocs ?? [])
  const healthy = list.filter(
    (svc) => serviceHealth(svc, byService.get(`${svc.Project}/${svc.Service}`) ?? []).settled,
  ).length

  const allAllocs = allocs.data?.allocs ?? []
  const running = allAllocs.filter((a) => a.state === 'running').length

  const building = (runs.data ?? []).filter((r) => r.state === 'running').length

  const feed = events.data?.events ?? []
  const dayAgo = (events.dataUpdatedAt || 0) - 24 * 60 * 60 * 1000
  const recent = feed.filter((e) => Date.parse(e.at) >= dayAgo)
  const warns = recent.filter((e) => e.severity === 'warning').length
  const errors = recent.filter((e) => e.severity === 'error').length

  const decisions = feed
    .map(parseScaleDecision)
    .filter((d): d is ScaleDecision => d !== null)
    .slice(0, 4)

  const subtitle = [
    'single binary',
    health.data?.pid !== undefined ? `pid ${health.data.pid}` : null,
    health.data?.uptime_seconds !== undefined
      ? `up ${formatUptime(health.data.uptime_seconds)}`
      : null,
  ]
    .filter(Boolean)
    .join(' · ')

  return (
    <div className="space-y-4">
      <PageHeader title="Dashboard" subtitle={subtitle} />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Services" value={list.length} sub={`${healthy} healthy`} />
        <StatTile label="Allocations" value={allAllocs.length} sub={`${running} running`} />
        <StatTile
          label="Builds"
          value={building}
          tone={building > 0 ? 'primary' : 'default'}
          sub={building > 0 ? 'slot 1/1 in use' : 'slot 0/1 · idle'}
        />
        <StatTile
          label="Events / 24h"
          value={recent.length}
          sub={`${warns} warn · ${errors} error`}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <UtilisationCard node={node.data} history={seed.data ?? null} />

        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle>Recent events</CardTitle>
            <Link to="/events" className="font-mono text-xs text-primary hover:underline">
              view all →
            </Link>
          </CardHeader>
          <CardContent>
            {feed.length === 0 ? (
              <p className="text-sm text-muted-foreground">Nothing has happened yet.</p>
            ) : (
              feed.slice(0, 5).map((e) => <EventRow key={e.id} event={e} />)
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Autoscaler decisions</CardTitle>
          </CardHeader>
          <CardContent>
            {node.data?.breaker_open ? (
              <p className="pb-2 text-sm text-status-error">
                The circuit breaker is open: scaling and rollouts are paused.
              </p>
            ) : null}
            {decisions.length === 0 ? (
              <p className="text-sm text-muted-foreground">No scaling decisions recently.</p>
            ) : (
              decisions.map((d) => (
                <div
                  key={`${d.service}-${d.at}`}
                  className="flex items-baseline gap-3 border-b border-border/50 py-2 text-sm last:border-0"
                >
                  <span className="shrink-0 font-mono">{d.service}</span>
                  {d.from !== undefined && d.to !== undefined ? (
                    <span
                      className={`shrink-0 font-mono tabular-nums ${
                        d.direction === 'up' ? 'text-status-ok' : 'text-status-info'
                      }`}
                    >
                      {d.from} → {d.to}
                    </span>
                  ) : null}
                  <span className="min-w-0 truncate text-muted-foreground">{d.reason}</span>
                  <span className="ml-auto shrink-0 font-mono text-xs text-muted-foreground">
                    {formatClock(d.at)}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle>Backups</CardTitle>
            {backups.data?.replication ? (
              <span
                className={`font-mono text-xs ${
                  isStale(backups.data.replication.last_segment_at)
                    ? 'text-status-error'
                    : 'text-status-ok'
                }`}
              >
                CDC lag {replicationLag(backups.data.replication.last_segment_at)}
              </span>
            ) : null}
          </CardHeader>
          <CardContent>
            {backups.data === null ? (
              <p className="text-sm text-status-error">
                No backup destination is configured. This node's state exists only on its
                own disk.
              </p>
            ) : backups.data ? (
              <>
                <KeyValue label="Last archive" mono>
                  {backups.data.backups[0]
                    ? `${backups.data.backups[0].id} · ${formatBytes(backups.data.backups[0].snapshot.size)}`
                    : 'none yet'}
                </KeyValue>
                <KeyValue label="S3 replication" mono>
                  {backups.data.replication.failures > 0 ? (
                    <span className="text-status-error">
                      {backups.data.replication.failures} failure(s)
                    </span>
                  ) : isStale(backups.data.replication.last_segment_at) ? (
                    <span className="text-status-error">stale</span>
                  ) : (
                    <span className="text-status-ok">in sync</span>
                  )}
                </KeyValue>
                <KeyValue label="Encryption" mono>
                  AEAD · xchacha20-poly1305
                </KeyValue>
                <KeyValue label="Archives retained" mono>
                  {backups.data.backups.length}
                </KeyValue>
              </>
            ) : (
              <KeyValueSkeleton rows={4} />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

/**
 * UtilisationCard is the node's own numbers (procfs, polled every 10 s), each
 * accumulated into a sparkline client-side. CPU and memory are pinned to 100
 * so a flat 2% line and a flat 90% one cannot look the same.
 */
function UtilisationCard({
  node,
  history,
}: {
  node: NodeStats | undefined
  history: StatsHistory | null
}) {
  const machine = node?.node
  const at = machine?.at ?? node?.at ?? ''
  const cpu = useTimedSeries(machine?.cpu_percent, at, history, 'cpu')
  const memory = useTimedSeries(machine?.memory_percent, at, history, 'memory')
  const load = useTimedSeries(machine?.load1, at)
  const runningSeries = useTimedSeries(node?.running, node?.at ?? '')
  const gpu = useTimedSeries(machine?.gpu_vram_percent, at, history, 'gpu_vram')

  const memoryText =
    machine?.memory_total_bytes !== undefined && machine.memory_available_bytes !== undefined
      ? `${formatBytes(machine.memory_total_bytes - machine.memory_available_bytes)} / ${formatBytes(machine.memory_total_bytes)}`
      : undefined

  // The GPU panel exists only when a GPU is visible: a GPU-less node gets no
  // panel, not an empty one; absence is not a 0% card.
  const gpus = machine?.gpus ?? []
  const hasGPU = gpus.length > 0 || gpu.values.some((v) => v !== null)
  const vramUsed = gpus.reduce((sum, g) => sum + (g.vram_used_bytes ?? 0), 0)
  const vramTotal = gpus.reduce((sum, g) => sum + (g.vram_total_bytes ?? 0), 0)
  const gpuText =
    vramTotal > 0 ? `${formatBytes(vramUsed)} / ${formatBytes(vramTotal)}` : undefined

  return (
    <Card className="lg:col-span-3">
      <CardHeader className="flex-row items-baseline justify-between space-y-0">
        <CardTitle>Server utilisation</CardTitle>
        <span className="font-mono text-xs text-muted-foreground">procfs · 10s poll</span>
      </CardHeader>
      <CardContent className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
        <MetricChartPanel label="CPU" unit="%" series={cpu} scale="percent" latest={machine?.cpu_percent} tone={1} />
        <MetricChartPanel
          label="Memory"
          unit="%"
          series={memory}
          scale="percent"
          latest={machine?.memory_percent}
          {...(memoryText !== undefined ? { valueText: memoryText } : {})}
          tone={2}
        />
        <MetricChartPanel label="Load 1m" unit="" series={load} scale="auto" latest={machine?.load1} tone={3} />
        <MetricChartPanel
          label="Allocs running"
          unit=""
          series={runningSeries}
          scale="auto"
          latest={node?.running}
          tone={4}
        />
        {hasGPU ? (
          <MetricChartPanel
            label={gpus.length > 1 ? `GPU VRAM (${gpus.length} GPUs)` : 'GPU VRAM'}
            unit="%"
            series={gpu}
            scale="percent"
            latest={machine?.gpu_vram_percent}
            {...(gpuText !== undefined ? { valueText: gpuText } : {})}
            tone={2}
          />
        ) : null}
      </CardContent>
    </Card>
  )
}
