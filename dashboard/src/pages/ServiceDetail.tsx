import { useEffect, useRef, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLiveLog, MaxLogLines } from '@/hooks/useLiveLog'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import {
  Topic,
  allocsResponseSchema,
  servicesResponseSchema,
  statsSampleSchema,
  type AllocStats,
  type EdgeBreakdown,
  type StatsSample,
} from '@/lib/api'
import {
  allocStateVariant,
  formatBytes,
  groupAllocs,
  groupCodes,
  serviceHealth,
} from '@/lib/state'
import { Sparkline } from '@/components/Sparkline'
import { useSeries } from '@/hooks/useSeries'

export function ServiceDetail({ project, service }: { project: string; service: string }) {

  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)
  const stats = useLiveTopic({ topic: Topic.Stats, project, service }, statsSampleSchema)

  const key = `${project}/${service}`
  const desired = (services.data?.services ?? []).find(
    (s) => s.Project === project && s.Service === service,
  )
  const mine = groupAllocs(allocs.data?.allocs ?? []).get(key) ?? []

  if (services.connected && !desired) {
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

  const health = desired ? serviceHealth(desired, mine) : null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="font-mono">{key}</CardTitle>
          {health ? <Badge variant={health.settled ? 'ok' : 'warn'}>{health.label}</Badge> : null}
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <Field label="Image" value={desired?.Image ?? '—'} mono />
          <Field label="Desired" value={String(desired?.Count ?? 0)} />
          {desired?.Expose ? (
            <Field
              label="Domains"
              value={(desired.Expose.Domains ?? []).join(', ') || 'auto-generated'}
              mono
            />
          ) : null}
        </CardContent>
      </Card>

      <StatsPanel sample={stats.data} />

      <Card>
        <CardHeader>
          <CardTitle>Allocations</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {mine.length === 0 ? (
            <p className="text-sm text-muted-foreground">No allocations.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="pb-2 pr-4 font-medium">Alloc</th>
                  <th className="pb-2 pr-4 font-medium">State</th>
                  <th className="pb-2 pr-4 font-medium">Restarts</th>
                  <th className="pb-2 pr-4 font-medium">CPU</th>
                  <th className="pb-2 font-medium">Memory</th>
                </tr>
              </thead>
              <tbody>
                {mine.map((alloc) => (
                  <AllocRow
                    key={alloc.ID}
                    id={alloc.ID}
                    state={alloc.State}
                    restarts={alloc.Restarts ?? 0}
                    stats={(stats.data?.allocs ?? []).find((a) => a.alloc_id === alloc.ID)}
                    at={stats.data?.at ?? ''}
                  />
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <EdgePanel edge={stats.data?.edge} />

      <LogPanel project={project} service={service} />
    </div>
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
function StatsPanel({ sample }: { sample: StatsSample | null }) {
  const at = sample?.at ?? ''
  const cpu = useSeries(sample?.cpu, at)
  const memory = useSeries(sample?.memory, at)
  const rps = useSeries(sample?.rps, at)
  const p95 = useSeries(sample?.p95_latency_ms, at)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Live</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* CPU and memory are percentages of the declared limit, so the scale
            is fixed at 100: a flat 2% line and a flat 90% one must not look
            the same. Rate and latency have no natural ceiling and scale to
            their own range. */}
        <Metric label="CPU" unit="%" points={cpu} max={100} latest={sample?.cpu} />
        <Metric label="Memory" unit="%" points={memory} max={100} latest={sample?.memory} />
        <Metric label="Requests" unit="/s" points={rps} latest={sample?.rps} />
        <Metric label="p95" unit=" ms" points={p95} latest={sample?.p95_latency_ms} />
      </CardContent>
    </Card>
  )
}

function Metric({
  label,
  unit,
  points,
  max,
  latest,
}: {
  label: string
  unit: string
  points: (number | undefined)[]
  max?: number | undefined
  latest?: number | undefined
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
        <span className="font-mono text-sm tabular-nums">
          {/* An em dash, not a zero: the daemon omits a metric it has nothing
              recent for, and "0" would be a claim about the service. */}
          {latest === undefined ? '—' : `${latest.toFixed(latest < 10 ? 1 : 0)}${unit}`}
        </span>
      </div>
      <Sparkline points={points} max={max} label={`${label} over the last few minutes`} />
    </div>
  )
}

/** AllocRow is one alloc, with its own resource history. */
function AllocRow({
  id,
  state,
  restarts,
  stats,
  at,
}: {
  id: string
  state: string
  restarts: number
  stats: AllocStats | undefined
  at: string
}) {
  const cpu = useSeries(stats?.cpu, at)
  const memory = useSeries(stats?.memory, at)

  return (
    <tr className="border-t border-border/60">
      <td className="py-2 pr-4 font-mono text-xs">{id}</td>
      <td className="py-2 pr-4">
        <Badge variant={allocStateVariant(state)}>{state}</Badge>
      </td>
      <td className="py-2 pr-4 tabular-nums">{restarts}</td>
      <td className="py-2 pr-4">
        <Sparkline points={cpu} max={100} className="h-6 w-20" label={`CPU for ${id}`} />
      </td>
      <td className="py-2">
        <Sparkline points={memory} max={100} className="h-6 w-20" label={`Memory for ${id}`} />
      </td>
    </tr>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="w-24 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      {/* Values come from a job spec and are rendered as text, never markup. */}
      <span className={mono ? 'font-mono text-xs' : ''}>{value}</span>
    </div>
  )
}

/** LogPanel streams the service's output over the shared socket. */
function LogPanel({ project, service }: { project: string; service: string }) {
  const { lines, error, dropped } = useLiveLog(project, service)
  const [filter, setFilter] = useState('')
  const [follow, setFollow] = useState(true)
  const bottom = useRef<HTMLDivElement>(null)

  const shown = filter
    ? lines.filter((l) => l.line.toLowerCase().includes(filter.toLowerCase()))
    : lines

  useEffect(() => {
    if (follow) bottom.current?.scrollIntoView({ block: 'end' })
  }, [shown.length, follow])

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 gap-3">
        <CardTitle>Logs</CardTitle>
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
            <input
              type="checkbox"
              checked={follow}
              onChange={(e) => setFollow(e.target.checked)}
            />
            Follow
          </label>
        </div>
      </CardHeader>
      <CardContent>
        {error ? <p className="pb-2 text-sm text-destructive">{error}</p> : null}
        {dropped > 0 ? (
          <p className="pb-2 text-xs text-muted-foreground">
            {dropped} earlier line{dropped === 1 ? '' : 's'} dropped (showing the most recent{' '}
            {MaxLogLines}).
          </p>
        ) : null}
        <div className="max-h-96 overflow-auto rounded-md bg-muted/40 p-2 font-mono text-xs">
          {shown.length === 0 ? (
            <p className="text-muted-foreground">
              {lines.length === 0 ? 'Waiting for output…' : 'No lines match the filter.'}
            </p>
          ) : (
            shown.map((entry, i) => (
              // Workload output is attacker-controlled whenever the workload is.
              // It is rendered as a text child — never markup (PRD §14, A03).
              <div key={`${entry.alloc_id}-${i}`} className="whitespace-pre-wrap break-all">
                <span className="mr-2 text-muted-foreground">{allocSuffix(entry.alloc_id)}</span>
                {entry.line}
              </div>
            ))
          )}
          <div ref={bottom} />
        </div>
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
