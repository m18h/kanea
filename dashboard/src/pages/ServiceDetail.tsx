import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Loader2,
  Minus,
  Pencil,
  Play,
  Plus,
  RotateCw,
  Scaling,
  Square,
  SquareTerminal,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog } from '@/components/ui/dialog'
import { ChartSkeleton, TableSkeleton } from '@/components/Skeletons'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { BackChip } from '@/components/BackChip'
import { EventRow } from '@/components/EventRow'
import { ExecTerminal } from '@/components/ExecTerminal'
import { KeyValue } from '@/components/KeyValue'
import { LogViewer } from '@/components/LogViewer'
import { MetricChartPanel } from '@/components/MetricChartPanel'
import { PageHeader } from '@/components/PageHeader'
import { Sparkline } from '@/components/Sparkline'
import { StatusDot } from '@/components/StatusDot'
import { useLiveLog, MaxLogLines } from '@/hooks/useLiveLog'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { useSession } from '@/hooks/useSession'
import { allocSubject, seedFromHistory, seriesKey, useSeries, useTimedSeries } from '@/hooks/useSeries'
import { seriesStatus } from '@/lib/seriesStatus'
import { scaleBounds } from '@/lib/scale'
import { exposeUrls } from '@/lib/exposeUrl'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { OpenUrlMenu } from '@/components/OpenUrlMenu'
import { Link } from '@/lib/router'
import {
  Topic,
  allocsResponseSchema,
  fetchEvents,
  restartService,
  scaleService,
  servicesResponseSchema,
  statsSampleSchema,
  type Alloc,
  type InitContainer,
  type AllocStats,
  type EdgeBreakdown,
  type KaneaEvent,
  type Service,
  type StatsHistory,
  type StatsSample,
} from '@/lib/api'
import { useDateStyle } from '@/hooks/useDateStyle'
import { formatDateTime } from '@/lib/datetime'
import { parseScaleDecision } from '@/lib/events'
import { rolloutStatus, type RolloutStatus } from '@/lib/rollout'
import {
  allocStateVariant,
  formatBytes,
  memoryUsageText,
  allocExitReason,
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
  // The seed rides this subscription's first frame (v1.79): one round trip
  // instead of a socket and a REST call, and a reconnect re-seeds for free
  // because the daemon treats a resubscribe as a replace.
  const stats = useLiveTopic(
    { topic: Topic.Stats, project, service, history: true, history_allocs: true },
    statsSampleSchema,
  )

  const events = useQuery({
    queryKey: ['events', project],
    queryFn: ({ signal }) => fetchEvents({ project, limit: 100 }, signal),
    refetchInterval: 15_000,
  })

  // The seed arrives on the first frame; GET /v1/stats/history remains for
  // one-shot callers with nowhere to put a socket, and is no longer one of them.
  const history = stats.data?.history ?? null
  const seeded = stats.data?.history !== undefined || stats.data?.history_omitted === true

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
          <PageHeader title={<span className="font-mono">{key}</span>} />
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
  const rollout = desired ? rolloutStatus(desired, mine) : null
  const myEvents = (events.data?.events ?? []).filter(
    (e) => !e.service || e.service === service,
  )

  return (
    <div className="space-y-4">
      {/* Navigation and actions share the top row: one is where you came
          from, the other is what you can do here, and neither is the page's
          name. The name gets its own row underneath, where a long image
          reference can run without squeezing the buttons. */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <BackChip to="/services">Services</BackChip>
          <div className="ml-auto">
            {desired && rollout ? (
              <ServiceActions
                project={project}
                service={service}
                desired={desired}
                rollout={rollout}
              />
            ) : null}
          </div>
        </div>
        {/* The title is the service's full name, project included: a service
            name is only unique inside its project, so `web` alone names two
            different things on a node running `shop` and `blog`. It is also
            the form every other surface uses - PipelineDetail's title, the
            CLI's `project/service` argument, the stats subject below - so the
            page's name now matches what you would type to reach it. */}
        <PageHeader
          title={<span className="font-mono">{key}</span>}
          subtitle={
            <span className="inline-flex items-center gap-3">
              {status ? <StatusDot tone={status.tone} label={status.word} /> : null}
              {rollout?.deploying ? <Badge variant="info">deploying</Badge> : null}
              <span>{desired?.Image ?? ''}</span>
            </span>
          }
        />
      </div>

      <StatsPanel
        subject={key}
        memoryLimitBytes={desired?.Resources.MemoryBytes}
        sample={stats.data}
        history={history}
        seeded={seeded}
        connected={stats.connected}
        error={stats.error}
      />

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
                      <TH>Reason</TH>
                      <TH>Age</TH>
                      <TH className="pr-0" aria-label="Actions" />
                    </tr>
                  </THead>
                  <TBody>
                    {allocPager.pageItems.map((alloc) => (
                      <AllocRow
                        key={alloc.id}
                        alloc={alloc}
                        subject={key}
                        stats={(stats.data?.allocs ?? []).find((a) => a.alloc_id === alloc.id)}
                        at={stats.data?.at ?? ''}
                        history={history}
                        seeded={seeded}
                        connected={stats.connected}
                      />
                    ))}
                  </TBody>
                </Table>
              )}
              <PaginationControls state={allocPager} />
            </CardContent>
          </Card>

          <LogPanel project={project} service={service} inits={desired?.Init ?? []} />

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
 * Stop and start are scales (to zero and back), restart bumps the generation:
 * every button writes desired state and the reconciler converges, so nothing
 * here is a second path to the runtime. The buttons stay visible for a viewer
 * but disabled: a viewer who does not know they are a viewer reads a missing
 * button as a broken dashboard.
 */
/** How long a rollout may hold the buttons before honesty re-enables them. */
const rolloutLockMs = 5 * 60 * 1000

export function ServiceActions({
  project,
  service,
  desired,
  rollout,
}: {
  project: string
  service: string
  desired: Service
  rollout: RolloutStatus
}) {
  const { session, csrf } = useSession()
  const admin = session?.role === 'admin'

  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmStop, setConfirmStop] = useState(false)
  const [scaleOpen, setScaleOpen] = useState(false)
  // Which action kicked off the rollout the page is now watching. Cleared
  // when convergence lands; the spinner rides it.
  const [initiated, setInitiated] = useState<string | null>(null)
  // The honesty valve: a rollout that has not converged in rolloutLockMs
  // gives the buttons back rather than wedging the page on a stuck deploy.
  const [lockExpired, setLockExpired] = useState(false)

  // What "start" should scale back to: the last non-zero count this page saw.
  // The daemon does not remember it: a stopped service's record says zero;
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

  const converging = rollout.deploying && !lockExpired
  // Render-time reset (the derived-state pattern): convergence voids both the
  // initiating-action marker and the honesty valve.
  if (!rollout.deploying && (initiated !== null || lockExpired)) {
    setInitiated(null)
    setLockExpired(false)
  }
  useEffect(() => {
    if (!rollout.deploying) return
    const timer = setTimeout(() => setLockExpired(true), rolloutLockMs)
    return () => clearTimeout(timer)
  }, [rollout.deploying])

  const run = (name: string, action: () => Promise<void>) => {
    setBusy(name)
    setError(null)
    action()
      .then(() => setInitiated(name))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(null))
  }

  const stopped = desired.Count === 0
  const disabled = !admin || busy !== null || converging
  const title = admin ? undefined : 'Requires the admin role'
  const bounds = scaleBounds(desired)
  const urls = exposeUrls(desired)
  const spinner = (name: string) =>
    busy === name || (initiated === name && converging) ? (
      <Loader2 size={14} className="animate-spin" />
    ) : null

  return (
    <div className="flex items-center gap-2">
      {error ? (
        <span className="max-w-64 truncate text-xs text-destructive" title={error}>
          {error}
        </span>
      ) : null}
      {rollout.deploying ? (
        <span className="font-mono text-xs text-muted-foreground">
          {lockExpired
            ? 'still converging; actions re-enabled'
            : `rolling out · ${rollout.updated}/${rollout.total} updated`}
        </span>
      ) : null}
      {/* Opening a public URL is navigation, not a mutation, so it is not
          gated on the admin role the write buttons need. It is absent rather
          than disabled when there is nothing to open: see exposeUrls for the
          cases, one of which the dashboard cannot resolve for a viewer. */}
      <OpenUrlMenu urls={urls} />
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
          {spinner('start') ?? <Play size={14} />}
          {busy === 'start' ? 'Starting…' : 'Start'}
        </Button>
      ) : (
        <>
          {/* Scaling writes one number and the reconciler converges; this is
              the same route `kanea scale` and the autoscaler use, so the
              dashboard is not a second path to the runtime. The count is
              chosen in a dialog rather than nudged in place: a replica count
              is a decision, and one taken by holding down a button is a
              decision nobody made deliberately. */}
          <Button
            size="sm"
            variant="outline"
            disabled={disabled}
            title={title ?? bounds.hint}
            onClick={() => setScaleOpen(true)}
          >
            {spinner('scale') ?? <Scaling size={14} />}
            Scale
          </Button>
          <ScaleDialog
            open={scaleOpen}
            onClose={() => setScaleOpen(false)}
            subject={`${project}/${service}`}
            current={desired.Count}
            bounds={bounds}
            onScale={(count) => {
              setScaleOpen(false)
              run('scale', () => scaleService(project, service, count, csrf))
            }}
          />
          <Button
            size="sm"
            variant="outline"
            disabled={disabled}
            title={title}
            onClick={() => run('restart', () => restartService(project, service, csrf))}
          >
            {spinner('restart') ?? <RotateCw size={14} />}
            {busy === 'restart' || (initiated === 'restart' && converging)
              ? 'Restarting…'
              : 'Restart'}
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
            {spinner('stop') ?? <Square size={14} />}
            {busy === 'stop' ? 'Stopping…' : confirmStop ? 'Confirm stop?' : 'Stop'}
          </Button>
        </>
      )}
    </div>
  )
}

/**
 * ScaleDialog picks a replica count.
 *
 * A dialog rather than a stepper in the toolbar, because a replica count is a
 * decision: it wants the current value in front of you, the range you may
 * choose from, and one deliberate confirmation - not a button that changes
 * production every time it is clicked.
 *
 * The draft is local until Scale is pressed, so nothing is written while you
 * are still choosing, and the picker is seeded from the live count each time
 * the dialog opens rather than held between openings: the count can move under
 * you (the autoscaler, another operator, `kanea scale`), and a stale draft
 * would quietly undo whatever moved it.
 */
function ScaleDialog({
  open,
  onClose,
  subject,
  current,
  bounds,
  onScale,
}: {
  open: boolean
  onClose: () => void
  subject: string
  current: number
  bounds: { min: number; max: number; hint: string | undefined }
  onScale: (count: number) => void
}) {
  const [draft, setDraft] = useState(current)
  // Re-seeded on each *opening*, and deliberately not while open. Following
  // the live count instead would look tidier and would make this control
  // unusable on the services it matters most for: an autoscaling service moves
  // its count every few seconds, and each move would wipe whatever the
  // operator had typed. What they typed is an intent that does not depend on
  // where the count happens to be - scaling to 7 is the same decision from 3
  // as from 4 - so the draft is theirs until they cancel or commit.
  const [wasOpen, setWasOpen] = useState(open)
  if (wasOpen !== open) {
    setWasOpen(open)
    if (open) setDraft(current)
  }

  const bounded = Number.isFinite(bounds.max)
  const clamp = (n: number) => Math.min(Math.max(n, bounds.min), bounds.max)
  // The buttons cannot leave the range, but the *starting* value can already
  // be outside it: a service running twelve replicas when a policy capping it
  // at ten is applied afterwards. Submitting that would be refused by the
  // daemon, so it is refused here first.
  const valid = draft >= bounds.min && draft <= bounds.max
  const unchanged = draft === current

  return (
    <Dialog open={open} onClose={onClose} title={`Scale ${subject}`} className="w-[90vw] max-w-sm">
      <div className="space-y-4">
        <div className="flex items-center justify-center gap-3">
          <Button
            size="sm"
            variant="outline"
            aria-label="Fewer replicas"
            className="h-10 w-10 p-0"
            disabled={draft <= bounds.min}
            onClick={() => setDraft((n) => clamp(n - 1))}
          >
            <Minus size={16} />
          </Button>
          {/* A readout, not a field. The count is chosen with the two
              buttons, which cannot express an out-of-range or half-typed
              value, so there is nothing here to validate and nothing to
              mis-type. role="status" is what makes the change audible to a
              screen reader: pressing a button that silently rewrites a number
              elsewhere on screen is exactly what a live region is for. */}
          <span
            role="status"
            aria-live="polite"
            className="w-24 text-center font-mono text-lg tabular-nums"
          >
            {draft}
          </span>
          <Button
            size="sm"
            variant="outline"
            aria-label="More replicas"
            className="h-10 w-10 p-0"
            disabled={draft >= bounds.max}
            onClick={() => setDraft((n) => clamp(n + 1))}
          >
            <Plus size={16} />
          </Button>
        </div>

        <p className="text-center text-xs text-muted-foreground">
          Currently <span className="font-mono">{current}</span>
          {bounded ? (
            <>
              {' · '}
              allowed <span className="font-mono">
                {bounds.min}-{bounds.max}
              </span>
            </>
          ) : null}
        </p>

        {/* What the autoscaler will do with the number, said before it is
            written rather than discovered afterwards. */}
        {bounds.hint ? (
          <p className="rounded-md bg-muted/50 p-2 text-xs text-muted-foreground">{bounds.hint}</p>
        ) : null}
        <p className="text-center text-xs text-muted-foreground">
          Scaling to zero is stopping; use Stop for that.
        </p>

        <div className="flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          {/* Always "Scale to N", never a bare "Scale": the button states the
              decision it commits, and it stops colliding with the toolbar
              button that opened this dialog. */}
          <Button size="sm" disabled={!valid || unchanged} onClick={() => onScale(draft)}>
            {valid ? `Scale to ${draft}` : 'Scale'}
          </Button>
        </div>
      </div>
    </Dialog>
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
  const style = useDateStyle()
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
                  {formatDateTime(lastDecision.at, style)}
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
          {/* Zero means unbounded (R11, v1.58): "0m · 0 B" would read as
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
        {/* Empty means the node's default applies (R33), which is not a value
            to render: showing "none" would claim a policy nobody declared. */}
        {desired.pull_policy ? (
          <KeyValue label="Pull policy" mono>
            {desired.pull_policy}
          </KeyValue>
        ) : null}
        {(desired.Init ?? []).length > 0 ? (
          <KeyValue label="Init" mono>
            {/* In declaration order, which is run order (R32). */}
            <span className="break-all">
              {(desired.Init ?? []).map((step) => step.name).join(' → ')}
            </span>
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
 * measured": the same distinction the metric gauges draw by being absent.
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
      {/* Cumulative for the life of the edge process, not a rate; the panel
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
  subject,
  memoryLimitBytes,
  sample,
  history,
  seeded,
  connected,
  error,
}: {
  subject: string
  /** The service's declared per-alloc memory cap, or 0 for unbounded (R11). */
  memoryLimitBytes: number | undefined
  sample: StatsSample | null
  history: StatsHistory | null
  seeded: boolean
  connected: boolean
  error: string | null
}) {
  const at = sample?.at ?? ''
  const cpu = useTimedSeries(seriesKey(subject, 'cpu'), sample?.cpu, at, history, 'cpu')
  const memory = useTimedSeries(seriesKey(subject, 'memory'), sample?.memory, at, history, 'memory')
  const rps = useTimedSeries(seriesKey(subject, 'rps'), sample?.rps, at, history, 'rps')
  const p95 = useTimedSeries(
    seriesKey(subject, 'p95_latency_ms'), sample?.p95_latency_ms, at, history, 'p95_latency_ms')

  // One verdict for the panel, because all four series arrive on the same
  // frame and from the same seed: they are never empty for different reasons.
  const status = seriesStatus({ points: cpu.times.length, seeded, connected, error })

  const memoryText = memoryUsageText(sample, memoryLimitBytes)

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* CPU and memory are percentages of the declared limit, so the scale
          is fixed at 100: a flat 2% line and a flat 90% one must not look
          the same. Rate and latency have no natural ceiling and scale to
          their own range. */}
      <Card className="p-4">
        <MetricChartPanel label="CPU" unit="%" series={cpu} scale="percent" latest={sample?.cpu} tone={1} big status={status} error={error} />
      </Card>
      <Card className="p-4">
        <MetricChartPanel
          label="Memory"
          unit="%"
          series={memory}
          scale="percent"
          latest={sample?.memory}
          {...(memoryText !== undefined ? { detail: memoryText } : {})}
          tone={2}
          big
          status={status}
          error={error}
        />
      </Card>
      <Card className="p-4">
        <MetricChartPanel label="Requests / s" unit="/s" series={rps} scale="auto" latest={sample?.rps} tone={3} big status={status} error={error} />
      </Card>
      <Card className="p-4">
        <MetricChartPanel label="p95 latency" unit=" ms" series={p95} scale="auto" latest={sample?.p95_latency_ms} tone={4} big status={status} error={error} />
      </Card>
    </div>
  )
}

/** AllocRow is one alloc, with its own resource history. */
function AllocRow({
  alloc,
  subject,
  stats,
  at,
  history,
  seeded,
  connected,
}: {
  alloc: Alloc
  subject: string
  stats: AllocStats | undefined
  at: string
  history: StatsHistory | null
  seeded: boolean
  connected: boolean
}) {
  // Seeded from the per-alloc half of the history (v1.79). Before it existed
  // these two sparklines accumulated from empty at one point per five seconds,
  // so a row was visibly blank for the first minute of every visit, with no
  // readout beside it to fall back on.
  const block = history?.allocs?.[alloc.id]
  const key = allocSubject(subject, alloc.id)
  const cpu = useSeries(
    seriesKey(key, 'cpu'), stats?.cpu, at, block ? seedFromHistory(block, 'cpu') : undefined)
  const memory = useSeries(
    seriesKey(key, 'memory'), stats?.memory, at,
    block ? seedFromHistory(block, 'memory') : undefined)
  const status = seriesStatus({ points: cpu.length, seeded, connected })
  const tone = allocStateVariant(alloc.state)
  const reason = allocExitReason(alloc)
  const { session } = useSession()
  const admin = session?.role === 'admin'
  const [shellOpen, setShellOpen] = useState(false)

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
        <Sparkline points={cpu} max={100} unit="%" tone={1} className="h-6 w-24" label={`CPU for ${alloc.id}`} status={status} />
      </TD>
      <TD>
        <Sparkline points={memory} max={100} unit="%" tone={2} className="h-6 w-24" label={`Memory for ${alloc.id}`} status={status} />
      </TD>
      <TD className="font-mono tabular-nums">
        {alloc.restarts ?? 0}
        {alloc.last_exit_at ? (
          <span className="text-muted-foreground"> ({relativeAge(alloc.last_exit_at)})</span>
        ) : null}
      </TD>
      <TD>
        {/* Why it last stopped, or why it never started (PRD v1.68). Shown
            whatever the current state: the State column is right there, so a
            running row carrying OOMKilled reads as "up now, killed for memory
            last time", which is the thing worth knowing. */}
        {reason ? (
          <span
            className="flex max-w-[22rem] flex-col leading-tight"
            title={reason.message ? `${reason.label}; ${reason.message}` : reason.label}
          >
            <span className={reason.alarming ? 'text-status-error' : 'text-muted-foreground'}>
              {reason.label}
            </span>
            {reason.message ? (
              <span className="truncate text-xs text-muted-foreground">{reason.message}</span>
            ) : null}
          </span>
        ) : (
          <span className="text-muted-foreground">-</span>
        )}
      </TD>
      <TD className="font-mono tabular-nums">{relativeAge(alloc.created_at)}</TD>
      <TD className="pr-0 text-right">
        {/* The most privileged verb on the page: admin-only like the API, and
            only against a running alloc; a shell into a stopped one is a
            worse error message than this button's absence. */}
        {admin && alloc.state === 'running' ? (
          <>
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1.5 px-2 text-xs"
              onClick={() => setShellOpen(true)}
            >
              <SquareTerminal size={13} />
              Shell
            </Button>
            <Dialog
              open={shellOpen}
              onClose={() => setShellOpen(false)}
              dismissable={false}
              title={<span className="font-mono">{alloc.id} · sh</span>}
              className="h-[70vh] w-[90vw] max-w-4xl"
            >
              {/* Mounted only while open: the terminal (and xterm's lazy
                  chunk) exist exactly while someone is looking at them. */}
              {shellOpen ? <ExecTerminal project={alloc.project} alloc={alloc.id} /> : null}
            </Dialog>
          </>
        ) : null}
      </TD>
    </TR>
  )
}

/** LogPanel streams the service's output over the shared socket. */
function LogPanel({
  project,
  service,
  inits,
}: {
  project: string
  service: string
  inits: InitContainer[]
}) {
  // Which container's log this panel is following: '' is the task, otherwise an
  // init container's block name (R32). Each step writes its own file, so this
  // opens a different feed rather than filtering one.
  const [selected, setSelected] = useState('')
  // Derived rather than reset in an effect: a step removed from the spec while
  // this panel is open would otherwise leave the picker on a name the daemon
  // no longer resolves and a stream that never fills, and correcting it in an
  // effect costs a second render to say what one expression already knows.
  const container = inits.some((i) => i.name === selected) ? selected : ''
  const { lines, error, dropped, droppedByDaemon } = useLiveLog(project, service, 200, container)
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

  // One definition, rendered in the card header and again inside the expanded
  // dialog. Both are driven by the same state, so they cannot disagree.
  const logControls = (
    <>
      <input
        type="search"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter"
        aria-label="Filter log lines"
        className="rounded-md border bg-background px-2 py-1 text-xs"
      />
      {inits.length > 0 ? (
        <label className="flex items-center gap-1 text-xs text-muted-foreground">
          Container
          <select
            value={container}
            onChange={(e) => setSelected(e.target.value)}
            aria-label="Which container's log to follow"
            className="rounded-md border bg-background px-2 py-1 text-xs"
          >
            <option value="">task</option>
            {inits.map((step) => (
              <option key={step.name} value={step.name}>
                {step.name}
              </option>
            ))}
          </select>
        </label>
      ) : null}
      <label className="flex items-center gap-1 text-xs text-muted-foreground">
        <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
        Follow
      </label>
    </>
  )

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3 space-y-0">
        <div className="flex items-baseline gap-2">
          <CardTitle>Logs</CardTitle>
          <span className="font-mono text-xs text-muted-foreground">
            tail · all allocs · live{container ? ` · init "${container}"` : ''}
          </span>
        </div>
        <div className="flex items-center gap-2">{logControls}</div>
      </CardHeader>
      <CardContent>
        {error ? <p className="pb-2 text-sm text-destructive">{error}</p> : null}
        <LogViewer
          lines={viewerLines}
          live
          follow={follow}
          onFollowChange={setFollow}
          tintSeverity
          toolbar={{
            copy: true,
            download: { filename: `${project}-${service}${container ? `-${container}` : ''}.log` },
            expand: true,
          }}
          title={`${project}/${service}; logs`}
          controls={logControls}
          emptyText={
            lines.length === 0
              ? container
                ? `Waiting for init "${container}"…`
                : 'Waiting for output…'
              : 'No lines match the filter.'
          }
          notice={
            dropped > 0 || droppedByDaemon > 0 ? (
              // Two gaps with two causes, said separately: one is this tab
              // running out of buffer, the other is the node not keeping up.
              // Reporting them as one number would send someone looking in the
              // wrong place.
              <p className="pb-2 text-xs text-muted-foreground">
                {dropped > 0 ? (
                  <>
                    {dropped} earlier line{dropped === 1 ? '' : 's'} dropped here (showing the most
                    recent {MaxLogLines}).{' '}
                  </>
                ) : null}
                {droppedByDaemon > 0 ? (
                  <>
                    {droppedByDaemon} line{droppedByDaemon === 1 ? '' : 's'} were not sent by the
                    node.
                  </>
                ) : null}
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
