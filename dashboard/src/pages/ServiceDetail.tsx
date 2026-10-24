import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  ExternalLink,
  Loader2,
  Minus,
  Pencil,
  Play,
  Plus,
  RotateCw,
  Scaling,
  ScrollText,
  Square,
  SquareTerminal,
  Trash2,
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
import { SpecEditDialog } from '@/components/SpecEditDialog'
import { KeyValue } from '@/components/KeyValue'
import { LogViewer } from '@/components/LogViewer'
import { MetricChartPanel } from '@/components/MetricChartPanel'
import { PageHeader } from '@/components/PageHeader'
import { StatusDot } from '@/components/StatusDot'
import { TabBar, type Tab } from '@/components/TabBar'
import { useLiveLog, MaxLogLines } from '@/hooks/useLiveLog'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { useRouter } from '@/hooks/useRouter'
import { useSession } from '@/hooks/useSession'
import { seriesKey, useTimedSeries } from '@/hooks/useSeries'
import { seriesStatus } from '@/lib/seriesStatus'
import { cn } from '@/lib/utils'
import { scaleBounds } from '@/lib/scale'
import { exposeUrls } from '@/lib/exposeUrl'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { OverflowMenu, overflowItem } from '@/components/OverflowMenu'
import { Link } from '@/lib/router'
import {
  Topic,
  allocsResponseSchema,
  deleteService,
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

  // The mockup's section switcher. The alloc the Logs tab follows lives up
  // here rather than in the panel, because an allocation row's logs button
  // needs to set both at once.
  const [tab, setTab] = useState<DetailTab>('allocations')
  const [logAlloc, setLogAlloc] = useState('')

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
      <div className="space-y-5">
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

  const ready = mine.filter((a) => a.state === 'running').length
  const scalingNames = (desired?.Scaling?.metrics ?? []).map((m) =>
    m.name === 'p95_latency_ms' ? 'p95' : m.name,
  )
  // Deploy age reads off the newest alloc: a deploy replaces every alloc, so
  // the youngest one's age is how long the current generation has been out.
  const newest = mine.reduce<string | undefined>(
    (best, a) =>
      a.created_at !== undefined && (best === undefined || a.created_at > best)
        ? a.created_at
        : best,
    undefined,
  )

  const tabs: Tab<DetailTab>[] = [
    { value: 'allocations', label: 'Allocations', count: mine.length },
    { value: 'logs', label: 'Logs' },
    { value: 'spec', label: 'Spec' },
    { value: 'events', label: 'Events', count: myEvents.length },
  ]
  if (stats.data?.edge) tabs.push({ value: 'edge', label: 'Edge' })

  return (
    <div className="space-y-5">
      <PageHeader
        back={
          <div className="mb-2">
            <BackChip to="/services">Services</BackChip>
          </div>
        }
        title={
          <span className="flex flex-wrap items-center gap-3">
            {/* The title is the service's full name, project included: a
                service name is only unique inside its project, and this is
                the form every other surface uses. */}
            <span className="font-mono">{key}</span>
            {status ? (
              <span
                className={cn(
                  'flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-normal',
                  statusPill[status.tone],
                )}
              >
                <StatusDot tone={status.tone} />
                {status.word}
                {desired && desired.Count > 0 ? ` · ${ready} of ${desired.Count} ready` : ''}
              </span>
            ) : null}
            {rollout?.deploying ? <Badge variant="info">deploying</Badge> : null}
          </span>
        }
        subtitle={
          <span className="font-mono text-xs">
            {desired?.Image ?? ''}
            {scalingNames.length > 0 ? ` · autoscale ${scalingNames.join(' · ')}` : ''}
            {newest !== undefined ? ` · deployed ${relativeAge(newest)} ago` : ''}
          </span>
        }
        actions={
          desired && rollout ? (
            <ServiceActions
              project={project}
              service={service}
              desired={desired}
              rollout={rollout}
              degraded={mine.some((a) => a.state === 'failed')}
            />
          ) : undefined
        }
      />

      <StatsPanel
        subject={key}
        memoryLimitBytes={desired?.Resources.MemoryBytes}
        sample={stats.data}
        history={history}
        seeded={seeded}
        connected={stats.connected}
        error={stats.error}
      />

      <TabBar tabs={tabs} value={tab} onChange={setTab} />

      {tab === 'allocations' ? (
        <Card className="py-1">
          {mine.length === 0 ? (
            <p className="px-4 py-3 text-sm text-muted-foreground">No allocations.</p>
          ) : (
            <Table>
              <THead>
                <tr>
                  <TH>Allocation</TH>
                  <TH>State</TH>
                  <TH className="text-right">CPU</TH>
                  <TH className="text-right">Mem</TH>
                  <TH>Age</TH>
                  <TH className="text-right" aria-label="Actions" />
                </tr>
              </THead>
              <TBody>
                {allocPager.pageItems.map((alloc) => (
                  <AllocRow
                    key={alloc.id}
                    alloc={alloc}
                    inits={desired?.init ?? []}
                    stats={(stats.data?.allocs ?? []).find((a) => a.alloc_id === alloc.id)}
                    onLogs={() => {
                      setLogAlloc(alloc.id)
                      setTab('logs')
                    }}
                  />
                ))}
              </TBody>
            </Table>
          )}
          <div className="px-3">
            <PaginationControls state={allocPager} />
          </div>
        </Card>
      ) : null}

      {tab === 'logs' ? (
        <LogPanel
          project={project}
          service={service}
          inits={desired?.init ?? []}
          allocs={mine}
          selectedAlloc={logAlloc}
          onSelectAlloc={setLogAlloc}
        />
      ) : null}

      {tab === 'spec' ? (
        <div className="grid items-start gap-4 lg:grid-cols-2">
          <SpecPanel project={project} service={service} desired={desired} />
          <AutoscalePanel desired={desired} events={myEvents} />
        </div>
      ) : null}

      {tab === 'events' ? (
        myEvents.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing recorded yet.</p>
        ) : (
          <div>
            {myEvents.slice(0, 20).map((e) => (
              <EventRow key={e.id} event={e} />
            ))}
          </div>
        )
      ) : null}

      {tab === 'edge' ? <EdgePanel edge={stats.data?.edge} /> : null}
    </div>
  )
}

type DetailTab = 'allocations' | 'logs' | 'spec' | 'events' | 'edge'

/** The header pill's tint per status tone: dot + word + tinted capsule, the
 * mockup's badge. */
const statusPill: Record<string, string> = {
  ok: 'border-status-ok/40 bg-status-ok/10 text-status-ok',
  warn: 'border-status-warn/40 bg-status-warn/10 text-status-warn',
  error: 'border-status-error/40 bg-status-error/10 text-status-error',
  muted: 'border-border bg-muted text-muted-foreground',
  info: 'border-status-info/40 bg-status-info/10 text-status-info',
}

/**
 * ServiceActions is the lifecycle row: edit spec, start, stop, restart.
 *
 * Stop and start are scales (to zero and back), restart bumps the generation:
 * every button writes desired state and the reconciler converges, so nothing
 * here is a second path to the runtime. The buttons stay visible for a viewer
 * but disabled: a viewer who does not know they are a viewer reads a missing
 * button as a broken dashboard.
 *
 * A degraded service (v1.106) is the one case where the recovery control is not
 * about the declared count. A service whose allocs exhausted the restart budget
 * is `AllocFailed`: the reconciler leaves it alone until its spec hash changes
 * (R29), so `count > 0` yet nothing runs. It is down but not stopped, so the
 * recovery is a restart (the generation bump is the spec-hash change that
 * revives a failed alloc) - and the button says so, reading "Start" rather than
 * "Restart", because an operator looking at a down service reaches for the verb
 * that brings it back, not the one that rolls a healthy one. It is the same
 * control relabelled by state, never a second button; Remove is the other half
 * of "start or remove a degraded service" and already sits outside the branch.
 */
/** How long a rollout may hold the buttons before honesty re-enables them. */
const rolloutLockMs = 5 * 60 * 1000

export function ServiceActions({
  project,
  service,
  desired,
  rollout,
  degraded,
}: {
  project: string
  service: string
  desired: Service
  rollout: RolloutStatus
  // degraded is true when at least one alloc has given up (AllocFailed): the
  // service is down but declared, so the recovery control becomes "Start".
  degraded: boolean
}) {
  const { session, csrf } = useSession()
  const { navigate } = useRouter()
  const admin = session?.role === 'admin'

  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmStop, setConfirmStop] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
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
  useEffect(() => {
    if (!confirmRemove) return
    const timer = setTimeout(() => setConfirmRemove(false), 4000)
    return () => clearTimeout(timer)
  }, [confirmRemove])

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
      {/* The recovery control, always visible: for a healthy service a
          Restart (a deliberate roll), for a degraded or stopped one a Start,
          because the operator looking at a down service reaches for the verb
          that brings it back (R29 / v1.106). Same action either way. */}
      {stopped ? (
        <Button
          size="sm"
          variant="outline"
          disabled={disabled}
          title={title}
          onClick={() => run('start', () => scaleService(project, service, lastCount.current, csrf))}
        >
          {spinner('start') ?? <Play size={14} />}
          {busy === 'start' ? 'Starting…' : 'Start'}
        </Button>
      ) : (
        <Button
          size="sm"
          variant="outline"
          disabled={disabled}
          title={title}
          onClick={() => run('restart', () => restartService(project, service, csrf))}
        >
          {spinner('restart') ?? (degraded ? <Play size={14} /> : <RotateCw size={14} />)}
          {busy === 'restart' || (initiated === 'restart' && converging)
            ? degraded
              ? 'Starting…'
              : 'Restarting…'
            : degraded
              ? 'Start'
              : 'Restart'}
        </Button>
      )}
      <Link to={`/services/${project}/${service}/edit`}>
        <Button size="sm" className="font-semibold">
          <Pencil size={14} />
          Edit spec
        </Button>
      </Link>
      {/* Everything else folds into the overflow menu (the mockup's ⋯):
          rarer verbs, still one click-and-a-bit away. The two destructive
          ones keep their disarm-on-timeout confirm inside the menu, which
          stays open while a confirm is armed. */}
      <OverflowMenu>
        {(close) => (
          <>
            {urls.map((u) => (
              <a
                key={u}
                href={u}
                target="_blank"
                rel="noopener noreferrer"
                className={overflowItem}
                onClick={close}
              >
                <ExternalLink size={14} aria-hidden />
                <span className="truncate">Open {u.replace(/^https?:\/\//, '')}</span>
              </a>
            ))}
            {!stopped ? (
              <button
                type="button"
                className={overflowItem}
                disabled={disabled}
                title={title ?? bounds.hint}
                onClick={() => {
                  close()
                  setScaleOpen(true)
                }}
              >
                <Scaling size={14} aria-hidden />
                Scale…
              </button>
            ) : null}
            {!stopped ? (
              <button
                type="button"
                className={cn(overflowItem, confirmStop ? 'text-destructive' : '')}
                disabled={disabled}
                title={title}
                onClick={() => {
                  if (!confirmStop) {
                    setConfirmStop(true)
                    return
                  }
                  setConfirmStop(false)
                  close()
                  run('stop', () => scaleService(project, service, 0, csrf))
                }}
              >
                {spinner('stop') ?? <Square size={14} aria-hidden />}
                {busy === 'stop' ? 'Stopping…' : confirmStop ? 'Confirm stop?' : 'Stop'}
              </button>
            ) : null}
            {/* Outside the stopped branch on purpose (PRD v1.100): a stopped
                service must stay removable. The fire path does not go through
                run(): a successful remove unmounts this page by navigating
                away. Volume data survives the removal (v1.83). */}
            <button
              type="button"
              className={cn(overflowItem, confirmRemove ? 'text-destructive' : '')}
              disabled={disabled}
              title={title ?? 'Delete the service declaration; volume data is kept'}
              onClick={() => {
                if (!confirmRemove) {
                  setConfirmRemove(true)
                  return
                }
                setConfirmRemove(false)
                close()
                setBusy('remove')
                setError(null)
                deleteService(project, service, csrf)
                  .then(() => navigate('/services'))
                  .catch((err: unknown) => {
                    setError(err instanceof Error ? err.message : String(err))
                    setBusy(null)
                  })
              }}
            >
              {busy === 'remove' ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Trash2 size={14} aria-hidden />
              )}
              {busy === 'remove' ? 'Removing…' : confirmRemove ? 'Confirm remove?' : 'Remove'}
            </button>
          </>
        )}
      </OverflowMenu>
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

/** SpecPanel is the declared record, key facts only - and, since v1.103,
 * where an admin edits it in place, scoped to this one service. */
function SpecPanel({
  project,
  service,
  desired,
}: {
  project: string
  service: string
  desired: Service | undefined
}) {
  const { session } = useSession()
  const [editOpen, setEditOpen] = useState(false)
  if (!desired) return null
  const publish = desired.Publish ?? []
  const admin = session?.role === 'admin'

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle>Spec</CardTitle>
        {/* Visible but disabled for a viewer, the page's own convention. */}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2"
          disabled={!admin}
          title={admin ? 'Edit the spec inline' : 'Requires the admin role'}
          aria-label="Edit spec inline"
          onClick={() => setEditOpen(true)}
        >
          <Pencil size={14} />
        </Button>
        <SpecEditDialog
          project={project}
          service={service}
          open={editOpen}
          onClose={() => setEditOpen(false)}
        />
      </CardHeader>
      <CardContent>
        <KeyValue label="Image" mono>
          <span className="break-all">{desired.Image}</span>
        </KeyValue>
        <KeyValue label="Replicas" mono>
          {desired.Count}
        </KeyValue>
        {/* Absent overrides render nothing: the image's own entrypoint and
            arguments are the default, and claiming "none" would misread it. */}
        {(desired.Command ?? []).length > 0 ? (
          <KeyValue label="Command" mono>
            <span className="break-all">{(desired.Command ?? []).join(' ')}</span>
          </KeyValue>
        ) : null}
        {(desired.args ?? []).length > 0 ? (
          <KeyValue label="Args" mono>
            {/* Elements may be empty on purpose (`--save ""`), so quote them. */}
            <span className="break-all">
              {(desired.args ?? []).map((a) => JSON.stringify(a)).join(' ')}
            </span>
          </KeyValue>
        ) : null}
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
        {(desired.init ?? []).length > 0 ? (
          <KeyValue label="Init" mono>
            {/* In declaration order, which is run order (R32). */}
            <span className="break-all">
              {(desired.init ?? []).map((step) => step.name).join(' → ')}
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

  // One segmented card rather than four boxes (the mockup's instrument row):
  // the same hairline treatment as StatStrip, drawn as left/top borders so
  // the grid wraps cleanly at two columns.
  const cell = (i: number) =>
    [
      'min-w-0 p-4',
      i % 2 === 1 ? 'border-l border-border' : '',
      i >= 2 ? 'border-t border-border lg:border-t-0' : '',
      i > 0 ? 'lg:border-l lg:border-border' : '',
    ].join(' ')

  return (
    <Card className="grid overflow-hidden sm:grid-cols-2 lg:grid-cols-4">
      {/* CPU and memory are percentages of the declared limit, so the scale
          is fixed at 100: a flat 2% line and a flat 90% one must not look
          the same. Rate and latency have no natural ceiling and scale to
          their own range. */}
      <div className={cell(0)}>
        <MetricChartPanel label="CPU" unit="%" series={cpu} scale="percent" latest={sample?.cpu} tone={1} big status={status} error={error} />
      </div>
      <div className={cell(1)}>
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
      </div>
      <div className={cell(2)}>
        <MetricChartPanel label="Requests / s" unit="/s" series={rps} scale="auto" latest={sample?.rps} tone={3} big status={status} error={error} />
      </div>
      <div className={cell(3)}>
        <MetricChartPanel label="p95 latency" unit=" ms" series={p95} scale="auto" latest={sample?.p95_latency_ms} tone={4} big status={status} error={error} />
      </div>
    </Card>
  )
}

/** AllocRow is one alloc, with its own resource history. */
/**
 * AllocRow is one container: id (with the leader's init steps beneath),
 * state with its restart-and-reason story as a second line, the live
 * numbers as numbers, and the two per-alloc verbs - jump to its logs,
 * open a shell.
 */
function AllocRow({
  alloc,
  inits,
  stats,
  onLogs,
}: {
  alloc: Alloc
  inits: InitContainer[]
  stats: AllocStats | undefined
  onLogs: () => void
}) {
  const tone = allocStateVariant(alloc.state)
  const reason = allocExitReason(alloc)
  const { session } = useSession()
  const admin = session?.role === 'admin'
  const [shellOpen, setShellOpen] = useState(false)

  return (
    <TR>
      <TD className="font-mono text-xs">
        {alloc.id}
        {/* The init sequence runs once per service, on the leader alone
            (R32, v1.92), so only alloc 0 has steps to show; a follower's row
            carrying them would claim work it never did. */}
        {inits.length > 0 && alloc.index === 0 ? (
          <InitSteps alloc={alloc} inits={inits} />
        ) : null}
      </TD>
      <TD>
        <StatusDot
          tone={tone === 'ok' ? 'ok' : tone === 'warn' ? 'warn' : tone === 'error' ? 'error' : 'muted'}
          label={alloc.state}
        />
        {/* Restarts and the last exit's reason share the second line: "how
            stable is this container" is one question (PRD v1.68). */}
        <div
          className="mt-0.5 text-xs text-muted-foreground"
          {...(reason?.message ? { title: reason.message } : {})}
        >
          {alloc.restarts ?? 0} restart{(alloc.restarts ?? 0) === 1 ? '' : 's'}
          {reason ? (
            <span className={reason.alarming ? 'text-status-error' : ''}> · {reason.label}</span>
          ) : null}
        </div>
      </TD>
      <TD className="text-right font-mono tabular-nums">
        {stats?.cpu !== undefined ? `${Math.round(stats.cpu)}%` : '–'}
      </TD>
      <TD className="text-right font-mono tabular-nums">
        {stats?.memory_bytes !== undefined
          ? formatBytes(stats.memory_bytes)
          : stats?.memory !== undefined
            ? `${Math.round(stats.memory)}%`
            : '–'}
      </TD>
      <TD className="font-mono tabular-nums">{relativeAge(alloc.created_at)}</TD>
      <TD className="text-right">
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            aria-label={`Logs for ${alloc.id}`}
            title="View this alloc's logs"
            className="rounded-md border border-border p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
            onClick={onLogs}
          >
            <ScrollText size={13} aria-hidden />
          </button>
          {/* The most privileged verb on the page: admin-only like the API,
              and only against a running alloc; a shell into a stopped one is
              a worse error message than this button's absence. */}
          {admin && alloc.state === 'running' ? (
            <>
              <button
                type="button"
                aria-label={`Shell into ${alloc.id}`}
                title="Open a shell"
                className="rounded-md border border-border p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={() => setShellOpen(true)}
              >
                <SquareTerminal size={13} aria-hidden />
              </button>
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
        </div>
      </TD>
    </TR>
  )
}


type InitStepState = 'done' | 'running' | 'failed' | 'pending'

/**
 * initStepStates reads the leader's record against the declared sequence
 * (R32). `init_step` is a zero-based ordinal with `omitempty`, so absence
 * means the first step, never "unknown". Outside the `init` state the record
 * says nothing about individual steps: a leader that reached its task ran
 * them all (that is what leaving `init` means), and one whose last exit was
 * an init failure stopped on the step the record still names.
 */
function initStepStates(alloc: Alloc, inits: InitContainer[]): InitStepState[] {
  const current = alloc.init_step ?? 0
  if (alloc.state === 'init') {
    return inits.map((_, i) => (i < current ? 'done' : i === current ? 'running' : 'pending'))
  }
  if (alloc.last_exit_reason === 'init_failed' || alloc.last_exit_reason === 'init_timeout') {
    return inits.map((_, i) => (i < current ? 'done' : i === current ? 'failed' : 'pending'))
  }
  return inits.map(() => 'done')
}

const initStepGlyph: Record<InitStepState, { mark: string; className: string }> = {
  done: { mark: '✓', className: 'text-muted-foreground' },
  running: { mark: '▸', className: 'text-status-warn' },
  failed: { mark: '✗', className: 'text-status-error' },
  pending: { mark: '·', className: 'text-muted-foreground/60' },
}

/** InitSteps renders the leader's init sequence under its id: one entry per
 * declared step, marked done, running (with elapsed), failed, or pending. */
function InitSteps({ alloc, inits }: { alloc: Alloc; inits: InitContainer[] }) {
  const states = initStepStates(alloc, inits)
  return (
    <ol
      aria-label={`Init steps for ${alloc.id}`}
      className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5"
    >
      {inits.map((step, i) => {
        const state = states[i] ?? 'done'
        const glyph = initStepGlyph[state]
        const elapsed =
          state === 'running' && alloc.init_started_at
            ? ` · ${relativeAge(alloc.init_started_at)}`
            : ''
        return (
          <li
            key={step.name}
            className="flex items-center gap-1 text-xs text-muted-foreground"
            title={`init "${step.name}": ${state}`}
          >
            <span aria-hidden className={glyph.className}>
              {glyph.mark}
            </span>
            <span className={state === 'failed' ? 'text-status-error' : undefined}>
              {step.name}
              {elapsed}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

function LogPanel({
  project,
  service,
  inits,
  allocs,
  selectedAlloc,
  onSelectAlloc,
}: {
  project: string
  service: string
  inits: InitContainer[]
  allocs: Alloc[]
  /** Which alloc's lines to show; lifted to the page so an allocation row's
   * logs button can select one while switching tabs. */
  selectedAlloc: string
  onSelectAlloc: (id: string) => void
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
  // '' is every alloc. A filter over the one merged stream rather than a
  // second subscription, because every line already carries its alloc_id;
  // derived-validated like the container picker, so an alloc that rolled
  // away while selected falls back to all.
  const allocId = allocs.some((a) => a.id === selectedAlloc) ? selectedAlloc : ''

  // Memoized: at ten thousand buffered lines the filter is no longer free,
  // and this re-runs on every stats frame otherwise.
  const shown = useMemo(() => {
    const mine = allocId ? lines.filter((l) => l.alloc_id === allocId) : lines
    if (!filter) return mine
    const needle = filter.toLowerCase()
    return mine.filter((l) => l.line.toLowerCase().includes(needle))
  }, [lines, filter, allocId])
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
      {/* Bare mono pills, the mockup's: the value is the label ("shop-api-0",
          "wait-for-postgres"), so a caption beside it would say it twice.
          The aria-labels carry what the eye infers from the options. */}
      {allocs.length > 1 ? (
        <select
          value={allocId}
          onChange={(e) => onSelectAlloc(e.target.value)}
          aria-label="Which allocation's log to show"
          className="h-8 rounded-md border border-border bg-card px-2.5 font-mono text-xs"
        >
          <option value="">all allocs</option>
          {allocs.map((a) => (
            <option key={a.id} value={a.id}>
              {a.id}
            </option>
          ))}
        </select>
      ) : null}
      {inits.length > 0 ? (
        <select
          value={container}
          onChange={(e) => setSelected(e.target.value)}
          aria-label="Which container's log to follow"
          className="h-8 rounded-md border border-border bg-card px-2.5 font-mono text-xs"
        >
          {/* In run order, which is declaration order (R32), and numbered
              because the names alone cannot say they are a sequence. The task
              is last because it starts once every step has finished; the
              value stays the bare block name, which is what the daemon
              resolves back to a step index. */}
          {inits.map((step, i) => (
            <option key={step.name} value={step.name}>
              {i + 1}. {step.name}
            </option>
          ))}
          <option value="">task</option>
        </select>
      ) : null}
      <input
        type="search"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter…"
        aria-label="Filter log lines"
        className="h-8 min-w-40 flex-1 rounded-md border bg-background px-2.5 text-xs"
      />
      <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
        Follow
      </label>
    </>
  )

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2.5">{logControls}</div>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      <LogViewer
          lines={viewerLines}
          live
          follow={follow}
          onFollowChange={setFollow}
          tintSeverity
          toolbar={{
            copy: true,
            download: {
              filename: `${allocId || `${project}-${service}`}${container ? `-${container}` : ''}.log`,
            },
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
    </div>
  )
}

/** allocSuffix shortens an alloc id to its index, which is what distinguishes
 * one line from another within a service. */
function allocSuffix(id: string): string {
  const idx = id.lastIndexOf('-')
  return idx === -1 ? id : id.slice(idx + 1)
}
