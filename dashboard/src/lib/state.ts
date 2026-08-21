import type { BadgeProps } from '@/components/ui/badge'
import type { Alloc, StatsSample } from '@/lib/api'

/** allocStateVariant maps an alloc state to how alarming it should look. */
export function allocStateVariant(state: string): NonNullable<BadgeProps['variant']> {
  switch (state) {
    case 'running':
      return 'ok'
    // `init` is an alloc running its init sequence (R32): on its way up, not
    // in trouble, so it reads like `pending`, which is what it is.
    case 'init':
    case 'backoff':
    case 'pending':
      return 'warn'
    case 'failed':
      return 'error'
    default:
      return 'muted'
  }
}

/**
 * reasonLabels renders a termination reason the way a person says it (PRD
 * v1.68). Kept in step with cmd/kanea/describe.go's map of the same name: the
 * dashboard and `kanea describe` are answering the same question and should not
 * word it differently.
 */
const reasonLabels: Record<string, string> = {
  oom_killed: 'OOMKilled',
  signal: 'Signalled',
  error: 'Error',
  completed: 'Completed',
  image_failed: 'ImageFailed',
  volume_failed: 'VolumeFailed',
  passthrough_failed: 'GrantFailed',
  network_failed: 'NetworkFailed',
  create_failed: 'CreateFailed',
  start_failed: 'StartFailed',
  init_failed: 'InitFailed',
  init_timeout: 'InitTimeout',
}

export interface ExitReason {
  label: string
  message: string
  /** alarming is true for a cause that needs a person, not just a note. */
  alarming: boolean
}

/**
 * allocExitReason describes why an alloc last stopped, or why it never started.
 *
 * Returns null when there is nothing to say. A record written before v1.68 has
 * an exit code and no reason, and still renders as the code: an upgrade must
 * not make an existing alloc less legible than it was.
 */
export function allocExitReason(alloc: Alloc): ExitReason | null {
  const reason = alloc.last_exit_reason
  if (!reason) {
    return alloc.last_exit_code
      ? { label: `exit ${alloc.last_exit_code}`, message: '', alarming: false }
      : null
  }
  return {
    label: reasonLabels[reason] ?? reason,
    message: alloc.last_exit_message ?? '',
    // A clean exit is a fact, not a problem. Everything else got here by
    // something going wrong.
    alarming: reason !== 'completed',
  }
}

/** groupAllocs indexes allocs by their service, in stable index order. */
export function groupAllocs(allocs: Alloc[]): Map<string, Alloc[]> {
  const out = new Map<string, Alloc[]>()
  for (const alloc of allocs) {
    const key = `${alloc.project}/${alloc.service}`
    const existing = out.get(key)
    if (existing) existing.push(alloc)
    else out.set(key, [alloc])
  }
  for (const group of out.values()) {
    group.sort((a, b) => a.index - b.index)
  }
  return out
}

export interface Health {
  label: string
  /** settled is false while anything is still converging. */
  settled: boolean
}

/**
 * serviceHealth summarises a service the way `kanea status` does.
 *
 * "ok" means settled, not merely "nothing has failed yet": a service that is
 * still starting is not ok, or the dashboard would look green during exactly
 * the window an operator is watching it.
 */
export function serviceHealth(service: { Count: number }, allocs: Alloc[]): Health {
  const running = allocs.filter((a) => a.state === 'running').length
  const backoff = allocs.filter((a) => a.state === 'backoff').length
  const failed = allocs.filter((a) => a.state === 'failed').length

  if (failed > 0) return { label: `${failed} failed`, settled: false }
  if (backoff > 0) return { label: `${backoff} restarting`, settled: false }
  if (service.Count === 0) {
    return running === 0
      ? { label: 'stopped', settled: true }
      : { label: 'stopping', settled: false }
  }
  if (running > service.Count) return { label: 'stopping', settled: false }
  if (running < service.Count) return { label: 'starting', settled: false }
  return { label: 'ok', settled: true }
}

/** CodeClass groups status codes the way an operator reads them. */
export interface CodeClass {
  /** klass is "2xx", "3xx", "4xx", "5xx" or "other". */
  klass: string
  count: number
  variant: NonNullable<BadgeProps['variant']>
}

/**
 * groupCodes folds the edge's exact status codes into classes (PRD §9.1.1).
 *
 * The exposition keeps exact codes because Prometheus users want them; a
 * dashboard tile does not. Five buckets fit on a card and answer the question
 * a glance is asking (is anything failing) where twenty codes would need
 * reading rather than seeing.
 *
 * Returned in class order rather than by volume: 5xx is always in the same
 * place, so its absence is as visible as its presence.
 */
export function groupCodes(codes: Record<string, number> | null | undefined): CodeClass[] {
  const order: { klass: string; variant: NonNullable<BadgeProps['variant']> }[] = [
    { klass: '2xx', variant: 'ok' },
    { klass: '3xx', variant: 'muted' },
    { klass: '4xx', variant: 'warn' },
    { klass: '5xx', variant: 'error' },
    { klass: 'other', variant: 'muted' },
  ]

  const totals = new Map<string, number>()
  for (const [code, count] of Object.entries(codes ?? {})) {
    const digit = code.charAt(0)
    const klass = /^[2345]$/.test(digit) ? `${digit}xx` : 'other'
    totals.set(klass, (totals.get(klass) ?? 0) + count)
  }

  return order
    .filter(({ klass }) => totals.has(klass))
    .map(({ klass, variant }) => ({ klass, count: totals.get(klass) ?? 0, variant }))
}

import type { StatusTone } from '@/components/StatusDot'

/** serviceStatusTone maps a health summary onto the dot + word the mockup
 * shows: running / scaling / degraded / stopped. */
export function serviceStatusTone(health: Health): { tone: StatusTone; word: string } {
  if (health.label.includes('failed') || health.label.includes('restarting')) {
    return { tone: 'error', word: 'degraded' }
  }
  if (health.label === 'stopped') return { tone: 'muted', word: 'stopped' }
  if (!health.settled) return { tone: 'warn', word: 'scaling' }
  return { tone: 'ok', word: 'running' }
}

/** formatUptime renders elapsed seconds the way the mockup header reads:
 * the two largest units that are non-zero ("41d 6h", "6h 12m", "12m"). */
export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '-'
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m`
  return `${Math.floor(seconds)}s`
}

/** relativeAge renders how old a timestamp is in its single largest unit:
 * the allocs table's AGE column ("41d", "6h", "3m", "0s"). */
export function relativeAge(iso: string | undefined, now: number = Date.now()): string {
  if (!iso) return '-'
  const at = new Date(iso).getTime()
  if (Number.isNaN(at)) return '-'
  const seconds = Math.max(0, Math.floor((now - at) / 1000))
  if (seconds >= 86_400) return `${Math.floor(seconds / 86_400)}d`
  if (seconds >= 3_600) return `${Math.floor(seconds / 3_600)}h`
  if (seconds >= 60) return `${Math.floor(seconds / 60)}m`
  return `${seconds}s`
}

/** formatClock renders a timestamp as the wall-clock time the feed shows. */
export function formatClock(iso: string): string {
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return iso
  return at.toLocaleTimeString([], { hour12: false })
}

/** formatMetric renders a sample the same way everywhere: one decimal while
 * the number is small enough for it to mean something. */
export function formatMetric(value: number, unit: string): string {
  return `${value.toFixed(value < 10 ? 1 : 0)}${unit}`
}

/** formatBytes renders a byte count in the largest unit that stays readable. */
export function formatBytes(n: number): string {
  const unit = 1024
  if (n < unit) return `${n} B`
  if (n < unit ** 2) return `${(n / unit).toFixed(1)} KiB`
  if (n < unit ** 3) return `${(n / unit ** 2).toFixed(1)} MiB`
  return `${(n / unit ** 3).toFixed(1)} GiB`
}

/**
 * memoryUsageText renders the bytes behind the memory percentage.
 *
 * The figure is summed from the per-alloc breakdown the frame already carries,
 * so this needs nothing new on the wire: the service-level sample has only a
 * percentage, while every alloc reports its own `memory_bytes`. The denominator
 * is the declared cap times the number of allocs that actually reported, which
 * is what keeps the ratio equal to the percentage beside it - that percentage
 * is the mean of the per-alloc ones, and every alloc of a service shares one
 * declared cap.
 *
 * A service with no declared limit is the interesting case and the reason this
 * does not simply mirror the Overview's "used / total": since R11 v1.58 an
 * omitted `resources.memory` is unbounded, the scrapers record no percentage
 * for a limitless alloc, and the panel has therefore always shown a bare dash
 * for such a service. The bytes are recorded regardless, so they are shown
 * alone - a real number where there was nothing, and no invented denominator.
 */
export function memoryUsageText(
  sample: StatsSample | null,
  limitBytes: number | undefined,
): string | undefined {
  let used = 0
  let reporting = 0
  for (const alloc of sample?.allocs ?? []) {
    if (alloc.memory_bytes === undefined) continue
    used += alloc.memory_bytes
    reporting++
  }
  // Nothing measured is not zero used (§9.2): say nothing rather than "0 B".
  if (reporting === 0) return undefined
  if (limitBytes === undefined || limitBytes <= 0) return formatBytes(used)
  return `${formatBytes(used)} / ${formatBytes(limitBytes * reporting)}`
}
