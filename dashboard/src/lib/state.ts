import type { BadgeProps } from '@/components/ui/badge'
import type { Alloc } from '@/lib/api'

/** allocStateVariant maps an alloc state to how alarming it should look. */
export function allocStateVariant(state: string): NonNullable<BadgeProps['variant']> {
  switch (state) {
    case 'running':
      return 'ok'
    case 'backoff':
    case 'pending':
      return 'warn'
    case 'failed':
      return 'error'
    default:
      return 'muted'
  }
}

/** groupAllocs indexes allocs by their service, in stable index order. */
export function groupAllocs(allocs: Alloc[]): Map<string, Alloc[]> {
  const out = new Map<string, Alloc[]>()
  for (const alloc of allocs) {
    const key = `${alloc.Project}/${alloc.Service}`
    const existing = out.get(key)
    if (existing) existing.push(alloc)
    else out.set(key, [alloc])
  }
  for (const group of out.values()) {
    group.sort((a, b) => a.Index - b.Index)
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
 * "ok" means settled, not merely "nothing has failed yet" — a service that is
 * still starting is not ok, or the dashboard would look green during exactly
 * the window an operator is watching it.
 */
export function serviceHealth(service: { Count: number }, allocs: Alloc[]): Health {
  const running = allocs.filter((a) => a.State === 'running').length
  const backoff = allocs.filter((a) => a.State === 'backoff').length
  const failed = allocs.filter((a) => a.State === 'failed').length

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
 * a glance is asking — is anything failing — where twenty codes would need
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
