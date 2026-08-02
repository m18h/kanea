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
