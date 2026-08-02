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
