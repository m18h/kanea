import { describe, expect, it } from 'vitest'
import { groupAllocs, serviceHealth } from '@/lib/state'
import type { Alloc } from '@/lib/api'

function alloc(service: string, index: number, state = 'running'): Alloc {
  return { id: `shop-${service}-${index}`, project: 'shop', service, index, state }
}

describe('groupAllocs', () => {
  it('groups by service and orders by index', () => {
    const grouped = groupAllocs([alloc('web', 2), alloc('api', 0), alloc('web', 0), alloc('web', 1)])

    expect([...grouped.keys()].sort()).toEqual(['shop/api', 'shop/web'])
    expect(grouped.get('shop/web')?.map((a) => a.index)).toEqual([0, 1, 2])
  })

  it('is empty for no allocs, which is a service scaled to zero', () => {
    expect(groupAllocs([]).size).toBe(0)
  })
})

describe('serviceHealth', () => {
  const running = (n: number) => Array.from({ length: n }, (_, i) => alloc('web', i, 'running'))

  it('is ok only when the desired count is actually running', () => {
    expect(serviceHealth({ Count: 2 }, running(2))).toEqual({ label: 'ok', settled: true })
  })

  // Green while starting would look reassuring during exactly the window
  // someone is watching to see whether it works.
  it('is not settled while starting', () => {
    expect(serviceHealth({ Count: 3 }, running(1))).toEqual({ label: 'starting', settled: false })
  })

  it('reports failure ahead of restarting', () => {
    const allocs = [alloc('web', 0, 'failed'), alloc('web', 1, 'backoff')]
    expect(serviceHealth({ Count: 2 }, allocs).label).toBe('1 failed')
  })

  it('distinguishes a drained stop from one still draining', () => {
    expect(serviceHealth({ Count: 0 }, [])).toEqual({ label: 'stopped', settled: true })
    expect(serviceHealth({ Count: 0 }, running(1))).toEqual({ label: 'stopping', settled: false })
  })
})
