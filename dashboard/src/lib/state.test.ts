import { describe, expect, it } from 'vitest'
import { groupAllocs } from '@/lib/state'
import type { Alloc } from '@/lib/api'

function alloc(service: string, index: number, state = 'running'): Alloc {
  return { ID: `shop-${service}-${index}`, Project: 'shop', Service: service, Index: index, State: state }
}

describe('groupAllocs', () => {
  it('groups by service and orders by index', () => {
    const grouped = groupAllocs([alloc('web', 2), alloc('api', 0), alloc('web', 0), alloc('web', 1)])

    expect([...grouped.keys()].sort()).toEqual(['shop/api', 'shop/web'])
    expect(grouped.get('shop/web')?.map((a) => a.Index)).toEqual([0, 1, 2])
  })

  it('is empty for no allocs, which is a service scaled to zero', () => {
    expect(groupAllocs([]).size).toBe(0)
  })
})
