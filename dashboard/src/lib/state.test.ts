import { describe, expect, it } from 'vitest'
import { groupAllocs, memoryUsageText, serviceHealth } from '@/lib/state'
import type { Alloc, StatsSample } from '@/lib/api'

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

describe('memoryUsageText', () => {
  const sample = (allocs: Array<{ alloc_id: string; memory_bytes?: number }>): StatsSample =>
    ({ service: 'shop/web', at: '2026-08-21T10:00:00Z', allocs })

  it('sums the allocs and scales the cap by the number reporting', () => {
    // The percentage beside this is the mean of the per-alloc ones, and every
    // alloc of a service shares one declared cap, so summing both halves keeps
    // the ratio and the percentage saying the same thing.
    const text = memoryUsageText(
      sample([
        { alloc_id: 'a', memory_bytes: 100 * 1024 * 1024 },
        { alloc_id: 'b', memory_bytes: 156 * 1024 * 1024 },
      ]),
      256 * 1024 * 1024,
    )

    expect(text).toBe('256.0 MiB / 512.0 MiB')
  })

  it('names the allocation as "all memory" when none is declared', () => {
    // R11 v1.58: an omitted resources.memory is unbounded. There is still an
    // allocation to name, it just is not a number - and the Resources row on
    // the same page has called it "all memory" since v1.58, so this does too.
    expect(memoryUsageText(sample([{ alloc_id: 'a', memory_bytes: 512 * 1024 * 1024 }]), 0))
      .toBe('512.0 MiB / all memory')
    expect(memoryUsageText(sample([{ alloc_id: 'a', memory_bytes: 512 * 1024 * 1024 }]), undefined))
      .toBe('512.0 MiB / all memory')
  })

  it('always reads as used over allocated', () => {
    // The readout answers "how much of what it may have", so the denominator
    // is never dropped: half an answer invites the reader to supply the other
    // half from memory, and they will supply the node's total.
    for (const limit of [0, 256 * 1024 * 1024]) {
      const text = memoryUsageText(sample([{ alloc_id: 'a', memory_bytes: 1024 }]), limit)
      expect(text).toContain(' / ')
    }
  })

  it('counts only the allocs that reported', () => {
    // A just-started alloc has a record and no sample yet. Counting it in the
    // denominator would make a healthy service read as half idle.
    const text = memoryUsageText(
      sample([{ alloc_id: 'a', memory_bytes: 128 * 1024 * 1024 }, { alloc_id: 'b' }]),
      256 * 1024 * 1024,
    )

    expect(text).toBe('128.0 MiB / 256.0 MiB')
  })

  it('says nothing when nothing was measured', () => {
    // Not "0 B": a missing metric and an idle service lead to opposite
    // conclusions, and §9.2 says each layer has to keep them apart.
    expect(memoryUsageText(sample([{ alloc_id: 'a' }]), 256 * 1024 * 1024)).toBeUndefined()
    expect(memoryUsageText(sample([]), 256 * 1024 * 1024)).toBeUndefined()
    expect(memoryUsageText(null, 256 * 1024 * 1024)).toBeUndefined()
  })
})
