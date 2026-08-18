import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  clearAll,
  maxTimedPoints,
  record,
  retain,
  retainMs,
  seed,
  seedSlots,
  seriesKey,
  size,
  slotsOf,
  snapshotOf,
  subscribe,
} from '@/lib/seriesStore'

// The store is module state, which is the one real hazard in testing it: a case
// that leaks into the next one passes for the wrong reason.
beforeEach(() => clearAll())

const key = seriesKey('shop/web', 'cpu')

describe('record', () => {
  it('appends a sample and changes the snapshot identity', () => {
    const before = snapshotOf(key)
    record(key, 10, '2026-08-13T10:00:00Z')
    const after = snapshotOf(key)

    expect(after).not.toBe(before)
    expect(after.values).toEqual([10])
  })

  it('does not change identity when the same timestamp is recorded again', () => {
    // The UPlotChart contract: it calls setData on the snapshot's identity, so
    // a no-op record must not look like new data.
    record(key, 10, '2026-08-13T10:00:00Z')
    const first = snapshotOf(key)
    record(key, 10, '2026-08-13T10:00:00Z')
    record(key, 99, '2026-08-13T10:00:00Z')

    expect(snapshotOf(key)).toBe(first)
    expect(snapshotOf(key).values).toEqual([10])
  })

  it('refuses a sample older than the newest', () => {
    record(key, 10, '2026-08-13T10:00:05Z')
    record(key, 99, '2026-08-13T10:00:00Z')

    expect(snapshotOf(key).values).toEqual([10])
  })

  it('records an absent value as a gap, never a zero', () => {
    record(key, 10, '2026-08-13T10:00:00Z')
    record(key, undefined, '2026-08-13T10:00:05Z')

    expect(snapshotOf(key).values).toEqual([10, null])
  })

  it('breaks the line across a silence', () => {
    record(key, 10, '2026-08-13T10:00:00Z')
    record(key, 20, '2026-08-13T10:02:00Z')

    expect(snapshotOf(key).values).toEqual([10, null, 20])
  })

  it('is bounded', () => {
    const start = Date.parse('2026-08-13T10:00:00Z')
    for (let i = 0; i < maxTimedPoints + 50; i++) {
      record(key, i, new Date(start + i * 5_000).toISOString())
    }
    expect(snapshotOf(key).values).toHaveLength(maxTimedPoints)
    expect(snapshotOf(key).times).toHaveLength(maxTimedPoints)
  })
})

describe('seed', () => {
  it('prepends history under the live samples', () => {
    record(key, 30, '2026-08-13T10:00:10Z')
    seed(key, {
      times: [Date.parse('2026-08-13T10:00:00Z') / 1000, Date.parse('2026-08-13T10:00:05Z') / 1000],
      values: [10, 20],
      asOf: '2026-08-13T10:00:05Z',
    })

    expect(snapshotOf(key).values).toEqual([10, 20, 30])
  })

  it('takes nothing from a seed that is not older than what is held', () => {
    // A live sample is authoritative for its own instant; a seed covering the
    // same ground must not rewrite it.
    record(key, 30, '2026-08-13T10:00:10Z')
    seed(key, {
      times: [Date.parse('2026-08-13T10:00:10Z') / 1000],
      values: [99],
      asOf: '2026-08-13T10:00:10Z',
    })

    expect(snapshotOf(key).values).toEqual([30])
  })

  it('is idempotent, so a hook may call it on every render', () => {
    // After the first seed the oldest held point is the seed's own first
    // point, so a repeat has nothing older to contribute. That is what
    // replaces the "have I seeded yet" flag the hooks used to carry.
    const s = {
      times: [Date.parse('2026-08-13T10:00:00Z') / 1000, Date.parse('2026-08-13T10:00:05Z') / 1000],
      values: [10, 20],
      asOf: '2026-08-13T10:00:05Z',
    }
    seed(key, s)
    const first = snapshotOf(key)
    seed(key, s)
    seed(key, s)

    expect(snapshotOf(key).values).toEqual([10, 20])
    expect(snapshotOf(key)).toBe(first)
  })

  it('prepends only the portion older than the oldest held point', () => {
    // The overlap between "history up to T" and the first live frames must not
    // be counted twice.
    record(key, 20, '2026-08-13T10:00:05Z')
    seed(key, {
      times: [
        Date.parse('2026-08-13T10:00:00Z') / 1000,
        Date.parse('2026-08-13T10:00:05Z') / 1000,
      ],
      values: [10, 20],
      asOf: '2026-08-13T10:00:04Z',
    })

    expect(snapshotOf(key).values).toEqual([10, 20])
  })
})

describe('the slot grid', () => {
  it('accumulates and seeds independently of the timed series', () => {
    seedSlots(key, [1, 2], '2026-08-13T10:00:00Z')
    record(key, 3, '2026-08-13T10:00:05Z')

    expect(slotsOf(key)).toEqual([1, 2, 3])
  })
})

describe('lifetime', () => {
  it('survives a release and re-retain, which is the whole point', () => {
    // The regression this store exists for: a panel that unmounts and remounts
    // (any navigation away and back) used to rebuild from nothing.
    const release = retain(key)
    record(key, 10, '2026-08-13T10:00:00Z')
    release()

    retain(key)
    expect(snapshotOf(key).values).toEqual([10])
  })

  it('drops an entry nobody has referenced for retainMs', () => {
    const release = retain(key)
    record(key, 10, '2026-08-13T10:00:00Z')
    release()

    // A later retain of some *other* key is what sweeps; there is deliberately
    // no timer doing it in the background.
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + retainMs + 1)
    retain(seriesKey('shop/other', 'cpu'))
    vi.restoreAllMocks()

    expect(snapshotOf(key).values).toEqual([])
  })

  it('never evicts a referenced entry to satisfy the cap', () => {
    const held = seriesKey('shop/held', 'cpu')
    retain(held)
    record(held, 42, '2026-08-13T10:00:00Z')

    // Far more keys than the cap, none of them referenced.
    for (let i = 0; i < 400; i++) {
      const other = seriesKey(`shop/svc-${i}`, 'cpu')
      const release = retain(other)
      record(other, i, '2026-08-13T10:00:00Z')
      release()
    }

    expect(snapshotOf(held).values).toEqual([42])
    expect(size()).toBeLessThanOrEqual(401)
  })
})

describe('subscribe', () => {
  it('notifies a listener when a point lands', async () => {
    const seen = vi.fn()
    subscribe(key, seen)
    record(key, 10, '2026-08-13T10:00:00Z')

    // Notifications are deferred so a record during one component's render
    // cannot synchronously schedule a state update in another.
    await Promise.resolve()
    expect(seen).toHaveBeenCalled()
  })

  it('stops notifying after unsubscribe', async () => {
    const seen = vi.fn()
    subscribe(key, seen)()
    record(key, 10, '2026-08-13T10:00:00Z')

    await Promise.resolve()
    expect(seen).not.toHaveBeenCalled()
  })
})
