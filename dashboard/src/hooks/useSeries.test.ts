import { describe, expect, it } from 'vitest'
import { mergeSeed, seedFromHistory, SparklineLength } from '@/hooks/useSeries'
import type { StatsHistory } from '@/lib/api'

function history(points: { at: string; value: number }[]): StatsHistory {
  return {
    subject: 'shop/web',
    from: '2026-08-09T14:00:00Z',
    to: '2026-08-09T14:05:00Z',
    interval_seconds: 5,
    series: { cpu: points },
  }
}

describe('seedFromHistory', () => {
  it('places points into fixed slots and keeps gaps as undefined', () => {
    const seed = seedFromHistory(
      history([
        { at: '2026-08-09T14:05:00Z', value: 42 },
        // Two slots earlier — the slot between was never written.
        { at: '2026-08-09T14:04:50Z', value: 40 },
      ]),
      'cpu',
    )
    expect(seed).toBeDefined()
    const points = seed?.points ?? []
    expect(points[points.length - 1]).toBe(42)
    expect(points[points.length - 2]).toBeUndefined()
    expect(points[points.length - 3]).toBe(40)
    expect(seed?.asOf).toBe('2026-08-09T14:05:00Z')
  })

  it('trims the leading emptiness so a short history is a short line', () => {
    const seed = seedFromHistory(history([{ at: '2026-08-09T14:05:00Z', value: 42 }]), 'cpu')
    expect(seed?.points).toEqual([42])
  })

  it('is undefined for an empty or missing series', () => {
    expect(seedFromHistory(history([]), 'cpu')).toBeUndefined()
    expect(seedFromHistory(history([{ at: '2026-08-09T14:05:00Z', value: 1 }]), 'rps')).toBeUndefined()
  })
})

describe('mergeSeed', () => {
  it('prepends the seed and keeps the ring bounded', () => {
    const seed = Array.from({ length: SparklineLength }, (_, i) => i)
    const merged = mergeSeed(seed, [990, 991])
    expect(merged).toHaveLength(SparklineLength)
    expect(merged[merged.length - 1]).toBe(991)
    expect(merged[0]).toBe(2)
  })

  it('preserves gaps from both sides', () => {
    expect(mergeSeed([1, undefined], [undefined, 2])).toEqual([1, undefined, undefined, 2])
  })
})
