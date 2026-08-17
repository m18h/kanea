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
        // Two slots earlier; the slot between was never written.
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

// ---- useTimedSeries / timedSeedFromHistory (v1.64 charts) ----

import { renderHook } from '@testing-library/react'
import { timedSeedFromHistory, useTimedSeries, type TimedSeries } from './useSeries'

function historyOf(points: { at: string; value: number }[]): StatsHistory {
  return {
    subject: 'node',
    from: points[0]?.at ?? '',
    to: points.at(-1)?.at ?? '',
    interval_seconds: 5,
    series: { cpu: points },
  }
}

describe('timedSeedFromHistory', () => {
  it('keeps real timestamps and inserts a null across a silence', () => {
    const seed = timedSeedFromHistory(
      historyOf([
        { at: '2026-08-13T10:00:00Z', value: 10 },
        { at: '2026-08-13T10:00:05Z', value: 20 },
        // A minute of nothing: the line must break, not bridge.
        { at: '2026-08-13T10:01:10Z', value: 30 },
      ]),
      'cpu',
    )
    expect(seed).toBeDefined()
    expect(seed?.values).toEqual([10, 20, null, 30])
    expect(seed?.times).toHaveLength(4)
    expect(seed?.asOf).toBe('2026-08-13T10:01:10Z')
  })

  it('answers undefined for a series the history does not carry', () => {
    expect(timedSeedFromHistory(historyOf([]), 'cpu')).toBeUndefined()
    expect(
      timedSeedFromHistory(historyOf([{ at: '2026-08-13T10:00:00Z', value: 1 }]), 'rps'),
    ).toBeUndefined()
  })
})

describe('useTimedSeries', () => {
  it('accumulates samples at their timestamps and dedupes repeats', () => {
    const { result, rerender } = renderHook<TimedSeries, { v: number | undefined; at: string }>(
      ({ v, at }) => useTimedSeries(v, at),
      { initialProps: { v: 10, at: '2026-08-13T10:00:00Z' } },
    )
    rerender({ v: 10, at: '2026-08-13T10:00:00Z' }) // repeat: must not double
    rerender({ v: 20, at: '2026-08-13T10:00:05Z' })
    rerender({ v: undefined, at: '2026-08-13T10:00:10Z' }) // a gap, not a zero
    rerender({ v: 40, at: '2026-08-13T10:00:15Z' })

    expect(result.current.values).toEqual([10, 20, null, 40])
    expect(result.current.times).toHaveLength(4)
  })

  it('seeds from history without recording the overlap twice', () => {
    const history = historyOf([
      { at: '2026-08-13T10:00:00Z', value: 10 },
      { at: '2026-08-13T10:00:05Z', value: 20 },
    ])
    const { result, rerender } = renderHook<TimedSeries, { v: number | undefined; at: string }>(
      ({ v, at }) => useTimedSeries(v, at, history, 'cpu'),
      { initialProps: { v: 20, at: '2026-08-13T10:00:05Z' } },
    )
    // The live sample at the seed's newest timestamp is the overlap.
    rerender({ v: 30, at: '2026-08-13T10:00:10Z' })
    expect(result.current.values).toEqual([10, 20, 30])
  })

  it('breaks the line when live samples resume after a silence', () => {
    const { result, rerender } = renderHook<TimedSeries, { v: number | undefined; at: string }>(
      ({ v, at }) => useTimedSeries(v, at),
      { initialProps: { v: 10, at: '2026-08-13T10:00:00Z' } },
    )
    rerender({ v: 20, at: '2026-08-13T10:02:00Z' }) // tab was hidden
    expect(result.current.values).toEqual([10, null, 20])
  })
})
