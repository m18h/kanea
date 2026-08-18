import { useEffect } from 'react'
import type { StatsHistory, HistoryBlock } from '@/lib/api'
import {
  SparklineLength,
  gapSeconds,
  record,
  retain,
  seed as seedStore,
  seedSlots,
  slotsOf,
  snapshotOf,
  type SeriesKey,
  type TimedSeries,
} from '@/lib/seriesStore'

// The accumulation itself lives in lib/seriesStore, so a series outlives the
// component drawing it and a navigation no longer throws minutes of samples
// away. What is left here is the parsing (a history payload into points) and
// the two hooks that bind a key to a panel.
//
// They live apart from the components that draw them for the same reason the
// router's context does: a module exporting both a hook and a component breaks
// fast refresh, and every consumer remounts on each edit.

export {
  SparklineLength,
  seriesKey,
  allocSubject,
  type SeriesKey,
  type TimedSeries,
} from '@/lib/seriesStore'

/** SeriesSeed is a history to start from: slot values (gaps as undefined) and
 * the timestamp of the newest slot, so live samples older than the seed are
 * not double-counted. */
export interface SeriesSeed {
  points: (number | undefined)[]
  asOf: string
}

/** A block of sparse points: either a whole /v1/stats/history body or one of
 * the per-alloc blocks inside it. */
type Block = Pick<HistoryBlock, 'interval_seconds' | 'to' | 'series'>

/**
 * seedFromHistory turns one series of a history block into a SeriesSeed: fixed
 * slots, one per interval, with absent points restored as undefined gaps;
 * "measured nothing" survives the round trip.
 */
export function seedFromHistory(history: Block, series: string): SeriesSeed | undefined {
  const points = history.series[series]
  if (!points || points.length === 0) return undefined

  const interval = history.interval_seconds * 1000
  if (interval <= 0) return undefined
  const to = Date.parse(history.to)
  if (!Number.isFinite(to)) return undefined

  const slots: (number | undefined)[] = Array.from({ length: SparklineLength })
  let newest = ''
  for (const p of points) {
    const at = Date.parse(p.at)
    if (!Number.isFinite(at)) continue
    const slot = SparklineLength - 1 - Math.round((to - at) / interval)
    if (slot < 0 || slot >= SparklineLength) continue
    slots[slot] = p.value
    if (p.at > newest) newest = p.at
  }
  if (newest === '') return undefined

  // Leading slots before the first real point are trimmed: a chart that opens
  // with a wall of gaps reads as an outage nobody had.
  const first = slots.findIndex((v) => v !== undefined)
  return { points: slots.slice(first), asOf: newest }
}

/** mergeSeed prepends a seed to whatever live samples already accumulated. */
export function mergeSeed(
  seed: (number | undefined)[],
  live: (number | undefined)[],
): (number | undefined)[] {
  return [...seed, ...live].slice(-SparklineLength)
}

/**
 * timedSeedFromHistory turns one history series into points at their real
 * timestamps, inserting a null wherever the record goes quiet for longer than
 * gapSeconds: a sparse history must not draw a line across an hour nobody
 * measured.
 */
export function timedSeedFromHistory(
  history: Block,
  series: string,
): (TimedSeries & { asOf: string }) | undefined {
  const points = history.series[series]
  if (!points || points.length === 0) return undefined

  const parsed = points
    .map((p) => ({ t: Date.parse(p.at) / 1000, v: p.value, at: p.at }))
    .filter((p) => Number.isFinite(p.t))
    .sort((a, b) => a.t - b.t)
  if (parsed.length === 0) return undefined

  const times: number[] = []
  const values: (number | null)[] = []
  let asOf = ''
  for (const p of parsed) {
    const prev = times.at(-1)
    if (prev !== undefined && p.t - prev > gapSeconds) {
      times.push(prev + 1)
      values.push(null)
    }
    times.push(p.t)
    values.push(p.v)
    if (p.at > asOf) asOf = p.at
  }
  return { times, values, asOf }
}

/**
 * useTimedSeries accumulates live samples onto their real timestamps,
 * optionally seeded from a history block. Because x is actual time, mixed
 * cadences lay out correctly by construction: there is no slot grid to disagree
 * about.
 *
 * The recording happens during render on purpose, as it always did: the
 * component is *already* re-rendering because the frame that produced this
 * sample changed its props, so state here would cost a second render per
 * sample and return a snapshot one sample stale. What makes that safe is the
 * store's guarantee rather than a local ref: `record` is idempotent and
 * monotonic, so a discarded or doubled render records exactly what its retry
 * would have.
 */
export function useTimedSeries(
  key: SeriesKey,
  value: number | undefined,
  at: string,
  history?: Block | StatsHistory | null,
  series?: string,
): TimedSeries {
  // Retained for as long as this panel is mounted; released on unmount, after
  // which the store keeps it for retainMs so a navigation back is instant.
  useEffect(() => retain(key), [key])

  if (history && series) {
    const parsed = timedSeedFromHistory(history, series)
    // Refused by the store when it is not older than what is already held, so
    // calling it every render is a no-op after the first that matters.
    if (parsed) seedStore(key, parsed)
  }
  record(key, value, at)

  // snapshotOf returns a stable object whose identity changes only when a
  // point lands, which is what the chart's setData effect keys on.
  return snapshotOf(key)
}

/**
 * useSeries accumulates a live value into a bounded slot grid, optionally
 * seeded so a fresh panel is not blank (v1.38).
 *
 * `undefined` is recorded as a gap rather than skipped or zeroed: the daemon
 * omits a metric it has nothing recent for, and a chart that closes over the
 * hole draws a line through data nobody measured.
 */
export function useSeries(
  key: SeriesKey,
  value: number | undefined,
  at: string,
  seed?: SeriesSeed,
): (number | undefined)[] {
  useEffect(() => retain(key), [key])

  if (seed) seedSlots(key, seed.points, seed.asOf)
  record(key, value, at)

  return slotsOf(key)
}
