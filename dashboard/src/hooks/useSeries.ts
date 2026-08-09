import { useEffect, useRef } from 'react'
import type { StatsHistory } from '@/lib/api'

/**
 * How many samples a sparkline keeps.
 *
 * At the daemon's five-second cadence this is five minutes — enough to see a
 * spike arrive and settle, short enough that the shape stays readable at the
 * width a table cell allows.
 */
export const SparklineLength = 60

/** SeriesSeed is a history to start from: slot values (gaps as undefined) and
 * the timestamp of the newest slot, so live samples older than the seed are
 * not double-counted. */
export interface SeriesSeed {
  points: (number | undefined)[]
  asOf: string
}

/**
 * seedFromHistory turns one series of a /v1/stats/history response into a
 * SeriesSeed: fixed slots, one per interval, with absent points restored as
 * undefined gaps — "measured nothing" survives the round trip.
 */
export function seedFromHistory(history: StatsHistory, series: string): SeriesSeed | undefined {
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
 * useSeries accumulates a live value into a bounded history, optionally
 * seeded from /v1/stats/history so a fresh page is not blank (v1.38).
 *
 * `undefined` is appended as a gap rather than skipped or zeroed: the daemon
 * omits a metric it has nothing recent for, and a chart that closes over the
 * hole draws a line through data nobody measured.
 *
 * It lives apart from the component that draws it for the same reason the
 * router's context does: a module exporting both a hook and a component breaks
 * fast refresh, and every consumer remounts on each edit.
 */
export function useSeries(
  value: number | undefined,
  at: string,
  seed?: SeriesSeed,
): (number | undefined)[] {
  const series = useRef<(number | undefined)[]>([])
  // Keyed on the sample's timestamp so React's strict-mode double render — or
  // a re-render for an unrelated prop — does not record the same sample twice.
  const lastAt = useRef<string>('')
  const seeded = useRef(false)

  useEffect(() => {
    if (seed === undefined || seeded.current) return
    seeded.current = true
    series.current = mergeSeed(seed.points, series.current)
    // The newest history point supersedes any older live sample's guard: a
    // live sample at or before asOf is the overlap between "history up to T"
    // and the first frames, and must not be recorded twice.
    if (lastAt.current === '' || lastAt.current <= seed.asOf) lastAt.current = seed.asOf
  }, [seed])

  useEffect(() => {
    if (at === lastAt.current) return
    // ISO-8601 in UTC compares lexicographically; anything unparsable falls
    // back to the exact-match guard above.
    if (seeded.current && lastAt.current !== '' && at !== '' && at < lastAt.current) return
    lastAt.current = at
    series.current = [...series.current, value].slice(-SparklineLength)
  }, [value, at])

  // Read during render on purpose: the consumer re-renders because the sample
  // that grew the series also changed its props, so the value is never stale —
  // and state here would re-render every consumer a second time per sample.
  // eslint-disable-next-line react-hooks/refs
  return series.current
}
