import { useEffect, useRef } from 'react'
import type { StatsHistory } from '@/lib/api'

/**
 * How many samples a sparkline keeps.
 *
 * At the daemon's five-second cadence this is five minutes: enough to see a
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
 * undefined gaps; "measured nothing" survives the round trip.
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

/** TimedSeries is a series over real time: aligned unix-seconds and values,
 * null marking a gap; uPlot's native vocabulary. */
export interface TimedSeries {
  times: number[]
  values: (number | null)[]
}

/** How many timed points a chart keeps: the 15 m history window at the 5 s
 * cadence, with headroom for a long-open page. */
const maxTimedPoints = 400

/** A silence longer than this breaks the line: the samples on either side are
 * real, the time between them was never measured. */
const gapSeconds = 30

/**
 * timedSeedFromHistory turns one /v1/stats/history series into TimedSeries
 * points at their real timestamps, inserting a null wherever the record goes
 * quiet for longer than gapSeconds: a sparse history must not draw a line
 * across an hour nobody measured.
 */
export function timedSeedFromHistory(
  history: StatsHistory,
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
 * optionally seeded from /v1/stats/history. Because x is actual time, mixed
 * cadences (a 5 s history under a 10 s poll) lay out correctly by
 * construction: there is no slot grid to disagree about.
 *
 * Same discipline as useSeries below: an undefined value is a gap (null),
 * samples dedupe on their timestamp, and the returned object's identity
 * changes exactly when a point lands, which is what lets a chart call
 * setData only when there is new data.
 */
export function useTimedSeries(
  value: number | undefined,
  at: string,
  history?: StatsHistory | null,
  series?: string,
): TimedSeries {
  /* eslint-disable react-hooks/refs -- the accumulation below runs during
     render on purpose: every step is guarded to be idempotent (the seeded
     flag, the lastAt dedupe), so a StrictMode double render records nothing
     twice, and the snapshot returned is never one sample stale the way an
     effect-time append would make it. */
  const times = useRef<number[]>([])
  const values = useRef<(number | null)[]>([])
  const snapshot = useRef<TimedSeries>({ times: [], values: [] })
  const lastAt = useRef<string>('')
  const seeded = useRef(false)

  if (!seeded.current && history && series) {
    seeded.current = true
    const seed = timedSeedFromHistory(history, series)
    if (seed) {
      times.current = [...seed.times, ...times.current].slice(-maxTimedPoints)
      values.current = [...seed.values, ...values.current].slice(-maxTimedPoints)
      if (lastAt.current === '' || lastAt.current <= seed.asOf) lastAt.current = seed.asOf
      snapshot.current = { times: [...times.current], values: [...values.current] }
    }
  }

  const fresh = at !== '' && at !== lastAt.current && !(lastAt.current !== '' && at < lastAt.current)
  if (fresh) {
    const t = Date.parse(at) / 1000
    if (Number.isFinite(t)) {
      lastAt.current = at
      const prev = times.current.at(-1)
      if (prev === undefined || t > prev) {
        if (prev !== undefined && t - prev > gapSeconds) {
          times.current.push(prev + 1)
          values.current.push(null)
        }
        times.current.push(t)
        values.current.push(value ?? null)
        if (times.current.length > maxTimedPoints) {
          times.current = times.current.slice(-maxTimedPoints)
          values.current = values.current.slice(-maxTimedPoints)
        }
        snapshot.current = { times: [...times.current], values: [...values.current] }
      }
    }
  }

  return snapshot.current
  /* eslint-enable react-hooks/refs */
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
  // Keyed on the sample's timestamp so React's strict-mode double render (or
  // a re-render for an unrelated prop) does not record the same sample twice.
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
  // that grew the series also changed its props, so the value is never stale;
  // and state here would re-render every consumer a second time per sample.
  // eslint-disable-next-line react-hooks/refs
  return series.current
}
