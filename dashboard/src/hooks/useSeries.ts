import { useEffect, useRef } from 'react'

/**
 * How many samples a sparkline keeps.
 *
 * At the daemon's five-second cadence this is five minutes — enough to see a
 * spike arrive and settle, short enough that the shape stays readable at the
 * width a table cell allows.
 */
export const SparklineLength = 60

/**
 * useSeries accumulates a live value into a bounded history.
 *
 * `undefined` is appended as a gap rather than skipped or zeroed: the daemon
 * omits a metric it has nothing recent for, and a chart that closes over the
 * hole draws a line through data nobody measured.
 *
 * It lives apart from the component that draws it for the same reason the
 * router's context does: a module exporting both a hook and a component breaks
 * fast refresh, and every consumer remounts on each edit.
 */
export function useSeries(value: number | undefined, at: string): (number | undefined)[] {
  const series = useRef<(number | undefined)[]>([])
  // Keyed on the sample's timestamp so React's strict-mode double render — or
  // a re-render for an unrelated prop — does not record the same sample twice.
  const lastAt = useRef<string>('')

  useEffect(() => {
    if (at === lastAt.current) return
    lastAt.current = at
    series.current = [...series.current, value].slice(-SparklineLength)
  }, [value, at])

  return series.current
}
