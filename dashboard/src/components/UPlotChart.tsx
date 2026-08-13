import { useEffect, useRef, useState } from 'react'
import uPlot from 'uplot'
import 'uplot/dist/uPlot.min.css'
import { buildOptions, chartColors, type ChartScale } from '@/lib/uplot'
import { formatMetric } from '@/lib/state'
import { cn } from '@/lib/utils'

export interface UPlotChartProps {
  /** Aligned arrays: unix seconds and values; a null value is a gap. */
  times: number[]
  values: (number | null)[]
  unit: string
  label: string
  tone: 1 | 2 | 3 | 4
  /** percent pins y to 0–100; auto pads 10% over the max with a 0 floor. */
  scale: ChartScale
  className?: string | undefined
}

/**
 * UPlotChart is one metric over real time: line, area, time axis, cursor.
 *
 * The instance is created per mount and destroyed on unmount (StrictMode runs
 * that pair twice, harmlessly); new samples arrive by setData, which uPlot
 * redraws without rebuilding — that is what makes the chart move smoothly
 * where the SVG sparkline visibly stepped. A theme flip recreates the chart:
 * colors are baked in at creation and the event is rare.
 */
export function UPlotChart({ times, values, unit, label, tone, scale, className }: UPlotChartProps) {
  const hostRef = useRef<HTMLDivElement>(null)
  const plotRef = useRef<uPlot | null>(null)
  const dataRef = useRef<[number[], (number | null)[]]>([times, values])
  // Latest-props-in-a-ref, so the create effect can seed a fresh instance
  // (e.g. after a theme flip) with current data without depending on it.
  // eslint-disable-next-line react-hooks/refs
  dataRef.current = [times, values]

  // Bumped when the `dark` class flips; the create effect depends on it.
  const [themeEpoch, setThemeEpoch] = useState(0)

  useEffect(() => {
    const observer = new MutationObserver(() => setThemeEpoch((n) => n + 1))
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    const rect = host.getBoundingClientRect()
    const width = rect.width || host.clientWidth || 300
    const height = rect.height || host.clientHeight || 96

    const plot = new uPlot(
      buildOptions({
        width,
        height,
        tone,
        scale,
        theme: chartColors(),
        formatValue: (v) => formatMetric(v, unit),
      }),
      dataRef.current,
      host,
    )
    plotRef.current = plot

    const observer =
      typeof ResizeObserver !== 'undefined'
        ? new ResizeObserver(() => {
            const r = host.getBoundingClientRect()
            if (r.width > 0 && r.height > 0) plot.setSize({ width: r.width, height: r.height })
          })
        : null
    observer?.observe(host)

    return () => {
      observer?.disconnect()
      plotRef.current = null
      plot.destroy()
    }
    // Recreated only on theme/shape changes; data flows through setData below.
  }, [tone, scale, unit, themeEpoch])

  useEffect(() => {
    plotRef.current?.setData([times, values])
  }, [times, values])

  return (
    <div
      ref={hostRef}
      role="img"
      aria-label={label}
      className={cn('min-w-0 [&_.u-over]:cursor-crosshair', className)}
    />
  )
}
