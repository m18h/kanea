import type uPlot from 'uplot'

/**
 * Pure helpers behind UPlotChart, split out so the option-building logic is
 * testable without a canvas (uPlot itself needs a 2d context jsdom lacks).
 */

export type ChartScale = 'percent' | 'auto'

export interface ChartTheme {
  /** stroke per tone, matching the Sparkline's text-chart-1..4 mapping. */
  stroke: Record<1 | 2 | 3 | 4, string>
  /** translucent fill per tone, for the area under the line. */
  fill: Record<1 | 2 | 3 | 4, string>
  grid: string
  axis: string
}

/** cssVar reads one HSL triplet custom property off the document root. */
function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

/**
 * chartColors resolves the app's chart palette at call time — the CSS vars
 * flip with the `dark` class, so the caller re-reads on a theme change rather
 * than caching across one.
 */
export function chartColors(): ChartTheme {
  const tone = (n: 1 | 2 | 3 | 4) => cssVar(`--chart-${n}`)
  const stroke = {} as ChartTheme['stroke']
  const fill = {} as ChartTheme['fill']
  for (const n of [1, 2, 3, 4] as const) {
    const v = tone(n)
    stroke[n] = `hsl(${v})`
    fill[n] = `hsl(${v} / 0.12)`
  }
  return {
    stroke,
    fill,
    grid: `hsl(${cssVar('--border')} / 0.6)`,
    axis: `hsl(${cssVar('--muted-foreground')})`,
  }
}

/**
 * smoothValues is a centered moving average for display: raw 5s samples of an
 * instantaneous reading are honest but unreadable at two pixels per point.
 * Null-aware — a gap stays a gap and never borrows neighbours across it, so
 * "absent is never zero" survives the smoothing (§9.2). The readout beside
 * the chart still shows the raw latest sample.
 */
export function smoothValues(values: (number | null)[], window: number): (number | null)[] {
  if (window <= 1) return values
  const half = Math.floor(window / 2)
  return values.map((v, i) => {
    if (v === null) return null
    let sum = v
    let n = 1
    // Walk outward, stopping each direction at its first gap: skipping a null
    // and continuing past it would average across a hole and drag the line
    // toward whatever sits on the far side.
    let left = true
    let right = true
    for (let d = 1; d <= half; d++) {
      if (left) {
        const w = values[i - d]
        if (i - d < 0 || w === null || w === undefined) {
          left = false
        } else {
          sum += w
          n++
        }
      }
      if (right) {
        const w = values[i + d]
        if (i + d >= values.length || w === null || w === undefined) {
          right = false
        } else {
          sum += w
          n++
        }
      }
    }
    return sum / n
  })
}

/** timeLabel renders a tick as HH:MM — one line, unlike uPlot's stacked
 * time-over-date default, which clips inside a compact panel. */
export function timeLabel(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

/** percentRange pins a 0–100 metric so a flat 2% and a flat 90% line differ. */
export function percentRange(): [number, number] {
  return [0, 100]
}

/**
 * paddedRange floors at zero and pads 10% above the maximum, so a spike has
 * headroom without inventing negative rates. An all-gap or all-zero series
 * gets [0, 1] rather than a degenerate scale.
 */
export function paddedRange(max: number): [number, number] {
  if (!Number.isFinite(max) || max <= 0) return [0, 1]
  return [0, max * 1.1]
}

export interface ChartOptions {
  width: number
  height: number
  tone: 1 | 2 | 3 | 4
  scale: ChartScale
  theme: ChartTheme
  /** formatValue renders the y value in the axis and cursor readout. */
  formatValue: (v: number) => string
  /** paths draws the series — the caller passes uPlot.paths.spline() so the
   * 5s samples read as a curve rather than a jag per sample. Injected rather
   * than imported here, keeping this module value-free of uPlot (testable
   * without a canvas). */
  paths?: uPlot.Series.PathBuilder | undefined
}

/** buildOptions assembles the uPlot options for one metric series. */
export function buildOptions(opts: ChartOptions): uPlot.Options {
  const { width, height, tone, scale, theme, formatValue, paths } = opts
  return {
    width,
    height,
    legend: { show: false },
    padding: [8, 8, 0, 0],
    cursor: {
      y: false,
      points: { size: 6, width: 2 },
    },
    scales: {
      x: { time: true },
      y:
        scale === 'percent'
          ? { range: percentRange() }
          : { range: (_u: uPlot, _min: number, max: number) => paddedRange(max) },
    },
    axes: [
      {
        stroke: theme.axis,
        grid: { show: false },
        ticks: { show: false },
        size: 18,
        font: '10px ui-monospace, monospace',
        space: 80,
        // One line, HH:MM. The default stacks the date under the time and the
        // second line clips inside a compact panel.
        values: (_u: uPlot, ticks: number[]) => ticks.map(timeLabel),
      },
      {
        stroke: theme.axis,
        grid: { stroke: theme.grid, width: 1 },
        ticks: { show: false },
        size: 40,
        font: '10px ui-monospace, monospace',
        space: 24,
        values: (_u: uPlot, ticks: number[]) => ticks.map((t) => formatValue(t)),
      },
    ],
    series: [
      {},
      {
        stroke: theme.stroke[tone],
        fill: theme.fill[tone],
        width: 1.5,
        // A gap in the data is a gap on screen — absent is never zero, and
        // never a line drawn through time nobody measured (PRD §9.2).
        spanGaps: false,
        points: { show: false },
        ...(paths !== undefined ? { paths } : {}),
      },
    ],
  }
}
