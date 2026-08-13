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
}

/** buildOptions assembles the uPlot options for one metric series. */
export function buildOptions(opts: ChartOptions): uPlot.Options {
  const { width, height, tone, scale, theme, formatValue } = opts
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
        size: 24,
        font: '10px ui-monospace, monospace',
        space: 80,
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
      },
    ],
  }
}
