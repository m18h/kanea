import { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { formatMetric } from '@/lib/state'

export interface SparklineProps {
  points: (number | undefined)[]
  /** max fixes the vertical scale. Without it the line is scaled to its own
   * range, which makes a flat 2% line look identical to a flat 90% one. */
  max?: number | undefined
  className?: string | undefined
  label?: string | undefined
  /** unit rides the hover readout ("%", "/s", " ms"). */
  unit?: string | undefined
  /** tone picks the series colour: 1 amber, 2 blue, 3 green, 4 red. Identity
   * never rides on the hue alone — every sparkline sits under its own label. */
  tone?: 1 | 2 | 3 | 4 | undefined
}

// A static map, never a template string: Tailwind's scanner only keeps class
// names it can read verbatim from the source.
const toneClass = {
  1: 'text-chart-1',
  2: 'text-chart-2',
  3: 'text-chart-3',
  4: 'text-chart-4',
} as const

/** The plot keeps this much air above the line and beside the end dot, so the
 * marker is never clipped by its own viewport. */
const padTop = 6
const padRight = 6

/**
 * Sparkline draws a small line chart as inline SVG.
 *
 * No charting library: this is a couple of paths over a bounded array, and the
 * dashboard's whole premise is a self-contained bundle inside the §21 budget.
 * The marks follow the usual smallmark grammar — a 2px line, a thin area wash
 * under it, an end dot ringed in the surface color, and a hairline baseline —
 * and a crosshair readout on hover, because a chart whose values can only be
 * guessed at is a decoration.
 */
export function Sparkline({ points, max, className, label, unit = '', tone }: SparklineProps) {
  const wrap = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ w: 120, h: 24 })
  const [hover, setHover] = useState<number | null>(null)

  // The chart fills whatever box the caller's classes give the wrapper. Sizing
  // from the container (rather than fixed props) is what lets the same
  // component be a table-cell mini and a full-width panel chart.
  //
  // The wrapper (and so this ref) exists from the first render even while the
  // chart shows "no data" — the observer must attach then, because an effect
  // with no dependencies will not run again when the data arrives, and a
  // viewBox stuck at the 120px fallback under a CSS-stretched svg puts every
  // hover coordinate somewhere other than the mouse.
  useEffect(() => {
    const el = wrap.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const measure = () => setSize({ w: el.clientWidth || 120, h: el.clientHeight || 24 })
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const { w, h } = size
  const values = points.filter((p): p is number => p !== undefined)
  const ceiling = max ?? (values.length > 0 ? Math.max(...values) : 1)
  const scale = ceiling > 0 ? ceiling : 1

  const baseY = h - 1
  const plotW = Math.max(w - padRight - 1, 1)
  const xAt = (i: number) => (points.length > 1 ? (i / (points.length - 1)) * plotW + 1 : w / 2)
  const yAt = (v: number) => baseY - Math.min(v / scale, 1) * (baseY - padTop)

  // Gaps break the line into segments rather than joining across them: the
  // daemon omits a metric it has nothing recent for, and a line drawn through
  // the hole is data nobody measured.
  const segments: { line: string; area: string }[] = []
  let current: { x: number; y: number }[] = []
  const closeSegment = () => {
    if (current.length === 0) return
    const line = current.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
    const first = current[0]
    const last = current[current.length - 1]
    const area =
      first !== undefined && last !== undefined
        ? `M${first.x.toFixed(1)},${baseY} L${line.split(' ').join(' L')} L${last.x.toFixed(1)},${baseY} Z`
        : ''
    segments.push({ line, area })
    current = []
  }
  points.forEach((value, i) => {
    if (value === undefined) {
      closeSegment()
      return
    }
    current.push({ x: xAt(i), y: yAt(value) })
  })
  closeSegment()

  const empty = segments.length === 0

  let lastIndex = points.length - 1
  while (lastIndex >= 0 && points[lastIndex] === undefined) lastIndex--
  const lastValue = points[lastIndex]

  const hoverValue = hover !== null ? points[hover] : undefined

  // Both sides of the mapping — this and xAt — are in the same coordinate
  // space only because the observed size *is* the CSS size. rect.width is
  // used here (not state) so a pointer event racing a resize still lands.
  const locate = (clientX: number): number => {
    const rect = wrap.current?.getBoundingClientRect()
    const width = rect?.width || w
    const rel = ((clientX - (rect?.left ?? 0)) / width) * w
    const step = points.length > 1 ? plotW / (points.length - 1) : 1
    const i = Math.round((rel - 1) / step)
    return Math.max(0, Math.min(points.length - 1, i))
  }

  if (empty) {
    return (
      <div ref={wrap} className={cn('flex items-center', className ?? 'h-6 w-[120px]')}>
        <span className="text-xs text-muted-foreground" aria-label={label}>
          no data
        </span>
      </div>
    )
  }

  return (
    <div
      ref={wrap}
      className={cn('relative', toneClass[tone ?? 2], className ?? 'h-6 w-[120px]')}
      onPointerMove={(e) => setHover(locate(e.clientX))}
      onPointerLeave={() => setHover(null)}
      // The readout is reachable without a pointer: focus shows the newest
      // sample, the same detail hover would.
      tabIndex={0}
      onFocus={() => setHover(lastIndex)}
      onBlur={() => setHover(null)}
    >
      <svg
        className="block h-full w-full"
        width={w}
        height={h}
        viewBox={`0 0 ${w} ${h}`}
        role="img"
        aria-label={label}
      >
        {/* The baseline anchors the shape; hairline and recessive. */}
        <line x1={0} x2={w} y1={baseY + 0.5} y2={baseY + 0.5} className="stroke-border" strokeWidth={1} />
        {segments.map((segment, i) => (
          <g key={i}>
            {segment.area ? <path d={segment.area} fill="currentColor" opacity={0.1} /> : null}
            <polyline
              points={segment.line}
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          </g>
        ))}
        {hover !== null ? (
          <line
            x1={xAt(hover)}
            x2={xAt(hover)}
            y1={0}
            y2={baseY}
            className="stroke-border"
            strokeWidth={1}
          />
        ) : null}
        {hover !== null && hoverValue !== undefined ? (
          <circle cx={xAt(hover)} cy={yAt(hoverValue)} r={3.5} fill="currentColor" className="stroke-card" strokeWidth={2} />
        ) : null}
        {/* The end dot marks "now" — ringed in the surface color so it stays
            legible where it sits on the line. */}
        {hover === null && lastValue !== undefined ? (
          <circle cx={xAt(lastIndex)} cy={yAt(lastValue)} r={3.5} fill="currentColor" className="stroke-card" strokeWidth={2} />
        ) : null}
      </svg>
      {hover !== null ? (
        <div
          className="pointer-events-none absolute -top-6 z-10 -translate-x-1/2 whitespace-nowrap rounded border bg-card px-1.5 py-0.5 font-mono text-xs tabular-nums text-card-foreground shadow-sm"
          style={{ left: Math.max(20, Math.min(w - 20, xAt(hover))) }}
        >
          {/* An em dash for a gap, not a zero: "measured nothing" is not
              "measured zero". */}
          {hoverValue === undefined ? '—' : formatMetric(hoverValue, unit)}
        </div>
      ) : null}
    </div>
  )
}
