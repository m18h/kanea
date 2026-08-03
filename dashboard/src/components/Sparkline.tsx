import { cn } from '@/lib/utils'

export interface SparklineProps {
  points: (number | undefined)[]
  /** max fixes the vertical scale. Without it the line is scaled to its own
   * range, which makes a flat 2% line look identical to a flat 90% one. */
  max?: number | undefined
  className?: string | undefined
  label?: string | undefined
}

/**
 * Sparkline draws a small line chart as inline SVG.
 *
 * No charting library: this is a polyline over a bounded array, and the
 * dashboard's whole premise is a self-contained bundle inside the §21 budget.
 */
export function Sparkline({ points, max, className, label }: SparklineProps) {
  const width = 120
  const height = 24

  const values = points.filter((p): p is number => p !== undefined)
  const ceiling = max ?? (values.length > 0 ? Math.max(...values) : 1)
  const scale = ceiling > 0 ? ceiling : 1

  // Gaps break the line into segments rather than joining across them.
  const segments: string[] = []
  let current: string[] = []
  points.forEach((value, i) => {
    if (value === undefined) {
      if (current.length > 0) segments.push(current.join(' '))
      current = []
      return
    }
    const x = points.length > 1 ? (i / (points.length - 1)) * width : width / 2
    const y = height - Math.min(value / scale, 1) * height
    current.push(`${x.toFixed(1)},${y.toFixed(1)}`)
  })
  if (current.length > 0) segments.push(current.join(' '))

  if (segments.length === 0) {
    return (
      <span className={cn('text-xs text-muted-foreground', className)} aria-label={label}>
        no data
      </span>
    )
  }

  return (
    <svg
      className={cn('text-primary', className)}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      {segments.map((segment, i) => (
        <polyline
          key={i}
          points={segment}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
        />
      ))}
    </svg>
  )
}
