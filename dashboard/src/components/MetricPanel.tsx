import { Sparkline, type SparklineProps } from '@/components/Sparkline'
import { formatMetric } from '@/lib/state'
import { cn } from '@/lib/utils'

export interface MetricPanelProps {
  label: string
  /** unit rides both the readout and the hover ("%", "", " ms"). */
  unit: string
  points: (number | undefined)[]
  /** latest overrides the newest point for the big readout; valueText replaces
   * the whole formatted string (memory wants "6.1 / 16 GiB"). */
  latest?: number | undefined
  valueText?: string | undefined
  max?: number | undefined
  tone: NonNullable<SparklineProps['tone']>
  /** big is the metric-card form; without it, the compact 2×2 panel form. */
  big?: boolean | undefined
  className?: string | undefined
}

/**
 * MetricPanel is a labelled sparkline with its current value: the mockup's
 * "CPU 38% ~~~" unit, used 2×2 on the Dashboard and as cards on ServiceDetail.
 */
export function MetricPanel({
  label,
  unit,
  points,
  latest,
  valueText,
  max,
  tone,
  big,
  className,
}: MetricPanelProps) {
  let lastIndex = points.length - 1
  while (lastIndex >= 0 && points[lastIndex] === undefined) lastIndex--
  const current = latest ?? (lastIndex >= 0 ? points[lastIndex] : undefined)

  return (
    <div className={cn('min-w-0', className)}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span
          className={cn('font-mono font-semibold tabular-nums', big ? 'text-2xl' : 'text-sm')}
        >
          {/* A gap is a dash: "measured nothing" is not "measured zero". */}
          {valueText ?? (current === undefined ? '—' : formatMetric(current, unit))}
        </span>
      </div>
      <Sparkline
        points={points}
        tone={tone}
        unit={unit}
        label={label}
        className={cn('w-full', big ? 'h-12' : 'h-9')}
        {...(max !== undefined ? { max } : {})}
      />
    </div>
  )
}
