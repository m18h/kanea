import { UPlotChart } from '@/components/UPlotChart'
import type { ChartScale } from '@/lib/uplot'
import type { TimedSeries } from '@/hooks/useSeries'
import { formatMetric } from '@/lib/state'
import { cn } from '@/lib/utils'

export interface MetricChartPanelProps {
  label: string
  /** unit rides both the readout and the axis ("%", "", " ms"). */
  unit: string
  series: TimedSeries
  /** latest overrides the newest point for the big readout; valueText replaces
   * the whole formatted string (memory wants "6.1 / 16 GiB"). */
  latest?: number | undefined
  valueText?: string | undefined
  scale: ChartScale
  tone: 1 | 2 | 3 | 4
  /** big is the metric-card form; without it, the compact panel form. */
  big?: boolean | undefined
  className?: string | undefined
}

/**
 * MetricChartPanel is MetricPanel grown up: the same labelled readout over a
 * real time-axis chart instead of a slot-grid sparkline. The sparkline stays
 * for table cells; this is for the panels with room to breathe.
 */
export function MetricChartPanel({
  label,
  unit,
  series,
  latest,
  valueText,
  scale,
  tone,
  big,
  className,
}: MetricChartPanelProps) {
  let lastIndex = series.values.length - 1
  while (lastIndex >= 0 && series.values[lastIndex] === null) lastIndex--
  const newest = lastIndex >= 0 ? series.values[lastIndex] : null
  const current = latest ?? (newest === null ? undefined : newest)

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
      {series.times.length === 0 ? (
        <div
          className={cn(
            'flex items-center justify-center text-[11px] text-muted-foreground/70',
            big ? 'h-24' : 'h-16',
          )}
        >
          no data
        </div>
      ) : (
        <UPlotChart
          times={series.times}
          values={series.values}
          unit={unit}
          label={label}
          tone={tone}
          scale={scale}
          className={cn('w-full', big ? 'h-24' : 'h-16')}
        />
      )}
    </div>
  )
}
