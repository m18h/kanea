import { ChartAreaSkeleton } from '@/components/Skeletons'
import { UPlotChart } from '@/components/UPlotChart'
import type { ChartScale } from '@/lib/uplot'
import type { TimedSeries } from '@/hooks/useSeries'
import type { SeriesStatus } from '@/lib/seriesStatus'
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
  /**
   * detail rides *beside* the readout instead of replacing it, for a number
   * that answers "how much is that?" without displacing the one the chart
   * plots: a service's memory is a percentage of its declared limit, and the
   * bytes behind it are what tells you whether 80% is 200 MiB or 20 GiB.
   * It wraps under the readout when the card is too narrow, rather than
   * truncating: half a byte figure is worse than a second line.
   */
  detail?: string | undefined
  scale: ChartScale
  tone: 1 | 2 | 3 | 4
  /** big is the metric-card form; without it, the compact panel form. */
  big?: boolean | undefined
  /**
   * status explains an empty series: still arriving, genuinely nothing
   * recorded, or a failure. Consulted only when there are no points, because a
   * series with data always draws. Defaults to 'live', so a caller that has
   * nothing to say gets the old behaviour.
   */
  status?: SeriesStatus | undefined
  /** error is the message shown when status is 'error'. */
  error?: string | null | undefined
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
  detail,
  scale,
  tone,
  big,
  status = 'live',
  error,
  className,
}: MetricChartPanelProps) {
  let lastIndex = series.values.length - 1
  while (lastIndex >= 0 && series.values[lastIndex] === null) lastIndex--
  const newest = lastIndex >= 0 ? series.values[lastIndex] : null
  const current = latest ?? (newest === null ? undefined : newest)

  // A series with points always draws; status only ever explains an absence.
  const empty = series.times.length === 0
  const state = empty ? status : 'live'

  return (
    <div className={cn('min-w-0', className)} aria-busy={state === 'loading' || undefined}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-2">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="flex items-baseline gap-1.5">
          <span
            className={cn('font-mono font-semibold tabular-nums', big ? 'text-2xl' : 'text-sm')}
          >
            {/* A gap is a dash: "measured nothing" is not "measured zero". This
                is untouched by the states below, which is the whole reason a
                skeleton is safe here: it stands where a *chart* goes, never
                where a number goes, and nothing renders a zero it did not
                measure. */}
            {valueText ?? (current === undefined ? '-' : formatMetric(current, unit))}
          </span>
          {detail !== undefined ? (
            <span className="font-mono text-xs tabular-nums text-muted-foreground">{detail}</span>
          ) : null}
        </span>
      </div>
      {state === 'live' ? (
        <UPlotChart
          times={series.times}
          values={series.values}
          unit={unit}
          label={label}
          tone={tone}
          scale={scale}
          className={cn('w-full', big ? 'h-24' : 'h-16')}
        />
      ) : state === 'loading' ? (
        <ChartAreaSkeleton big={big} />
      ) : (
        <div
          className={cn(
            'flex items-center justify-center text-[11px]',
            state === 'error' ? 'text-status-error' : 'text-muted-foreground/70',
            big ? 'h-24' : 'h-16',
          )}
        >
          {/* "yet" is the point: it puts the absence in the record rather than
              in the value, which is also the honest thing to say for the ten
              seconds after a restart during which no rate can exist. */}
          {state === 'error' ? (error ?? 'unavailable') : 'no samples yet'}
        </div>
      )}
    </div>
  )
}
