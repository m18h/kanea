import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

/**
 * Loading compositions matching the real layouts they stand in for. Heights
 * mirror the components they replace (KeyValue rows, table rows, MetricPanel
 * charts) so the swap from skeleton to data does not shift the page.
 */

/** KeyValueSkeleton matches a run of KeyValue label/value rows. */
export function KeyValueSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div aria-hidden aria-busy>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="flex items-baseline justify-between gap-3 border-b border-border/50 py-1.5 last:border-0"
        >
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-32" />
        </div>
      ))}
    </div>
  )
}

/** TableSkeleton stands in for a table card while its rows load. */
export function TableSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <Card aria-hidden aria-busy className="p-4">
      <div className="space-y-3">
        <div className="flex gap-4">
          {Array.from({ length: cols }, (_, i) => (
            <Skeleton key={i} className="h-3.5 flex-1" />
          ))}
        </div>
        {Array.from({ length: rows }, (_, r) => (
          <div key={r} className="flex gap-4">
            {Array.from({ length: cols }, (_, c) => (
              <Skeleton key={c} className="h-4 flex-1 opacity-70" />
            ))}
          </div>
        ))}
      </div>
    </Card>
  )
}

/** CardSkeleton is a generic card body: an optional title over text lines. */
export function CardSkeleton({ lines = 3, title = true }: { lines?: number; title?: boolean }) {
  return (
    <div aria-hidden aria-busy className="space-y-2.5">
      {title ? <Skeleton className="h-4 w-40" /> : null}
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={cn('h-4', i === lines - 1 ? 'w-2/3' : 'w-full')} />
      ))}
    </div>
  )
}

/** ChartSkeleton matches a MetricPanel: label, big value, chart area. */
export function ChartSkeleton({ big }: { big?: boolean }) {
  return (
    <div aria-hidden aria-busy className="space-y-2">
      <Skeleton className="h-3.5 w-20" />
      <Skeleton className={big ? 'h-8 w-24' : 'h-5 w-16'} />
      <Skeleton className={big ? 'h-12 w-full' : 'h-9 w-full'} />
    </div>
  )
}
