import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { DefaultPageSize, PageSizes, type Pagination } from '@/hooks/usePagination'

/**
 * PaginationControls renders the pager for a usePagination window.
 *
 * It renders nothing for a list that fits at the smallest size: a pager under
 * a seven-row table is chrome announcing a feature nobody needed today. The
 * threshold is the smallest size, not the current one, so choosing "100" on a
 * fifty-row list does not make the selector vanish under the reader.
 */
export function PaginationControls<T>({
  state,
  className,
}: {
  state: Pagination<T>
  className?: string | undefined
}) {
  if (state.total <= DefaultPageSize && state.pages <= 1) return null

  const from = state.start + 1
  const to = state.start + state.pageItems.length

  return (
    <div className={cn('flex flex-wrap items-center justify-between gap-3 pt-3', className)}>
      <span className="text-xs tabular-nums text-muted-foreground">
        {from}: {to} of {state.total}
      </span>
      <div className="flex items-center gap-2">
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          per page
          <select
            value={state.pageSize}
            onChange={(e) => state.setPageSize(Number(e.target.value))}
            aria-label="Rows per page"
            className="h-7 rounded-md border bg-background px-1.5 font-mono text-xs tabular-nums"
          >
            {PageSizes.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
        <Button
          variant="outline"
          size="sm"
          aria-label="Previous page"
          disabled={state.page === 0}
          onClick={() => state.setPage(state.page - 1)}
        >
          <ChevronLeft size={14} />
        </Button>
        <span className="text-xs tabular-nums text-muted-foreground">
          {state.page + 1}/{state.pages}
        </span>
        <Button
          variant="outline"
          size="sm"
          aria-label="Next page"
          disabled={state.page >= state.pages - 1}
          onClick={() => state.setPage(state.page + 1)}
        >
          <ChevronRight size={14} />
        </Button>
      </div>
    </div>
  )
}
