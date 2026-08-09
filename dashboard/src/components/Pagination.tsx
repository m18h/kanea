import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import type { Pagination } from '@/hooks/usePagination'

/**
 * PaginationControls renders the pager for a usePagination window.
 *
 * It renders nothing for a list that fits on one page: a pager under a
 * seven-row table is chrome announcing a feature nobody needed today.
 */
export function PaginationControls<T>({
  state,
  className,
}: {
  state: Pagination<T>
  className?: string | undefined
}) {
  if (state.pages <= 1) return null

  const from = state.start + 1
  const to = state.start + state.pageItems.length

  return (
    <div className={cn('flex items-center justify-between gap-3 pt-3', className)}>
      <span className="text-xs tabular-nums text-muted-foreground">
        {from}–{to} of {state.total}
      </span>
      <div className="flex items-center gap-2">
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
