import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react'
import { TH } from '@/components/ui/table'
import { cn } from '@/lib/utils'
import type { Sort } from '@/hooks/useSort'

/**
 * SortHeader is a TH the reader can click to sort by that column.
 *
 * The double chevron on an inactive column is the affordance — without it a
 * sortable header and a plain one are indistinguishable, and the feature only
 * exists for whoever happens to click a label.
 */
export function SortHeader<K extends string>({
  sort,
  sortKey,
  className,
  children,
}: {
  sort: Sort<K>
  sortKey: K
  className?: string | undefined
  children: React.ReactNode
}) {
  const active = sort.key === sortKey
  return (
    <TH
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}
      className={className}
    >
      <button
        type="button"
        onClick={() => sort.toggle(sortKey)}
        className={cn(
          'inline-flex items-center gap-1 uppercase tracking-wider transition-colors hover:text-foreground',
          active && 'text-foreground',
        )}
      >
        {children}
        {!active ? (
          <ChevronsUpDown size={12} aria-hidden className="opacity-40" />
        ) : sort.dir === 'asc' ? (
          <ChevronUp size={12} aria-hidden />
        ) : (
          <ChevronDown size={12} aria-hidden />
        )}
      </button>
    </TH>
  )
}
