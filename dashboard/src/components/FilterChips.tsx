import { cn } from '@/lib/utils'

/**
 * FilterChips is the row of status buttons every list page filters by: the
 * Events page's severity chips, generalised so four pages don't grow four
 * slightly different chip rows.
 */
export function FilterChips<F extends string>({
  options,
  value,
  onChange,
}: {
  options: readonly { value: F; label: string }[]
  value: F
  onChange: (value: F) => void
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          onClick={() => onChange(option.value)}
          className={cn(
            'rounded-md border px-3 py-1 text-xs transition-colors',
            value === option.value
              ? 'border-status-warn/60 font-medium text-primary'
              : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
