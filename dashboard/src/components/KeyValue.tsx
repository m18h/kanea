import { cn } from '@/lib/utils'

export interface KeyValueProps {
  label: string
  children: React.ReactNode
  /** mono for identifiers and figures; prose values stay in the UI face. */
  mono?: boolean | undefined
  className?: string | undefined
}

/** KeyValue is a label-left value-right row inside a card, mockup style. */
export function KeyValue({ label, children, mono, className }: KeyValueProps) {
  return (
    <div
      className={cn(
        'flex items-baseline justify-between gap-3 border-b border-border/50 py-1.5 last:border-0',
        className,
      )}
    >
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={cn('text-right text-sm', mono && 'font-mono tabular-nums')}>{children}</span>
    </div>
  )
}
