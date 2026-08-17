import { cn } from '@/lib/utils'

export type StatusTone = 'ok' | 'warn' | 'error' | 'info' | 'muted'

const dotClass: Record<StatusTone, string> = {
  ok: 'bg-status-ok',
  warn: 'bg-status-warn',
  error: 'bg-status-error',
  info: 'bg-status-info',
  muted: 'bg-muted-foreground',
}

const wordClass: Record<StatusTone, string> = {
  ok: 'text-status-ok',
  warn: 'text-status-warn',
  error: 'text-status-error',
  info: 'text-status-info',
  muted: 'text-muted-foreground',
}

export interface StatusDotProps {
  tone: StatusTone
  /** label rides beside the dot in the same tone. The dot never stands alone
   * where the state matters: colour is a highlight, the word is the fact. */
  label?: string | undefined
  className?: string | undefined
}

export function StatusDot({ tone, label, className }: StatusDotProps) {
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <span aria-hidden className={cn('size-2 shrink-0 rounded-full', dotClass[tone])} />
      {label !== undefined ? <span className={cn('text-sm', wordClass[tone])}>{label}</span> : null}
    </span>
  )
}
