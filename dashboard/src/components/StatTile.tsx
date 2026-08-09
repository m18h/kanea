import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

export interface StatTileProps {
  label: string
  value: React.ReactNode
  sub?: React.ReactNode | undefined
  /** tone colours the big number: 'primary' for "a slot is in use", 'ok' for
   * "replication is healthy". Never the only signal — the sub line says why. */
  tone?: 'default' | 'primary' | 'ok' | 'error' | undefined
  className?: string | undefined
}

const valueTone = {
  default: 'text-foreground',
  primary: 'text-primary',
  ok: 'text-status-ok',
  error: 'text-status-error',
} as const

/** StatTile is the top-of-page number card: label, big mono value, sub-stat. */
export function StatTile({ label, value, sub, tone, className }: StatTileProps) {
  return (
    <Card className={cn('p-4', className)}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 flex items-baseline gap-2">
        <span
          className={cn(
            'font-mono text-3xl font-semibold tabular-nums',
            valueTone[tone ?? 'default'],
          )}
        >
          {value}
        </span>
        {sub !== undefined ? <span className="text-xs text-muted-foreground">{sub}</span> : null}
      </div>
    </Card>
  )
}
