import type { KaneaEvent } from '@/lib/api'
import { eventScope, eventSource } from '@/lib/events'
import { useDateStyle } from '@/hooks/useDateStyle'
import { formatDateTime } from '@/lib/datetime'
import { StatusDot, type StatusTone } from '@/components/StatusDot'

const severityTone: Record<KaneaEvent['severity'], StatusTone> = {
  info: 'info',
  warning: 'warn',
  error: 'error',
}

/**
 * EventRow is the compact event line the Dashboard cards use: severity dot,
 * message, muted `source · time` beneath. The Events page renders its own
 * table rows: this is the card-sized form.
 */
export function EventRow({ event }: { event: KaneaEvent }) {
  const scope = eventScope(event)
  const style = useDateStyle()
  return (
    <div className="flex gap-2.5 border-b border-border/50 py-2 last:border-0">
      <StatusDot tone={severityTone[event.severity]} className="mt-1.5" />
      <div className="min-w-0">
        {/* Message text is daemon-composed but quotes user-named things;
            rendered as text, never markup. */}
        <div className="truncate text-sm">{event.message}</div>
        <div className="font-mono text-xs text-muted-foreground">
          {scope || eventSource(event)} · {formatDateTime(event.at, style)}
        </div>
      </div>
    </div>
  )
}
