import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Info, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { fetchEvents, type KaneaEvent } from '@/lib/api'
import { formatTime } from '@/lib/backups'
import { cn } from '@/lib/utils'

/**
 * The notification feed (PRD §11: "all channels also mirrored into the
 * dashboard notification feed").
 *
 * The same events that go to Telegram and Slack, in the order they happened.
 * It is the page an operator opens when something is wrong and they do not yet
 * know what — so it is deliberately not filtered down to errors by default: a
 * deploy two minutes before a crash is the most useful line on the page, and
 * hiding it behind a severity filter is how a feed becomes a log nobody reads.
 */
export function Events() {
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [project, setProject] = useState('')

  const feed = useQuery({
    queryKey: ['events', project],
    // The project key is omitted rather than set to undefined:
    // exactOptionalPropertyTypes draws that distinction, and it is the right
    // one — "no filter" and "filter by nothing" are different requests.
    queryFn: ({ signal }) =>
      fetchEvents(project ? { project, limit: 200 } : { limit: 200 }, signal),
    refetchInterval: 5_000,
  })

  const events = (feed.data?.events ?? []).filter(
    (event) => severity === 'all' || event.severity === severity,
  )
  const dropped = feed.data?.dropped ?? 0

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold tracking-tight">Events</h1>
        <div className="flex items-center gap-2">
          <input
            type="search"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            placeholder="Filter by project"
            aria-label="Filter by project"
            className="h-8 rounded-md border bg-background px-2 text-sm"
          />
          <div className="flex overflow-hidden rounded-md border">
            {(['all', 'error', 'warning', 'info'] as const).map((level) => (
              <button
                key={level}
                type="button"
                onClick={() => setSeverity(level)}
                className={cn(
                  'px-2.5 py-1 text-xs capitalize hover:bg-muted',
                  severity === level ? 'bg-muted font-medium' : 'text-muted-foreground',
                )}
              >
                {level}
              </button>
            ))}
          </div>
        </div>
      </div>

      {dropped > 0 ? (
        // Said out loud. A feed with gaps that does not admit to them is worse
        // than no feed: an operator reading "no crash events" would reach the
        // wrong conclusion about a quiet hour.
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
          {dropped} event{dropped === 1 ? '' : 's'} could not be queued since this daemon
          started, so this feed has gaps.
        </p>
      ) : null}

      {feed.isError ? (
        <p className="text-sm text-destructive">Cannot read the event feed.</p>
      ) : null}

      {feed.isSuccess && events.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {severity === 'all' && !project
            ? 'Nothing has happened yet.'
            : 'No events match that filter.'}
        </p>
      ) : null}

      <ol className="space-y-1">
        {events.map((event) => (
          <EventRow key={event.id} event={event} />
        ))}
      </ol>
    </section>
  )
}

type Severity = 'info' | 'warning' | 'error'

function EventRow({ event }: { event: KaneaEvent }) {
  const scope = [event.project, event.service].filter(Boolean).join('/')
  return (
    <li className="flex items-start gap-3 rounded-md border px-3 py-2">
      <SeverityIcon severity={event.severity} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-2">
          <code className="text-xs text-muted-foreground">{event.name}</code>
          {scope ? <Badge variant="muted">{scope}</Badge> : null}
          <time
            className="ml-auto font-mono text-xs text-muted-foreground"
            dateTime={event.at}
            title={event.at}
          >
            {formatTime(event.at)}
          </time>
        </div>
        {/* Rendered as text, never as markup: an event message carries a
            service name and an error string, both of which are ultimately
            workload-controlled (§14 A03). */}
        <p className="text-sm">{event.message}</p>
        {event.detail ? (
          <p className="mt-0.5 break-words text-xs text-muted-foreground">{event.detail}</p>
        ) : null}
      </div>
    </li>
  )
}

function SeverityIcon({ severity }: { severity: Severity }) {
  const shared = 'mt-0.5 shrink-0'
  if (severity === 'error') {
    return <XCircle size={16} className={cn(shared, 'text-destructive')} aria-label="error" />
  }
  if (severity === 'warning') {
    return (
      <AlertTriangle size={16} className={cn(shared, 'text-amber-500')} aria-label="warning" />
    )
  }
  return <Info size={16} className={cn(shared, 'text-muted-foreground')} aria-label="info" />
}
