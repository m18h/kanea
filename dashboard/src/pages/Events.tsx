import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { PageHeader } from '@/components/PageHeader'
import {
  fetchAudit,
  fetchEvents,
  fetchProjects,
  type AuditEntry,
  type KaneaEvent,
} from '@/lib/api'
import { eventScope, eventSource, matchGlob } from '@/lib/events'
import { matchesQuery } from '@/lib/search'
import { useDateStyle } from '@/hooks/useDateStyle'
import { type DateStyle, formatDateTime } from '@/lib/datetime'
import { useSession } from '@/hooks/useSession'
import { usePagination } from '@/hooks/usePagination'
import { PaginationControls } from '@/components/Pagination'
import { FilterChips } from '@/components/FilterChips'

const filters = [
  { value: 'all', label: 'all' },
  { value: 'info', label: 'info' },
  { value: 'warning', label: 'warning' },
  { value: 'error', label: 'error' },
  { value: 'audit', label: 'audit' },
] as const
type Filter = (typeof filters)[number]['value']

const severityVariant: Record<KaneaEvent['severity'], 'info' | 'warn' | 'error'> = {
  info: 'info',
  warning: 'warn',
  error: 'error',
}

/**
 * The notification feed (PRD §11: "all channels also mirrored into the
 * dashboard notification feed").
 *
 * The same events that go to Telegram and Slack, in the order they happened.
 * It is the page an operator opens when something is wrong and they do not yet
 * know what, so it is deliberately not filtered down to errors by default: a
 * deploy two minutes before a crash is the most useful line on the page, and
 * hiding it behind a severity filter is how a feed becomes a log nobody reads.
 *
 * The audit chip is a different feed at the same table: §13.3's append-only
 * log of authenticated mutations, which has no severity because it is not a
 * judgment; it is a record.
 */
export function Events() {
  const style = useDateStyle()
  const [filter, setFilter] = useState<Filter>('all')
  const [glob, setGlob] = useState('')
  const [query, setQuery] = useState('')
  const { session } = useSession()

  const feed = useQuery({
    queryKey: ['events', ''],
    queryFn: ({ signal }) => fetchEvents({ limit: 200 }, signal),
    refetchInterval: 5_000,
  })

  const audit = useQuery({
    queryKey: ['audit'],
    queryFn: ({ signal }) => fetchAudit(200, signal),
    enabled: filter === 'audit',
    refetchInterval: filter === 'audit' ? 15_000 : false,
    retry: false,
  })

  // Channel names per project, for the "→ slack" routing hint. This is "the
  // project has channels", not "this event was delivered": delivery is not
  // recorded per event, and the title on the hint says so.
  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => fetchProjects(signal),
    staleTime: 60_000,
  })
  const channels = new Map(
    (projects.data ?? []).map((p) => [p.name, p.notifications ?? []] as const),
  )

  const events = (feed.data?.events ?? []).filter(
    (event) =>
      (filter === 'all' || event.severity === filter) &&
      (glob.trim() === '' || matchGlob(glob, eventScope(event))) &&
      // The glob addresses the scope; the search reads the words. "db timeout"
      // across every service and "payments/*" are different questions.
      matchesQuery(query, event.message, event.detail, eventScope(event), eventSource(event)),
  )
  const dropped = feed.data?.dropped ?? 0

  // A changed filter resets to the first page: page 3 of "all" and page 3 of
  // "error" are unrelated places.
  const pager = usePagination(events, { resetKey: `${glob} ${query} ${filter}` })
  const auditPager = usePagination(audit.data ?? [], { resetKey: filter })

  return (
    <section className="space-y-4">
      <PageHeader title="Events" subtitle="notification feed · refreshes every 5s" />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <FilterChips options={filters} value={filter} onChange={setFilter} />
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search messages…"
            aria-label="Search event messages"
            className="h-7 w-40 rounded-md border bg-background px-2 text-xs"
          />
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            glob:
            <input
              type="search"
              value={glob}
              onChange={(e) => setGlob(e.target.value)}
              placeholder="svc/*"
              aria-label="Filter by project/service glob"
              className="h-7 w-28 rounded-md border bg-background px-2 font-mono text-xs"
            />
          </label>
        </div>
      </div>

      {dropped > 0 && filter !== 'audit' ? (
        // Said out loud. A feed with gaps that does not admit to them is worse
        // than no feed: an operator reading "no crash events" would reach the
        // wrong conclusion about a quiet hour.
        <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          {dropped} event{dropped === 1 ? '' : 's'} could not be queued since this daemon
          started, so this feed has gaps.
        </p>
      ) : null}

      {filter === 'audit' ? (
        <AuditTable
          entries={auditPager.pageItems}
          error={audit.isError}
          admin={session?.role === 'admin'}
          pager={<PaginationControls state={auditPager} />}
        />
      ) : (
        <>
          {feed.isError ? (
            <p className="text-sm text-destructive">Cannot read the event feed.</p>
          ) : null}
          {feed.isSuccess && events.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {filter === 'all' && !glob.trim() && !query.trim()
                ? 'Nothing has happened yet.'
                : 'No events match that filter.'}
            </p>
          ) : (
            <Card className="py-2">
              <Table>
                <THead>
                  <tr>
                    <TH className="pt-2">Time</TH>
                    <TH className="pt-2">Severity</TH>
                    <TH className="pt-2">Source</TH>
                    <TH className="pt-2">Message</TH>
                    <TH className="pt-2 text-right">Routed</TH>
                  </tr>
                </THead>
                <TBody>
                  {pager.pageItems.map((event) => (
                    <EventTableRow
                      key={event.id}
                      event={event}
                      channels={event.project ? (channels.get(event.project) ?? []) : []}
                      style={style}
                    />
                  ))}
                </TBody>
              </Table>
              <div className="px-3">
                <PaginationControls state={pager} />
              </div>
            </Card>
          )}
        </>
      )}
    </section>
  )
}

function EventTableRow({
  event,
  channels,
  style,
}: {
  event: KaneaEvent
  channels: string[]
  style: DateStyle
}) {
  const scope = eventScope(event)
  return (
    <TR>
      <TD className="whitespace-nowrap font-mono text-xs text-muted-foreground">
        <time dateTime={event.at} title={event.at}>
          {formatDateTime(event.at, style)}
        </time>
      </TD>
      <TD>
        <Badge variant={severityVariant[event.severity]} className="font-mono text-[11px]">
          {event.severity === 'warning' ? 'warn' : event.severity}
        </Badge>
      </TD>
      <TD className="whitespace-nowrap font-mono text-xs text-muted-foreground">
        {scope || eventSource(event)}
      </TD>
      <TD>
        {/* Rendered as text, never as markup: an event message carries a
            service name and an error string, both of which are ultimately
            workload-controlled (§14 A03). */}
        <span className="text-sm">{event.message}</span>
        {event.detail ? (
          <span className="mt-0.5 block break-words text-xs text-muted-foreground">
            {event.detail}
          </span>
        ) : null}
      </TD>
      <TD className="text-right">
        {channels.length > 0 ? (
          <span
            className="whitespace-nowrap font-mono text-xs text-primary/70"
            title="This project has notification channels configured; per-event delivery is not recorded."
          >
            → {channels.join(' · ')}
          </span>
        ) : null}
      </TD>
    </TR>
  )
}

function AuditTable({
  entries,
  error,
  admin,
  pager,
}: {
  entries: AuditEntry[]
  error: boolean
  admin: boolean
  pager: React.ReactNode
}) {
  const style = useDateStyle()
  if (error) {
    return (
      <p className="text-sm text-muted-foreground">
        {admin
          ? 'Cannot read the audit log.'
          : 'The audit log is admin-only; this account is a viewer.'}
      </p>
    )
  }
  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No audited actions yet.</p>
  }
  return (
    <Card className="py-2">
      <Table>
        <THead>
          <tr>
            <TH className="pt-2">Time</TH>
            <TH className="pt-2">Actor</TH>
            <TH className="pt-2">Action</TH>
            <TH className="pt-2">Target</TH>
            <TH className="pt-2">Result</TH>
          </tr>
        </THead>
        <TBody>
          {entries.map((entry) => (
            <TR key={entry.id}>
              <TD className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                <time dateTime={entry.time} title={entry.time}>
                  {formatDateTime(entry.time, style)}
                </time>
              </TD>
              <TD className="font-mono text-xs">
                {entry.actor ?? '-'}
                {entry.via ? <span className="text-muted-foreground"> · {entry.via}</span> : null}
              </TD>
              <TD className="font-mono text-xs">{entry.action}</TD>
              <TD className="break-all font-mono text-xs text-muted-foreground">
                {entry.target ?? '-'}
              </TD>
              <TD>
                <Badge
                  variant={
                    entry.result === 'ok' ? 'ok' : entry.result === 'attempt' ? 'muted' : 'error'
                  }
                  className="font-mono text-[11px]"
                >
                  {entry.result}
                </Badge>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
      <div className="px-3">{pager}</div>
    </Card>
  )
}
