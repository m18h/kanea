import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input, Label } from '@/components/ui/input'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { fetchAuditPage, type AuditEntry } from '@/lib/api'
import { formatTime } from '@/lib/backups'

const pageSize = 25

/**
 * AuditSection pages through the audit log, newest first, with the daemon's
 * own filters — actor, action and the `after` cursor are all server-side
 * (internal/api handleAudit), so the browser never downloads the log to
 * search it.
 */
export function AuditSection() {
  // The filter inputs are applied on submit, not per keystroke: each change
  // is a fresh server query, and the cursor stack resets with it.
  const [actorInput, setActorInput] = useState('')
  const [actionInput, setActionInput] = useState('')
  const [applied, setApplied] = useState({ actor: '', action: '' })
  // cursors[i] is the `after` value page i was fetched with; page 0 has none.
  const [cursors, setCursors] = useState<string[]>([])

  const after = cursors[cursors.length - 1]
  const page = useQuery({
    queryKey: ['audit', applied.actor, applied.action, after ?? ''],
    queryFn: ({ signal }) =>
      fetchAuditPage(
        {
          limit: pageSize,
          ...(applied.actor ? { actor: applied.actor } : {}),
          ...(applied.action ? { action: applied.action } : {}),
          ...(after ? { after } : {}),
        },
        signal,
      ),
    placeholderData: (prev) => prev,
  })

  const entries = page.data?.entries ?? []

  const apply = () => {
    setApplied({ actor: actorInput.trim(), action: actionInput.trim() })
    setCursors([])
  }

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold tracking-tight">Audit log</h2>

      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="audit-actor">Actor</Label>
          <Input
            id="audit-actor"
            className="w-44 font-mono"
            placeholder="ada"
            value={actorInput}
            onChange={(e) => setActorInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') apply()
            }}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="audit-action">Action</Label>
          <Input
            id="audit-action"
            className="w-44 font-mono"
            placeholder="service.apply"
            value={actionInput}
            onChange={(e) => setActionInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') apply()
            }}
          />
        </div>
        <Button variant="outline" onClick={apply}>
          Filter
        </Button>
      </div>

      {page.isError ? (
        <p className="text-sm text-destructive">Cannot read the audit log.</p>
      ) : null}

      <Card className="py-2">
        <Table>
          <THead>
            <tr>
              <TH className="pt-2">Time</TH>
              <TH className="pt-2">Actor</TH>
              <TH className="pt-2">Via</TH>
              <TH className="pt-2">Action</TH>
              <TH className="pt-2">Target</TH>
              <TH className="pt-2">Result</TH>
              <TH className="pt-2">Status</TH>
              <TH className="pt-2">Source</TH>
            </tr>
          </THead>
          <TBody>
            {entries.map((entry) => (
              <AuditRow key={entry.id} entry={entry} />
            ))}
          </TBody>
        </Table>
        {page.isSuccess && entries.length === 0 ? (
          <p className="px-4 pb-2 text-sm text-muted-foreground">Nothing matches.</p>
        ) : null}
        <div className="flex items-center justify-between gap-3 px-3 pb-1 pt-2">
          <span className="text-xs tabular-nums text-muted-foreground">
            page {cursors.length + 1}
          </span>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={cursors.length === 0}
              onClick={() => setCursors([])}
            >
              Newest
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!page.data?.more || !page.data.next_after}
              onClick={() => {
                const next = page.data?.next_after
                if (next) setCursors((c) => [...c, next])
              }}
            >
              Older
            </Button>
          </div>
        </div>
      </Card>
    </section>
  )
}

/** resultVariant maps the four audit results onto how alarming they look. */
function resultVariant(result: string): 'ok' | 'warn' | 'error' | 'muted' {
  switch (result) {
    case 'ok':
      return 'ok'
    case 'denied':
      return 'error'
    case 'error':
      return 'error'
    case 'attempt':
      return 'warn'
    default:
      return 'muted'
  }
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  return (
    <TR>
      <TD className="whitespace-nowrap font-mono text-xs text-muted-foreground">
        {formatTime(entry.time)}
      </TD>
      <TD className="font-mono text-xs">{entry.actor ?? '—'}</TD>
      <TD className="font-mono text-xs text-muted-foreground">{entry.via ?? '—'}</TD>
      <TD className="font-mono text-xs">{entry.action}</TD>
      <TD className="max-w-56 truncate font-mono text-xs text-muted-foreground" title={entry.target}>
        {entry.target ?? '—'}
      </TD>
      <TD>
        <Badge variant={resultVariant(entry.result)} className="font-mono text-[11px]">
          {entry.result}
        </Badge>
      </TD>
      <TD className="font-mono text-xs tabular-nums text-muted-foreground">
        {entry.status ?? '—'}
      </TD>
      <TD className="font-mono text-xs text-muted-foreground">{entry.source ?? '—'}</TD>
    </TR>
  )
}
