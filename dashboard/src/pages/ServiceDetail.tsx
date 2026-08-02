import { useEffect, useRef, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLiveLog, MaxLogLines } from '@/hooks/useLiveLog'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { Topic, allocsResponseSchema, servicesResponseSchema } from '@/lib/api'
import { allocStateVariant, groupAllocs, serviceHealth } from '@/lib/state'

export function ServiceDetail({ project, service }: { project: string; service: string }) {

  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  const key = `${project}/${service}`
  const desired = (services.data?.services ?? []).find(
    (s) => s.Project === project && s.Service === service,
  )
  const mine = groupAllocs(allocs.data?.allocs ?? []).get(key) ?? []

  if (services.connected && !desired) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Not found</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          No service <span className="font-mono">{key}</span> is deployed.
        </CardContent>
      </Card>
    )
  }

  const health = desired ? serviceHealth(desired, mine) : null

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="font-mono">{key}</CardTitle>
          {health ? <Badge variant={health.settled ? 'ok' : 'warn'}>{health.label}</Badge> : null}
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <Field label="Image" value={desired?.Image ?? '—'} mono />
          <Field label="Desired" value={String(desired?.Count ?? 0)} />
          {desired?.Expose ? (
            <Field
              label="Domains"
              value={(desired.Expose.Domains ?? []).join(', ') || 'auto-generated'}
              mono
            />
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Allocations</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {mine.length === 0 ? (
            <p className="text-sm text-muted-foreground">No allocations.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="pb-2 pr-4 font-medium">Alloc</th>
                  <th className="pb-2 pr-4 font-medium">State</th>
                  <th className="pb-2 font-medium">Restarts</th>
                </tr>
              </thead>
              <tbody>
                {mine.map((alloc) => (
                  <tr key={alloc.ID} className="border-t border-border/60">
                    <td className="py-2 pr-4 font-mono text-xs">{alloc.ID}</td>
                    <td className="py-2 pr-4">
                      <Badge variant={allocStateVariant(alloc.State)}>{alloc.State}</Badge>
                    </td>
                    <td className="py-2 tabular-nums">{alloc.Restarts ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <LogPanel project={project} service={service} />
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="w-24 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      {/* Values come from a job spec and are rendered as text, never markup. */}
      <span className={mono ? 'font-mono text-xs' : ''}>{value}</span>
    </div>
  )
}

/** LogPanel streams the service's output over the shared socket. */
function LogPanel({ project, service }: { project: string; service: string }) {
  const { lines, error, dropped } = useLiveLog(project, service)
  const [filter, setFilter] = useState('')
  const [follow, setFollow] = useState(true)
  const bottom = useRef<HTMLDivElement>(null)

  const shown = filter
    ? lines.filter((l) => l.line.toLowerCase().includes(filter.toLowerCase()))
    : lines

  useEffect(() => {
    if (follow) bottom.current?.scrollIntoView({ block: 'end' })
  }, [shown.length, follow])

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 gap-3">
        <CardTitle>Logs</CardTitle>
        <div className="flex items-center gap-2">
          <input
            type="search"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter"
            aria-label="Filter log lines"
            className="rounded-md border bg-background px-2 py-1 text-xs"
          />
          <label className="flex items-center gap-1 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={follow}
              onChange={(e) => setFollow(e.target.checked)}
            />
            Follow
          </label>
        </div>
      </CardHeader>
      <CardContent>
        {error ? <p className="pb-2 text-sm text-destructive">{error}</p> : null}
        {dropped > 0 ? (
          <p className="pb-2 text-xs text-muted-foreground">
            {dropped} earlier line{dropped === 1 ? '' : 's'} dropped (showing the most recent{' '}
            {MaxLogLines}).
          </p>
        ) : null}
        <div className="max-h-96 overflow-auto rounded-md bg-muted/40 p-2 font-mono text-xs">
          {shown.length === 0 ? (
            <p className="text-muted-foreground">
              {lines.length === 0 ? 'Waiting for output…' : 'No lines match the filter.'}
            </p>
          ) : (
            shown.map((entry, i) => (
              // Workload output is attacker-controlled whenever the workload is.
              // It is rendered as a text child — never markup (PRD §14, A03).
              <div key={`${entry.alloc_id}-${i}`} className="whitespace-pre-wrap break-all">
                <span className="mr-2 text-muted-foreground">{allocSuffix(entry.alloc_id)}</span>
                {entry.line}
              </div>
            ))
          )}
          <div ref={bottom} />
        </div>
      </CardContent>
    </Card>
  )
}

/** allocSuffix shortens an alloc id to its index, which is what distinguishes
 * one line from another within a service. */
function allocSuffix(id: string): string {
  const idx = id.lastIndexOf('-')
  return idx === -1 ? id : id.slice(idx + 1)
}
