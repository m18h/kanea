import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { Topic, allocsResponseSchema, servicesResponseSchema } from '@/lib/api'
import { groupAllocs, serviceHealth } from '@/lib/state'

/**
 * Overview is the "should I worry" page.
 *
 * PRD §12.2 also wants node CPU/memory/disk/network charts here. Those metrics
 * do not exist yet — the metrics pipeline is M6 — so the page shows what is
 * genuinely known rather than empty axes that imply the data is missing rather
 * than not yet collected.
 */
export function Overview() {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  const list = services.data?.services ?? []
  const byService = groupAllocs(allocs.data?.allocs ?? [])

  const summary = list.map((svc) => {
    const key = `${svc.Project}/${svc.Service}`
    return { key, service: svc, health: serviceHealth(svc, byService.get(key) ?? []) }
  })

  const unsettled = summary.filter((s) => !s.health.settled)
  const projects = new Set(list.map((s) => s.Project))

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Projects" value={projects.size} />
        <Stat label="Services" value={list.length} />
        <Stat
          label="Needing attention"
          value={unsettled.length}
          variant={unsettled.length === 0 ? 'ok' : 'warn'}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Service health</CardTitle>
        </CardHeader>
        <CardContent>
          {!services.connected ? (
            <p className="text-sm text-muted-foreground">Connecting…</p>
          ) : summary.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing deployed yet.</p>
          ) : (
            <ul className="space-y-1">
              {summary.map(({ key, service, health }) => (
                <li key={key} className="flex items-center justify-between gap-3 py-1">
                  <Link
                    to={`/services/${service.Project}/${service.Service}`}
                    className="font-mono text-xs hover:underline"
                  >
                    {key}
                  </Link>
                  <Badge variant={health.settled ? 'ok' : 'warn'}>{health.label}</Badge>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Node metrics</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            CPU, memory, disk and network charts arrive with the metrics pipeline (M6).
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

function Stat({
  label,
  value,
  variant,
}: {
  label: string
  value: number
  variant?: 'ok' | 'warn'
}) {
  return (
    <Card>
      <CardContent className="pt-4">
        <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-2xl font-semibold tabular-nums">{value}</span>
          {variant ? <Badge variant={variant}>{variant === 'ok' ? 'all settled' : 'check'}</Badge> : null}
        </div>
      </CardContent>
    </Card>
  )
}
