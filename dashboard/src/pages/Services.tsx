import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import {
  Topic,
  allocsResponseSchema,
  servicesResponseSchema,
  type Alloc,
  type Service,
} from '@/lib/api'
import { allocStateVariant, groupAllocs } from '@/lib/state'

/** Services lists what is declared and how much of it is actually running. */
export function Services() {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  if (services.error) {
    return <Panel title="Services">{services.error}</Panel>
  }
  if (!services.connected) {
    return <Panel title="Services">Connecting…</Panel>
  }

  const list = services.data?.services ?? []
  if (list.length === 0) {
    return <Panel title="Services">Nothing deployed yet.</Panel>
  }

  const byService = groupAllocs(allocs.data?.allocs ?? [])

  return (
    <Card>
      <CardHeader>
        <CardTitle>Services</CardTitle>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-muted-foreground">
            <tr>
              <th className="pb-2 pr-4 font-medium">Service</th>
              <th className="pb-2 pr-4 font-medium">Image</th>
              <th className="pb-2 pr-4 font-medium">Running</th>
              <th className="pb-2 font-medium">Allocs</th>
            </tr>
          </thead>
          <tbody>
            {list.map((svc) => (
              <ServiceRow
                key={`${svc.Project}/${svc.Service}`}
                service={svc}
                allocs={byService.get(`${svc.Project}/${svc.Service}`) ?? []}
              />
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}

function ServiceRow({ service, allocs }: { service: Service; allocs: Alloc[] }) {
  const running = allocs.filter((a) => a.State === 'running').length

  return (
    <tr className="border-t border-border/60">
      <td className="py-2 pr-4">
        <Link
          to={`/services/${service.Project}/${service.Service}`}
          className="font-mono text-xs hover:underline"
        >
          {service.Project}/{service.Service}
        </Link>
      </td>
      {/* Every value here comes from a job spec and is rendered as text. */}
      <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">{service.Image}</td>
      <td className="py-2 pr-4">
        <Badge variant={running >= service.Count ? 'ok' : 'warn'}>
          {running}/{service.Count}
        </Badge>
      </td>
      <td className="flex flex-wrap gap-1 py-2">
        {allocs.map((alloc) => (
          <Badge key={alloc.ID} variant={allocStateVariant(alloc.State)}>
            {alloc.Index}: {alloc.State}
          </Badge>
        ))}
      </td>
    </tr>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">{children}</CardContent>
    </Card>
  )
}
