import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { KeyValueSkeleton } from '@/components/Skeletons'
import { KeyValue } from '@/components/KeyValue'
import { fetchEdgePolicy, fetchSecretProviders, type NodeConfig } from '@/lib/api'
import { useDateStyle } from '@/hooks/useDateStyle'
import { timeOrNever } from '@/lib/settings'

/**
 * NodeSection shows what the unit flags decided: read facts, never forms.
 * Changing any of it is a unit edit and a restart, and the section says so
 * rather than growing inputs that could not take effect.
 */
export function NodeSection({ node }: { node: NodeConfig }) {
  const style = useDateStyle()
  const policy = useQuery({
    queryKey: ['edge-policy'],
    queryFn: ({ signal }) => fetchEdgePolicy(signal),
  })
  const providers = useQuery({
    queryKey: ['secret-providers'],
    queryFn: ({ signal }) => fetchSecretProviders(signal),
  })

  return (
    <section className="space-y-3">
      <div className="flex items-baseline gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Node</h2>
        <span className="text-xs text-muted-foreground">
          These are unit flags: edit the kanead unit and restart to change them.
        </span>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Daemon</CardTitle>
          </CardHeader>
          <CardContent>
            <KeyValue label="Listen" mono>
              {node.listen || '-'}
            </KeyValue>
            <KeyValue label="TLS">
              <Badge variant={node.tls ? 'ok' : 'muted'}>{node.tls ? 'on' : 'off'}</Badge>
            </KeyValue>
            <KeyValue label="Base domain" mono>
              {node.base_domain || '-'}
            </KeyValue>
            <KeyValue label="TLS default" mono>
              {node.tls_default || '-'}
            </KeyValue>
            <KeyValue label="DNS listen" mono>
              {node.dns_listen || '-'}
            </KeyValue>
            <KeyValue label="Data dir" mono>
              {node.data_dir}
            </KeyValue>
            <KeyValue label="Log dir" mono>
              {node.log_dir}
            </KeyValue>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Network</CardTitle>
          </CardHeader>
          <CardContent>
            <KeyValue label="Mode" mono>
              {node.network_mode}
            </KeyValue>
            <KeyValue label="Node CIDR" mono>
              {node.node_cidr}
            </KeyValue>
            <KeyValue label="Cluster CIDR" mono>
              {node.cluster_cidr}
            </KeyValue>
            <KeyValue label="Service CIDR" mono>
              {node.service_cidr}
            </KeyValue>
            {node.node_cidr6 ? (
              <KeyValue label="Node CIDR (v6)" mono>
                {node.node_cidr6}
              </KeyValue>
            ) : null}
            {node.cluster_cidr6 ? (
              <KeyValue label="Cluster CIDR (v6)" mono>
                {node.cluster_cidr6}
              </KeyValue>
            ) : null}
            {node.service_cidr6 ? (
              <KeyValue label="Service CIDR (v6)" mono>
                {node.service_cidr6}
              </KeyValue>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Published ports</CardTitle>
          </CardHeader>
          <CardContent>
            {policy.data ? (
              <>
                <KeyValue label="Publishing">
                  <Badge variant={policy.data.publish_enabled ? 'ok' : 'muted'}>
                    {policy.data.publish_enabled ? 'enabled' : 'off'}
                  </Badge>
                </KeyValue>
                <KeyValue label="Allowed" mono>
                  {policy.data.publish_ports || node.publish_ports || '-'}
                </KeyValue>
                <KeyValue label="Reserved" mono>
                  {(policy.data.reserved ?? []).join(', ') || '-'}
                </KeyValue>
              </>
            ) : policy.isError ? (
              <p className="text-sm text-muted-foreground">Cannot read the port policy.</p>
            ) : (
              <KeyValueSkeleton rows={3} />
            )}
          </CardContent>
        </Card>

        {providers.data && providers.data.length > 0 ? (
          <Card>
            <CardHeader>
              <CardTitle>External secret providers</CardTitle>
            </CardHeader>
            <CardContent>
              {providers.data.map((p) => (
                <KeyValue key={`${p.kind}/${p.name}`} label={`${p.kind} · ${p.name}`}>
                  <span className="font-mono text-xs text-muted-foreground">
                    {p.mappings} mapping(s) · last sync {timeOrNever(p.last_success, style)}
                  </span>
                </KeyValue>
              ))}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </section>
  )
}
