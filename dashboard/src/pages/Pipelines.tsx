import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Link } from '@/lib/router'
import { fetchRuns, isRunFinished, type Run } from '@/lib/api'
import { runStateVariant, runDuration, shortID, shortSHA } from '@/lib/pipelines'

/**
 * The pipeline list (PRD §10.2).
 *
 * Polled rather than live: a build takes minutes and the list changes when one
 * starts or ends, so a few seconds of staleness is invisible. Adding a
 * websocket topic for it would put a subscription on the daemon for a page that
 * is mostly still.
 */
export function Pipelines() {
  const runs = useQuery({
    queryKey: ['runs'],
    queryFn: ({ signal }) => fetchRuns({ limit: 50 }, signal),
    // Faster while something is running: an operator watching a build wants to
    // see it move, and once everything is finished there is nothing to see.
    refetchInterval: (query) =>
      (query.state.data ?? []).some((run) => !isRunFinished(run)) ? 2_000 : 15_000,
  })

  if (runs.isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Pipelines</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Could not read pipeline runs.
        </CardContent>
      </Card>
    )
  }

  const list = runs.data ?? []
  if (list.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Pipelines</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          No builds yet. A service with a <span className="font-mono">build</span> block builds on
          a push to its watched branch, or on <span className="font-mono">kanea build</span>.
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Pipelines</CardTitle>
      </CardHeader>
      <CardContent className="px-0">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-muted-foreground">
            <tr>
              <th className="px-4 pb-2 font-medium">Run</th>
              <th className="px-4 pb-2 font-medium">Service</th>
              <th className="px-4 pb-2 font-medium">State</th>
              <th className="px-4 pb-2 font-medium">Trigger</th>
              <th className="px-4 pb-2 font-medium">Commit</th>
              <th className="px-4 pb-2 font-medium">Duration</th>
            </tr>
          </thead>
          <tbody>
            {list.map((run) => (
              <RunRow key={`${run.project}/${run.service}/${run.id}`} run={run} />
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  )
}

function RunRow({ run }: { run: Run }) {
  return (
    <tr className="border-t">
      <td className="px-4 py-2 font-mono">
        <Link
          to={`/pipelines/${encodeURIComponent(run.project)}/${encodeURIComponent(
            run.service,
          )}/${encodeURIComponent(run.id)}`}
          className="hover:underline"
        >
          {shortID(run.id)}
        </Link>
      </td>
      <td className="px-4 py-2 font-mono">
        {run.project}/{run.service}
      </td>
      <td className="px-4 py-2">
        <Badge variant={runStateVariant(run.state)}>{run.state}</Badge>
      </td>
      <td className="px-4 py-2 text-muted-foreground">
        {run.trigger}
        {run.triggered_by ? ` · ${run.triggered_by}` : ''}
      </td>
      <td className="px-4 py-2 font-mono text-muted-foreground">{shortSHA(run.commit)}</td>
      <td className="px-4 py-2 text-muted-foreground">{runDuration(run)}</td>
    </tr>
  )
}
