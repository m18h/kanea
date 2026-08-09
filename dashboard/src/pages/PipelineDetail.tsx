import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { BackChip } from '@/components/BackChip'
import { LogViewer } from '@/components/LogViewer'
import { PageHeader } from '@/components/PageHeader'
import { StatTile } from '@/components/StatTile'
import { StatusDot, type StatusTone } from '@/components/StatusDot'
import { fetchRun, fetchRunLog, isRunFinished, type RunStep } from '@/lib/api'
import {
  runStateLabel,
  runStateVariant,
  runDuration,
  stepDuration,
  shortID,
  shortSHA,
} from '@/lib/pipelines'

/** How often a running build is re-read. */
const LivePollMs = 2_000

export function PipelineDetail({
  project,
  service,
  id,
}: {
  project: string
  service: string
  id: string
}) {
  const run = useQuery({
    queryKey: ['run', project, service, id],
    queryFn: ({ signal }) => fetchRun(project, service, id, signal),
    refetchInterval: (query) => {
      const data = query.state.data
      return data && isRunFinished(data) ? false : LivePollMs
    },
  })

  const log = useQuery({
    queryKey: ['run-log', project, service, id],
    queryFn: ({ signal }) => fetchRunLog(project, service, id, signal),
    // Tied to the run, not to a timer of its own: once the run is finished the
    // log will not grow, and polling a file nobody is writing is pure waste.
    refetchInterval: run.data && isRunFinished(run.data) ? false : LivePollMs,
  })

  if (run.isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Not found</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          No run <span className="font-mono">{shortID(id)}</span> for{' '}
          <span className="font-mono">
            {project}/{service}
          </span>
          .
        </CardContent>
      </Card>
    )
  }

  const data = run.data
  const live = !data || !isRunFinished(data)
  const logText = log.data ?? ''
  const logLines = logText ? logText.replace(/\n$/, '').split('\n') : []

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <BackChip to="/pipelines">Pipelines</BackChip>
        <PageHeader
          title={
            <span className="font-mono">
              {project}/{service}
            </span>
          }
          subtitle={
            data ? (
              <Badge variant={runStateVariant(data.state)} className="font-mono text-[11px]">
                {runStateLabel(data.state)}
              </Badge>
            ) : undefined
          }
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Commit"
          value={
            <span className="text-base">
              {data?.ref ? `${data.ref} @ ` : ''}
              {shortSHA(data?.commit)}
            </span>
          }
          sub={data?.triggered_by}
        />
        <StatTile
          label="Trigger"
          value={<span className="text-base">{data?.trigger ?? '—'}</span>}
          sub={
            data?.trigger === 'webhook' ? (
              <span className="text-status-ok">HMAC signature verified</span>
            ) : undefined
          }
        />
        <StatTile
          label="Duration"
          value={<span className="text-base">{data ? runDuration(data) : '—'}</span>}
          sub="rootless BuildKit · slot 1"
        />
        <StatTile
          label="Artifact"
          value={<span className="break-all text-base">{data?.image ?? '—'}</span>}
          sub={
            data?.digest ? (
              // The digest, not a signature: what ran is what was built
              // (§14 A08), and the digest is the provenance that exists.
              <span className="break-all font-mono">{shortDigest(data.digest)}</span>
            ) : undefined
          }
        />
      </div>

      {data?.error ? (
        <Card className="border-status-error/40 p-3 text-sm text-status-error">{data.error}</Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="self-start">
          <CardHeader>
            <CardTitle>Steps</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5 text-sm">
            {(data?.steps ?? []).length === 0 ? (
              <p className="text-muted-foreground">No steps recorded yet.</p>
            ) : (
              (data?.steps ?? []).map((step) => <StepRow key={step.name} step={step} />)
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between gap-3 space-y-0">
            <div className="flex items-baseline gap-2">
              <CardTitle>Build log</CardTitle>
              <span className="font-mono text-xs text-muted-foreground">
                {logLines.length} line{logLines.length === 1 ? '' : 's'} · stdout+stderr
              </span>
            </div>
            {logText ? <DownloadRaw text={logText} /> : null}
          </CardHeader>
          <CardContent>
            <LogViewer
              lines={logLines.map((text, i) => ({ key: String(i), text }))}
              live={live}
              showLineNumbers
              maxHeightClass="max-h-[28rem]"
              emptyText={live ? 'Waiting for the build to start…' : 'No log for this run.'}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function StepRow({ step }: { step: RunStep }) {
  const running = step.state === 'running'
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="flex items-center gap-2">
        <StatusDot tone={stepTone(step.state)} />
        <span className={running ? 'font-medium text-primary' : ''}>{step.name}</span>
      </span>
      <span className="font-mono text-xs tabular-nums text-muted-foreground">
        {step.state === 'pending' ? '—' : stepDuration(step)}
      </span>
    </div>
  )
}

function stepTone(state: string): StatusTone {
  switch (state) {
    case 'succeeded':
      return 'ok'
    case 'running':
      return 'warn'
    case 'failed':
      return 'error'
    default:
      return 'muted'
  }
}

/** DownloadRaw hands the fetched log over as a file, no extra endpoint. */
function DownloadRaw({ text }: { text: string }) {
  return (
    <a
      download="build.log"
      href={`data:text/plain;charset=utf-8,${encodeURIComponent(text)}`}
      className="text-xs font-medium text-primary hover:underline"
    >
      Download raw
    </a>
  )
}

/** shortDigest keeps the algorithm and both ends of the hash. */
function shortDigest(digest: string): string {
  const at = digest.indexOf(':')
  if (at === -1 || digest.length < at + 17) return digest
  const hash = digest.slice(at + 1)
  return `${digest.slice(0, at)}:${hash.slice(0, 8)}…${hash.slice(-4)}`
}
