import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { fetchRun, fetchRunLog, isRunFinished } from '@/lib/api'
import { runStateVariant, runDuration, stepDuration, shortID, shortSHA } from '@/lib/pipelines'

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
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="font-mono">
            {project}/{service} · {shortID(id)}
          </CardTitle>
          {data ? <Badge variant={runStateVariant(data.state)}>{data.state}</Badge> : null}
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <Field label="Trigger" value={triggerText(data?.trigger, data?.triggered_by)} />
          <Field label="Commit" value={shortSHA(data?.commit)} mono />
          <Field label="Branch" value={data?.ref ?? '—'} mono />
          <Field label="Duration" value={data ? runDuration(data) : '—'} />
          {/* The digest, not the tag: what ran is what was built (§14 A08). */}
          <Field label="Image" value={data?.image ?? '—'} mono />
          {data?.error ? <Field label="Error" value={data.error} /> : null}
        </CardContent>
      </Card>

      {data?.steps?.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Steps</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {data.steps.map((step) => (
              <div key={step.name} className="flex items-center justify-between gap-3">
                <span className="font-mono">{step.name}</span>
                <span className="flex items-center gap-3">
                  <span className="text-muted-foreground">{stepDuration(step)}</span>
                  <Badge variant={runStateVariant(step.state)}>{step.state}</Badge>
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Build log</CardTitle>
        </CardHeader>
        <CardContent>
          <BuildLog text={log.data ?? ''} live={!data || !isRunFinished(data)} />
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * BuildLog renders the log, following the tail while the build is going.
 *
 * It scrolls only when the operator was already at the bottom. Yanking the view
 * down while someone is reading the line that broke the build is the one thing
 * a live log must not do.
 */
function BuildLog({ text, live }: { text: string; live: boolean }) {
  const ref = useRef<HTMLPreElement>(null)
  const pinned = useRef(true)

  useEffect(() => {
    const el = ref.current
    if (!el || !live || !pinned.current) return
    el.scrollTop = el.scrollHeight
  }, [text, live])

  if (!text) {
    return (
      <p className="text-sm text-muted-foreground">
        {live ? 'Waiting for the build to start…' : 'No log for this run.'}
      </p>
    )
  }

  return (
    <pre
      ref={ref}
      onScroll={(event) => {
        const el = event.currentTarget
        // A small slack, because a scroll position is rarely exactly at the end.
        pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
      }}
      className="max-h-[28rem] overflow-auto rounded bg-muted p-3 font-mono text-xs leading-relaxed"
    >
      {/* Rendered as a text child, never as HTML: a build log is full of
          strings from a Containerfile nobody on this side wrote (§14, A03). */}
      {text}
    </pre>
  )
}

function triggerText(trigger?: string, by?: string): string {
  if (!trigger) return '—'
  return by ? `${trigger} · ${by}` : trigger
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-muted-foreground">{label}</span>
      <span className={mono ? 'break-all font-mono' : 'break-words'}>{value}</span>
    </div>
  )
}
