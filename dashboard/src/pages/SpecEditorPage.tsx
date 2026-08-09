import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { BackChip } from '@/components/BackChip'
import { PageHeader } from '@/components/PageHeader'
import { useSession } from '@/hooks/useSession'
import { useRouter } from '@/hooks/useRouter'
import { fetchProjects, servicesResponseSchema, Topic } from '@/lib/api'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import {
  applySpec,
  fetchSpecSource,
  renderSpec,
  HCL_TEMPLATE,
  type RenderedService,
  type SpecDiagnostic,
} from '@/lib/spec'

/**
 * The spec editor (PRD §12.2, v1.38): Deploy service and Edit spec.
 *
 * Validation is server-side — the browser has no HCL parser, and should not:
 * the daemon renders with the node's own base domain, so what the preview
 * shows is what an apply would mean *here*. The client-side "validated" state
 * is a courtesy; apply re-renders the same bytes regardless, so plan and
 * apply cannot drift.
 */
export function SpecEditorPage({
  project,
  service,
}: {
  project?: string | undefined
  service?: string | undefined
}) {
  const { session, csrf } = useSession()
  const { navigate } = useRouter()
  const editing = project !== undefined && service !== undefined

  const [text, setText] = useState(editing ? '' : HCL_TEMPLATE)
  const [loaded, setLoaded] = useState(!editing)
  const [sourceNote, setSourceNote] = useState<string | null>(null)
  const [diagnostics, setDiagnostics] = useState<SpecDiagnostic[]>([])
  const [preview, setPreview] = useState<RenderedService[] | null>(null)
  const [validated, setValidated] = useState(false)
  const [busy, setBusy] = useState<'validate' | 'apply' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmedOverwrite, setConfirmedOverwrite] = useState(false)
  const textarea = useRef<HTMLTextAreaElement>(null)

  // Prefill from the generated source when editing.
  useEffect(() => {
    if (!editing) return
    let cancelled = false
    fetchSpecSource(project, service)
      .then((result) => {
        if (cancelled) return
        if ('hcl' in result) {
          setText(result.hcl)
        } else {
          setSourceNote(result.refusal)
          setText(HCL_TEMPLATE)
        }
        setLoaded(true)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : String(err))
        setLoaded(true)
      })
    return () => {
      cancelled = true
    }
  }, [editing, project, service])

  // The GitOps warning: a synced project's next sync wins over anything
  // applied here. Warn, never block — an admin may be intentionally
  // hot-fixing — and require the checkbox so it was read.
  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => fetchProjects(signal),
    staleTime: 60_000,
  })
  const gitSource = project
    ? (projects.data ?? []).find((p) => p.name === project)?.git
    : undefined

  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const existing = new Set(
    (services.data?.services ?? []).map((s) => `${s.Project}/${s.Service}`),
  )

  const edit = (next: string) => {
    setText(next)
    // Any edit invalidates the previous validation — cosmetic only, the
    // server re-renders on apply, but a stale green tick misleads.
    setValidated(false)
    setPreview(null)
  }

  const validate = () => {
    setBusy('validate')
    setError(null)
    renderSpec(text, project, csrf)
      .then((result) => {
        setDiagnostics(result.diagnostics)
        if (result.valid) {
          setValidated(true)
          setPreview(result.services ?? [])
        } else {
          setValidated(false)
          setPreview(null)
        }
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(null))
  }

  const apply = () => {
    setBusy('apply')
    setError(null)
    applySpec(text, project, csrf)
      .then((result) => {
        if ('diagnostics' in result) {
          setDiagnostics(result.diagnostics)
          setValidated(false)
          setPreview(null)
          return
        }
        const first = result.applied[0]
        if (first) {
          const [p, s] = first.split('/')
          navigate(`/services/${p}/${s}`)
        } else {
          navigate('/services')
        }
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(null))
  }

  const admin = session?.role === 'admin'
  const applyBlocked =
    !admin || !validated || busy !== null || (gitSource !== undefined && !confirmedOverwrite)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <BackChip to={editing ? `/services/${project}/${service}` : '/services'}>
          {editing ? service : 'Services'}
        </BackChip>
        <PageHeader
          title={editing ? `Edit spec` : 'Deploy service'}
          subtitle={
            editing ? (
              <span className="font-mono">
                {project}/{service}
              </span>
            ) : (
              'HCL · validated on the node'
            )
          }
        />
      </div>

      {editing && loaded && !sourceNote ? (
        <p className="rounded-md border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
          This text was generated from the running desired state. Comments and variable
          interpolations from the original file are not preserved; resolved values appear
          as literals.
        </p>
      ) : null}
      {sourceNote ? (
        <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          Could not generate this service's spec: {sourceNote}. Starting from the template
          instead — the running service is unchanged until you apply.
        </p>
      ) : null}

      {gitSource ? (
        <div className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          <p>
            This project syncs from <span className="font-mono">{gitSource.url}</span>
            {gitSource.branch ? (
              <>
                {' '}
                (<span className="font-mono">{gitSource.branch}</span>)
              </>
            ) : null}
            . Changes applied here will be overwritten on the next sync — edit the
            repository instead, or confirm you want a hot-fix that the repository will
            later replace.
          </p>
          <label className="mt-2 flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={confirmedOverwrite}
              onChange={(e) => setConfirmedOverwrite(e.target.checked)}
            />
            Apply anyway; the next sync wins.
          </label>
        </div>
      ) : null}

      <Card>
        <CardContent className="pt-4">
          <textarea
            ref={textarea}
            value={text}
            onChange={(e) => edit(e.target.value)}
            spellCheck={false}
            disabled={!loaded}
            aria-label="Job spec HCL"
            className="min-h-[24rem] w-full resize-y rounded-md border bg-muted/30 p-3 font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button variant="outline" disabled={busy !== null || !loaded} onClick={validate}>
              {busy === 'validate' ? 'Validating…' : 'Validate'}
            </Button>
            <Button
              disabled={applyBlocked}
              title={
                admin
                  ? validated
                    ? undefined
                    : 'Validate first'
                  : 'Requires the admin role'
              }
              onClick={apply}
            >
              {busy === 'apply' ? 'Applying…' : 'Apply'}
            </Button>
            {validated ? (
              <Badge variant="ok" className="font-mono text-[11px]">
                valid
              </Badge>
            ) : null}
            {error ? <span className="text-sm text-destructive">{error}</span> : null}
          </div>
        </CardContent>
      </Card>

      {diagnostics.length > 0 ? (
        <DiagnosticList
          diagnostics={diagnostics}
          onJump={(line) => jumpToLine(textarea.current, text, line)}
        />
      ) : null}

      {preview ? <ApplyPreview services={preview} existing={existing} /> : null}
    </div>
  )
}

/** DiagnosticList positions the daemon's findings for the editor. */
function DiagnosticList({
  diagnostics,
  onJump,
}: {
  diagnostics: SpecDiagnostic[]
  onJump: (line: number) => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Diagnostics</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {diagnostics.map((d, i) => (
          <div key={i} className="flex items-start gap-2.5 text-sm">
            <Badge
              variant={d.severity === 'error' ? 'error' : 'warn'}
              className="font-mono text-[11px]"
            >
              {d.severity}
            </Badge>
            <div className="min-w-0">
              {/* Daemon-composed text quoting operator input: text, never markup. */}
              <span>{d.summary}</span>
              {d.line !== undefined && d.line > 0 ? (
                <button
                  type="button"
                  className="ml-2 font-mono text-xs text-primary hover:underline"
                  onClick={() => onJump(d.line ?? 1)}
                >
                  line {d.line}
                  {d.column !== undefined && d.column > 0 ? `:${d.column}` : ''}
                </button>
              ) : null}
              {d.detail ? (
                <p className="mt-0.5 text-xs text-muted-foreground">{d.detail}</p>
              ) : null}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

/** ApplyPreview summarises what a valid spec would do. */
function ApplyPreview({
  services,
  existing,
}: {
  services: RenderedService[]
  existing: Set<string>
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>What applying does</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {services.map((svc) => {
          const key = `${svc.Project}/${svc.Service}`
          return (
            <div key={key} className="flex items-center gap-3 text-sm">
              <Badge
                variant={existing.has(key) ? 'accent' : 'ok'}
                className="font-mono text-[11px]"
              >
                {existing.has(key) ? 'update' : 'new'}
              </Badge>
              <span className="font-mono">{key}</span>
              <span className="text-muted-foreground">
                {svc.Count} replica{svc.Count === 1 ? '' : 's'} ·{' '}
                <span className="font-mono text-xs">{svc.Image || 'built from source'}</span>
              </span>
            </div>
          )
        })}
        <p className="pt-1 text-xs text-muted-foreground">
          Services not named in this spec are untouched.
        </p>
      </CardContent>
    </Card>
  )
}

/** jumpToLine moves the textarea caret to a diagnostic's line. */
function jumpToLine(el: HTMLTextAreaElement | null, text: string, line: number) {
  if (!el) return
  let offset = 0
  const lines = text.split('\n')
  for (let i = 0; i < Math.min(line - 1, lines.length); i++) {
    offset += (lines[i]?.length ?? 0) + 1
  }
  el.focus()
  el.setSelectionRange(offset, offset)
}
