import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { DiagnosticList, jumpToLine } from '@/components/SpecDiagnostics'
import { GitSyncWarning } from '@/components/GitSyncWarning'
import { useSession } from '@/hooks/useSession'
import { Link } from '@/lib/router'
import { fetchProjects } from '@/lib/api'
import {
  applySpec,
  fetchServiceRecord,
  fetchSpecSource,
  renderSpec,
  type SpecDiagnostic,
} from '@/lib/spec'
import { checkScope } from '@/lib/specScope'

/**
 * The inline spec editor (PRD §12.2, v1.103): the full-page editor's flow in
 * a dialog on the service detail page, scoped to the one service the page
 * shows. Validate renders server-side and then checks the scope client-side
 * (lib/specScope.ts) against a fresh HTTP read of the stored record; an edit
 * that changes volumes, grants, the runtime or function config, another
 * service or a pipeline is refused by name with a pointer to the full editor.
 * Apply posts the same bytes that validated. A small deliberate duplicate of
 * SpecEditorPage's state machine (recurring rule 8): the two flows share the
 * diagnostics card and the git warning, and differ in scope and destination.
 */
export function SpecEditDialog({
  project,
  service,
  open,
  onClose,
}: {
  project: string
  service: string
  open: boolean
  onClose: () => void
}) {
  const { session, csrf } = useSession()
  const client = useQueryClient()
  const admin = session?.role === 'admin'
  const fullEditor = `/services/${project}/${service}/edit`

  const [text, setText] = useState('')
  const [loaded, setLoaded] = useState(false)
  // A generation refusal (pipeline project, inexpressible field): the dialog
  // shows it and links to the full editor. Never the template - that is the
  // deploy-new flow's seed, and offering it here would invite replacing a
  // running service with an example.
  const [refusal, setRefusal] = useState<string | null>(null)
  const [diagnostics, setDiagnostics] = useState<SpecDiagnostic[]>([])
  const [scopeError, setScopeError] = useState<string | null>(null)
  const [validated, setValidated] = useState(false)
  const [busy, setBusy] = useState<'validate' | 'apply' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmedOverwrite, setConfirmedOverwrite] = useState(false)
  const textarea = useRef<HTMLTextAreaElement>(null)

  // Each opening starts fresh from the generated source: a draft from a
  // previous visit would hide edits applied elsewhere in the meantime.
  // Re-seeded during render on the opening edge (ScaleDialog's pattern),
  // with the fetch itself in the effect below.
  const [wasOpen, setWasOpen] = useState(open)
  if (wasOpen !== open) {
    setWasOpen(open)
    if (open) {
      setText('')
      setLoaded(false)
      setRefusal(null)
      setDiagnostics([])
      setScopeError(null)
      setValidated(false)
      setError(null)
      setConfirmedOverwrite(false)
    }
  }

  useEffect(() => {
    if (!open) return
    let cancelled = false
    fetchSpecSource(project, service)
      .then((result) => {
        if (cancelled) return
        if ('hcl' in result) {
          setText(result.hcl)
        } else {
          setRefusal(result.refusal)
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
  }, [open, project, service])

  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => fetchProjects(signal),
    staleTime: 60_000,
    enabled: open,
  })
  const gitSource = (projects.data ?? []).find((p) => p.name === project)?.git

  const edit = (next: string) => {
    setText(next)
    setValidated(false)
    setScopeError(null)
  }

  const validate = () => {
    setBusy('validate')
    setError(null)
    setScopeError(null)
    // The baseline is fetched at validate time, over HTTP, so a concurrent
    // apply elsewhere is compared against rather than silently overwritten.
    Promise.all([renderSpec(text, project, csrf), fetchServiceRecord(project, service)])
      .then(([rendered, current]) => {
        setDiagnostics(rendered.diagnostics)
        if (!rendered.valid) {
          setValidated(false)
          return
        }
        const verdict = checkScope({ project, service, rendered, current })
        if (!verdict.ok) {
          setValidated(false)
          setScopeError(verdict.message)
          return
        }
        setValidated(true)
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
          return
        }
        // Services, allocs and stats arrive over the live socket; the events
        // list is the one polled query this page reads.
        void client.invalidateQueries({ queryKey: ['events', project] })
        onClose()
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(null))
  }

  // No rollout gate, deliberately: the full-page editor never had one, the
  // server owns concurrency, and an admin mid-rollout may be fixing the very
  // spec that is rolling.
  const applyBlocked =
    !admin || !validated || busy !== null || (gitSource !== undefined && !confirmedOverwrite)

  return (
    <Dialog
      open={open}
      onClose={onClose}
      dismissable={false}
      title={`Edit spec · ${project}/${service}`}
      className="w-[90vw] max-w-4xl"
    >
      <div className="max-h-[75vh] space-y-3 overflow-y-auto pr-1">
        {refusal ? (
          <>
            <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
              Could not generate this service's spec: {refusal}.
            </p>
            <div className="flex items-center gap-3">
              <Link
                to={fullEditor}
                className="text-sm text-primary underline-offset-4 hover:underline"
              >
                Open the full spec editor
              </Link>
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            </div>
          </>
        ) : (
          <>
            <p className="rounded-md border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
              Generated from the running desired state; comments and variable
              interpolations are not preserved. This edit is scoped to{' '}
              <span className="font-mono">
                {project}/{service}
              </span>
              : volumes, device and socket grants, and project or pipeline config are
              managed in the <Link to={fullEditor} className="underline underline-offset-4">full spec editor</Link>.
            </p>

            {gitSource ? (
              <GitSyncWarning
                git={gitSource}
                confirmed={confirmedOverwrite}
                onConfirm={setConfirmedOverwrite}
              />
            ) : null}

            <textarea
              ref={textarea}
              value={text}
              onChange={(e) => edit(e.target.value)}
              spellCheck={false}
              disabled={!loaded}
              aria-label="Job spec HCL"
              className="min-h-[20rem] w-full resize-y rounded-md border bg-muted/30 p-3 font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />

            {scopeError ? (
              <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
                {/* Composed in lib/specScope.ts from spec vocabulary: text, never markup. */}
                {scopeError}{' '}
                <Link to={fullEditor} className="underline underline-offset-4">
                  Open the full spec editor
                </Link>
              </p>
            ) : null}

            {diagnostics.length > 0 ? (
              <DiagnosticList
                diagnostics={diagnostics}
                onJump={(line) => jumpToLine(textarea.current, text, line)}
              />
            ) : null}

            <div className="flex flex-wrap items-center gap-2">
              <Button variant="outline" disabled={busy !== null || !loaded} onClick={validate}>
                {busy === 'validate' ? 'Validating…' : 'Validate'}
              </Button>
              <Button
                disabled={applyBlocked}
                title={
                  admin ? (validated ? undefined : 'Validate first') : 'Requires the admin role'
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
          </>
        )}
      </div>
    </Dialog>
  )
}
