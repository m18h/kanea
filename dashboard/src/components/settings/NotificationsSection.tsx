import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ChannelEditor } from '@/components/settings/ChannelEditor'
import {
  fetchProjectNotifications,
  fetchProjects,
  putNotificationSettings,
  putProjectNotifications,
  resetNotificationSettings,
  testNodeChannels,
  testProjectChannels,
  type ChannelTestResult,
  type NotificationSettingsView,
  type WireNotifications,
} from '@/lib/api'
import {
  channelFormsFromWire,
  channelFormsToWire,
  enabledChannelKinds,
  type ChannelForms,
} from '@/lib/settings'

/**
 * NotificationsSection edits the node-level default channels (the record
 * routes without a project scope are built from) and each project's override.
 *
 * A test sends a real message and deliberately bypasses the filters — a
 * channel configured for deploy.* would otherwise discard the test and leave
 * the operator no better informed (internal/notify's own rule).
 */
export function NotificationsSection({
  view,
  csrf,
  canWrite,
}: {
  view: NotificationSettingsView
  csrf: string | undefined
  canWrite: boolean
}) {
  const client = useQueryClient()
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [results, setResults] = useState<ChannelTestResult[] | null>(null)
  const [forms, setForms] = useState<ChannelForms>(() =>
    channelFormsFromWire(view.settings?.channels),
  )

  const save = useMutation({
    mutationFn: (channels: WireNotifications) => putNotificationSettings(channels, csrf),
    onSuccess: () => {
      setError('')
      setSaved(true)
      void client.invalidateQueries({ queryKey: ['settings'] })
    },
    onError: (err: Error) => {
      setSaved(false)
      setError(err.message)
    },
  })

  const remove = useMutation({
    mutationFn: () => resetNotificationSettings(csrf),
    onSuccess: () => {
      setError('')
      setSaved(false)
      setForms(channelFormsFromWire(null))
      void client.invalidateQueries({ queryKey: ['settings'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const test = useMutation({
    mutationFn: (channel: string) => testNodeChannels(channel, csrf),
    onSuccess: (r) => setResults(r),
    onError: (err: Error) => setError(err.message),
  })

  const configured = enabledChannelKinds(view.settings?.channels)

  const submit = () => {
    const built = channelFormsToWire(forms)
    if ('error' in built) {
      setError(built.error)
      return
    }
    save.mutate(built.channels)
  }

  return (
    <section className="space-y-3">
      <div className="flex items-baseline gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Notifications</h2>
        <Badge variant={view.source === 'store' ? 'ok' : 'muted'}>
          {view.source === 'store' ? 'node defaults set' : 'no node defaults'}
        </Badge>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          {error}
        </p>
      ) : null}
      {saved ? (
        <p className="rounded-md border border-status-ok/40 bg-status-ok/10 px-3 py-2 text-sm">
          Node default channels saved.
        </p>
      ) : null}

      <ChannelEditor value={forms} onChange={(next) => { setSaved(false); setForms(next) }} disabled={!canWrite} idPrefix="node" />

      {canWrite ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={save.isPending} onClick={submit}>
            {save.isPending ? 'Saving…' : 'Save node defaults'}
          </Button>
          {view.source === 'store' ? (
            <Button
              variant="outline"
              className={confirmRemove ? 'border-status-warn text-status-warn' : ''}
              disabled={remove.isPending}
              onClick={() => {
                if (!confirmRemove) {
                  setConfirmRemove(true)
                  return
                }
                setConfirmRemove(false)
                remove.mutate()
              }}
            >
              {confirmRemove ? 'Confirm remove?' : 'Remove node defaults'}
            </Button>
          ) : null}
          {configured.map((kind) => (
            <Button
              key={kind}
              size="sm"
              variant="outline"
              disabled={test.isPending}
              onClick={() => test.mutate(kind)}
            >
              Test {kind}
            </Button>
          ))}
        </div>
      ) : null}

      {results ? <TestResults results={results} /> : null}

      <ProjectNotifications csrf={csrf} canWrite={canWrite} />
    </section>
  )
}

/** TestResults renders what each channel did with a test message. */
function TestResults({ results }: { results: ChannelTestResult[] }) {
  return (
    <div className="space-y-1">
      {results.map((r, i) => (
        <p key={`${r.channel}-${i}`} className="text-sm">
          <Badge variant={r.ok ? 'ok' : 'error'} className="mr-2 font-mono text-[11px]">
            {r.channel}
          </Badge>
          {r.ok ? 'delivered' : <span className="text-destructive">{r.error ?? 'failed'}</span>}
        </p>
      ))}
    </div>
  )
}

/** ProjectNotifications lists projects and opens one override editor at a time. */
function ProjectNotifications({
  csrf,
  canWrite,
}: {
  csrf: string | undefined
  canWrite: boolean
}) {
  const [open, setOpen] = useState<string | null>(null)
  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => fetchProjects(signal),
  })

  const list = projects.data ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Per-project channels</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {projects.isError ? (
          <p className="text-sm text-destructive">Cannot read the project list.</p>
        ) : null}
        {projects.isSuccess && list.length === 0 ? (
          <p className="text-sm text-muted-foreground">No projects yet.</p>
        ) : null}
        {list.map((p) => (
          <div key={p.name} className="rounded-md border">
            <button
              type="button"
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-muted/40"
              onClick={() => setOpen(open === p.name ? null : p.name)}
            >
              <span className="font-medium">{p.name}</span>
              <span className="ml-auto flex items-center gap-1">
                {(p.notifications ?? []).map((kind) => (
                  <Badge key={kind} variant="muted" className="font-mono text-[11px]">
                    {kind}
                  </Badge>
                ))}
              </span>
            </button>
            {open === p.name ? (
              <div className="border-t px-3 py-3">
                <ProjectEditor project={p.name} csrf={csrf} canWrite={canWrite} />
              </div>
            ) : null}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

/** ProjectEditor loads one project's channels and edits them in place. */
function ProjectEditor({
  project,
  csrf,
  canWrite,
}: {
  project: string
  csrf: string | undefined
  canWrite: boolean
}) {
  const client = useQueryClient()
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [results, setResults] = useState<ChannelTestResult[] | null>(null)
  const [forms, setForms] = useState<ChannelForms | null>(null)

  const config = useQuery({
    queryKey: ['project-notifications', project],
    queryFn: ({ signal }) => fetchProjectNotifications(project, signal),
  })

  const save = useMutation({
    mutationFn: (n: WireNotifications | null) => putProjectNotifications(project, n, csrf),
    onSuccess: (_view, sent) => {
      setError('')
      setSaved(true)
      if (sent === null) setForms(channelFormsFromWire(null))
      void client.invalidateQueries({ queryKey: ['project-notifications', project] })
      void client.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err: Error) => {
      setSaved(false)
      setError(err.message)
    },
  })

  const test = useMutation({
    mutationFn: (channel: string) => testProjectChannels(project, channel, csrf),
    onSuccess: (r) => setResults(r),
    onError: (err: Error) => setError(err.message),
  })

  if (config.isError) {
    return <p className="text-sm text-destructive">Cannot read this project's channels.</p>
  }
  if (!config.data) {
    return <p className="text-sm text-muted-foreground">Loading…</p>
  }

  const view = config.data
  const value = forms ?? channelFormsFromWire(view.notifications)
  const configured = enabledChannelKinds(view.notifications)

  const submit = () => {
    const built = channelFormsToWire(value)
    if ('error' in built) {
      setError(built.error)
      return
    }
    save.mutate(built.channels)
  }

  return (
    <div className="space-y-3">
      {view.git_managed ? (
        <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          {view.warning ??
            'This project is synced from git — the next sync wins. Make the change in the ' +
              'repository, or it will be overwritten.'}
        </p>
      ) : null}
      {error ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          {error}
        </p>
      ) : null}
      {saved ? (
        <p className="rounded-md border border-status-ok/40 bg-status-ok/10 px-3 py-2 text-sm">
          Saved.
        </p>
      ) : null}

      <ChannelEditor
        value={value}
        onChange={(next) => {
          setSaved(false)
          setForms(next)
        }}
        disabled={!canWrite}
        idPrefix={`project-${project}`}
      />

      {canWrite ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" disabled={save.isPending} onClick={submit}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
          {view.notifications ? (
            <Button
              size="sm"
              variant="outline"
              className={confirmRemove ? 'border-status-warn text-status-warn' : ''}
              disabled={save.isPending}
              onClick={() => {
                if (!confirmRemove) {
                  setConfirmRemove(true)
                  return
                }
                setConfirmRemove(false)
                save.mutate(null)
              }}
            >
              {confirmRemove ? 'Confirm remove?' : 'Remove channels'}
            </Button>
          ) : null}
          {configured.map((kind) => (
            <Button
              key={kind}
              size="sm"
              variant="outline"
              disabled={test.isPending}
              onClick={() => test.mutate(kind)}
            >
              Test {kind}
            </Button>
          ))}
        </div>
      ) : null}

      {results ? <TestResults results={results} /> : null}
    </div>
  )
}
