import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { TableSkeleton } from '@/components/Skeletons'
import { PageHeader } from '@/components/PageHeader'
import { SortHeader } from '@/components/SortHeader'
import { StatTile } from '@/components/StatTile'
import { StatusDot, type StatusTone } from '@/components/StatusDot'
import { PaginationControls } from '@/components/Pagination'
import { usePagination } from '@/hooks/usePagination'
import { sortItems, useSort } from '@/hooks/useSort'
import { useLiveTopic } from '@/hooks/useLiveTopic'
import { useSession } from '@/hooks/useSession'
import {
  Topic,
  allocsResponseSchema,
  deleteProject,
  fetchProjects,
  servicesResponseSchema,
  stopProject,
  syncProject,
  type Alloc,
  type ProjectSummary,
  type Service,
} from '@/lib/api'
import { matchesQuery } from '@/lib/search'
import { groupAllocs, relativeAge, serviceHealth, serviceStatusTone } from '@/lib/state'

/**
 * Projects (PRD §4.2, §10.1, §12.2).
 *
 * A project is the namespace a service declares itself into, not a record;
 * which is why there is no "new project" button: declaring a service into a
 * name is how a project comes to exist, and a second way to make one would be
 * a second source of truth about which projects there are. Delete exists
 * (v1.104) because it is not that class of problem: it destroys the records
 * that make a project exist - its services and its pipeline config - so it
 * cannot disagree with the spec-driven path about what exists.
 *
 * Stop is the CLI's own recipe, not a route: every full record re-read over
 * HTTP and applied at count zero in one batch (stopProject in lib/api.ts says
 * why the scale route cannot do it). Remove goes through a dialog that names
 * every service it will delete, because the daemon's response and MCP's
 * result do the same: a destruction announces its scope first.
 *
 * Git sync status leads, because for a GitOps project it is the answer to "is
 * what I pushed what is running", and "Sync" here does what the poll loop
 * does, never what the webhook does: it marks the project and lets the sync
 * loop re-read the source over Kanea's own credential.
 *
 * A project's `description` is parsed from the spec but never stored on the
 * node, so this page cannot show one. That is a Store-shape decision, not an
 * omission here.
 */
export function Projects() {
  const client = useQueryClient()
  const { session, csrf } = useSession()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const [error, setError] = useState('')
  const sort = useSort<SortKey>()

  const projects = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => fetchProjects(signal),
    refetchInterval: 15_000,
  })

  // Both topics are the ones Services already subscribes to, so an expanded
  // row costs no request: the frames are already on the shared socket.
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)
  const allocs = useLiveTopic({ topic: Topic.Allocs }, allocsResponseSchema)

  const sync = useMutation({
    mutationFn: (project: string) => syncProject(project, csrf),
    onSuccess: () => {
      setError('')
      void client.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err: Error) => setError(err.message),
  })
  const stop = useMutation({
    mutationFn: (project: string) => stopProject(project, csrf),
    onSuccess: () => {
      setError('')
      void client.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err: Error) => setError(err.message),
  })
  // The dialog holds the project being confirmed; the mutation fires from it.
  const [removing, setRemoving] = useState<ProjectSummary | null>(null)
  const remove = useMutation({
    mutationFn: (project: string) => deleteProject(project, csrf),
    onSuccess: () => {
      setError('')
      setRemoving(null)
      void client.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const list = projects.data ?? []
  const filtered = list.filter((p) => matchesQuery(query, p.name, p.git?.url))
  const sorted = sortItems(filtered, sort, {
    project: (p) => p.name,
    services: (p) => p.services,
    allocs: (p) => p.allocs,
    // Ascending health reads problems-first: the reader clicking it wants what
    // is wrong, not the alphabet.
    health: (p) => healthRank[health(p).word],
  })
  const pager = usePagination(sorted, { resetKey: `${query} ${sort.key ?? ''} ${sort.dir}` })

  const canWrite = session?.role === 'admin'
  const gitBacked = list.filter((p) => p.git).length
  const running = list.reduce((sum, p) => sum + p.running, 0)
  const declared = list.reduce((sum, p) => sum + p.allocs, 0)

  return (
    <div className="space-y-4">
      <PageHeader
        title="Projects"
        subtitle={`${list.length} project${list.length === 1 ? '' : 's'} · ${list.reduce((n, p) => n + p.services, 0)} services`}
        actions={
          <Link to="/services/new">
            <Button className="font-semibold">Deploy service</Button>
          </Link>
        }
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <StatTile label="Projects" value={list.length} sub="namespaces in use" />
        <StatTile
          label="Git-backed"
          value={`${gitBacked}/${list.length}`}
          sub={gitBacked > 0 ? 'polled, and webhook-marked' : 'all deployed by pushing specs'}
        />
        <StatTile
          label="Allocs running"
          value={`${running}/${declared}`}
          tone={declared > 0 && running === declared ? 'ok' : declared > 0 ? 'error' : 'default'}
          sub="across every project"
        />
      </div>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      {projects.error ? (
        <Card className="p-4 text-sm text-destructive">{String(projects.error)}</Card>
      ) : projects.isPending ? (
        <TableSkeleton rows={4} cols={6} />
      ) : list.length === 0 ? (
        <Card className="p-4 text-sm text-muted-foreground">
          Nothing is deployed, so there are no projects. A project exists once a service
          declares itself into one.
        </Card>
      ) : (
        <>
          <div className="flex justify-end">
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search project or repository…"
              aria-label="Search projects"
              className="h-8 w-64 text-xs"
            />
          </div>

          {sorted.length === 0 ? (
            <Card className="p-4 text-sm text-muted-foreground">
              No projects match that filter.
            </Card>
          ) : (
            <Card className="py-2">
              <Table>
                <THead>
                  <tr>
                    <SortHeader sort={sort} sortKey="project" className="pt-2">
                      Project
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="services" className="pt-2">
                      Services
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="allocs" className="pt-2">
                      Allocs
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="health" className="pt-2">
                      Health
                    </SortHeader>
                    <TH className="pt-2">Git</TH>
                    <TH className="pt-2">Notifications</TH>
                    <TH className="pt-2 text-right">Actions</TH>
                  </tr>
                </THead>
                <TBody>
                  {pager.pageItems.map((project) => (
                    <ProjectRows
                      key={project.name}
                      project={project}
                      services={(services.data?.services ?? []).filter(
                        (s) => s.Project === project.name,
                      )}
                      servicesKnown={services.data !== null}
                      allocs={allocs.data?.allocs ?? []}
                      open={open[project.name] ?? false}
                      onToggle={() =>
                        setOpen((o) => ({ ...o, [project.name]: !o[project.name] }))
                      }
                      canWrite={canWrite}
                      syncing={sync.isPending && sync.variables === project.name}
                      onSync={() => sync.mutate(project.name)}
                      stopping={stop.isPending && stop.variables === project.name}
                      onStop={() => stop.mutate(project.name)}
                      onRemove={() => setRemoving(project)}
                    />
                  ))}
                </TBody>
              </Table>
              <div className="px-3">
                <PaginationControls state={pager} />
              </div>
            </Card>
          )}
        </>
      )}

      {removing ? (
        <RemoveProjectDialog
          project={removing}
          services={(services.data?.services ?? [])
            .filter((s) => s.Project === removing.name)
            .map((s) => s.Service)
            .sort()}
          pending={remove.isPending}
          onConfirm={() => remove.mutate(removing.name)}
          onClose={() => setRemoving(null)}
        />
      ) : null}

      <p className="text-xs text-muted-foreground">
        There is no create verb here: a project is the namespace its services declare themselves
        into, so deploy a service into a new name and the project exists. Remove (v1.104)
        deletes every service declaration and the project's pipeline config in one step; volume
        data, secrets and log files survive it. A synced repository speaks for its own project
        and no other: a spec that declares a different one is refused at sync, which is the
        boundary between "can push to one repo" and "owns every service on the node".
      </p>
    </div>
  )
}

/**
 * RemoveProjectDialog names everything a yes destroys before offering one:
 * the services by name (the daemon's response and MCP's result do the same),
 * the pipeline config on a git-backed project, and what survives.
 */
function RemoveProjectDialog({
  project,
  services,
  pending,
  onConfirm,
  onClose,
}: {
  project: ProjectSummary
  services: string[]
  pending: boolean
  onConfirm: () => void
  onClose: () => void
}) {
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Remove project · ${project.name}`}
      className="w-[90vw] max-w-md"
    >
      <div className="space-y-3 text-sm">
        {services.length > 0 ? (
          <p>
            This deletes {services.length} service declaration{services.length === 1 ? '' : 's'}:{' '}
            <span className="font-mono text-xs">{services.join(', ')}</span>
          </p>
        ) : (
          <p>
            This project declares no services; what goes is its stored configuration. (A
            git-backed project between its first apply and its first sync looks like this.)
          </p>
        )}
        {project.git ? (
          <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2">
            {/* A repository URL comes from operator config and renders as text. */}
            This project syncs from <span className="font-mono">{project.git.url}</span>. Its
            pipeline config and notification channels are deleted with it, and the repository
            stops syncing.
          </p>
        ) : null}
        <p className="text-muted-foreground">
          Volume data is kept, secrets under the project are not touched, and log files remain
          on disk. Re-applying a spec brings the services back with their data.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="outline"
            className="border-destructive text-destructive hover:bg-destructive/10"
            disabled={pending}
            onClick={onConfirm}
          >
            {pending ? 'Removing…' : 'Remove project'}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

type SortKey = 'project' | 'services' | 'allocs' | 'health'

/** Ascending health sort reads problems-first. */
const healthRank: Record<string, number> = { down: 0, degraded: 1, running: 2, stopped: 3, empty: 4 }

/**
 * health summarises a project from its own counts.
 *
 * Deliberately not a probe reading: `AllocRecord.Healthy` is written only by a
 * probe, so folding it in here would report every check-free project as broken.
 * "Running" means the runtime has the allocs the spec asked for.
 */
function health(project: ProjectSummary): { tone: StatusTone; word: string } {
  if (project.services === 0 && project.allocs === 0) return { tone: 'muted', word: 'empty' }
  if (project.allocs === 0) return { tone: 'muted', word: 'stopped' }
  if (project.running === project.allocs) return { tone: 'ok', word: 'running' }
  if (project.running === 0) return { tone: 'error', word: 'down' }
  return { tone: 'warn', word: 'degraded' }
}

/** ProjectRows is the project row plus, when expanded, its services. */
function ProjectRows({
  project,
  services,
  servicesKnown,
  allocs,
  open,
  onToggle,
  canWrite,
  syncing,
  onSync,
  stopping,
  onStop,
  onRemove,
}: {
  project: ProjectSummary
  services: Service[]
  servicesKnown: boolean
  allocs: Alloc[]
  open: boolean
  onToggle: () => void
  canWrite: boolean
  syncing: boolean
  onSync: () => void
  stopping: boolean
  onStop: () => void
  onRemove: () => void
}) {
  const state = health(project)
  const byService = groupAllocs(allocs)

  // Stop's two-click confirm, ServiceActions' pattern: armed by the first
  // click, fired by the second, and auto-disarmed after a beat - a button
  // left reading "confirm stop?" for minutes is a trap.
  const [confirmStop, setConfirmStop] = useState(false)
  useEffect(() => {
    if (!confirmStop) return
    const timer = setTimeout(() => setConfirmStop(false), 4000)
    return () => clearTimeout(timer)
  }, [confirmStop])

  return (
    <>
      <TR>
        <TD>
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            className="group flex items-center gap-1.5 text-left"
          >
            {open ? (
              <ChevronDown size={14} className="shrink-0 text-muted-foreground" aria-hidden />
            ) : (
              <ChevronRight size={14} className="shrink-0 text-muted-foreground" aria-hidden />
            )}
            <span className="font-medium group-hover:underline">{project.name}</span>
          </button>
        </TD>
        <TD className="font-mono tabular-nums">{project.services}</TD>
        <TD className="font-mono tabular-nums">
          {project.running}/{project.allocs}
        </TD>
        <TD>
          <StatusDot tone={state.tone} label={state.word} />
        </TD>
        <TD>
          <GitCell project={project} />
        </TD>
        <TD>
          {project.notifications && project.notifications.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {project.notifications.map((channel) => (
                <Badge key={channel} variant="muted" className="font-mono text-[11px]">
                  {channel}
                </Badge>
              ))}
            </div>
          ) : (
            <span className="font-mono text-xs text-muted-foreground">-</span>
          )}
        </TD>
        <TD className="text-right">
          <div className="flex justify-end gap-1.5">
            {project.git ? (
              <Button
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs"
                disabled={!canWrite || syncing}
                title={canWrite ? undefined : 'Requires the admin role'}
                onClick={onSync}
              >
                {syncing ? 'Syncing…' : 'Sync now'}
              </Button>
            ) : null}
            <Button
              size="sm"
              variant="outline"
              className={`h-7 px-2 text-xs ${confirmStop ? 'border-destructive text-destructive hover:bg-destructive/10' : ''}`}
              disabled={!canWrite || stopping || project.services === 0}
              title={
                canWrite
                  ? 'Scale every service in the project to zero'
                  : 'Requires the admin role'
              }
              onClick={() => {
                if (!confirmStop) {
                  setConfirmStop(true)
                  return
                }
                setConfirmStop(false)
                onStop()
              }}
            >
              {stopping ? 'Stopping…' : confirmStop ? 'Confirm stop?' : 'Stop'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-xs"
              disabled={!canWrite}
              title={
                canWrite
                  ? 'Delete every service and the project config; volume data is kept'
                  : 'Requires the admin role'
              }
              onClick={onRemove}
            >
              Remove
            </Button>
          </div>
        </TD>
      </TR>

      {open ? (
        <TR className="bg-muted/20">
          <TD colSpan={7} className="pl-9">
            {!servicesKnown ? (
              <span className="text-xs text-muted-foreground">Waiting for the service list…</span>
            ) : services.length === 0 ? (
              <span className="text-xs text-muted-foreground">
                No services yet: a git-backed project between its first apply and its first
                successful sync looks exactly like this.
              </span>
            ) : (
              <div className="flex flex-wrap gap-x-6 gap-y-2 py-1">
                {services.map((svc) => {
                  const own = byService.get(`${svc.Project}/${svc.Service}`) ?? []
                  const tone = serviceStatusTone(serviceHealth(svc, own))
                  return (
                    <Link
                      key={svc.Service}
                      to={`/services/${svc.Project}/${svc.Service}`}
                      className="group flex items-center gap-2 text-sm"
                    >
                      <StatusDot tone={tone.tone} />
                      <span className="group-hover:underline">{svc.Service}</span>
                      <span className="font-mono text-xs tabular-nums text-muted-foreground">
                        {own.filter((a) => a.state === 'running').length}/{svc.Count}
                      </span>
                    </Link>
                  )
                })}
              </div>
            )}
          </TD>
        </TR>
      ) : null}
    </>
  )
}

/** GitCell reports where a project's spec comes from, and when it last did. */
function GitCell({ project }: { project: ProjectSummary }) {
  const git = project.git
  if (!git) {
    return <span className="font-mono text-xs text-muted-foreground">pushed specs</span>
  }
  return (
    <div className="min-w-0">
      {/* A repository URL comes from an operator's config and renders as text. */}
      <span className="block truncate font-mono text-xs">
        {git.url}
        {git.branch ? `#${git.branch}` : ''}
      </span>
      <span className="block font-mono text-[11px] text-muted-foreground">
        {git.last_commit ? git.last_commit.slice(0, 7) : 'never synced'}
        {git.last_sync_at ? ` · ${relativeAge(git.last_sync_at)} ago` : ''}
      </span>
    </div>
  )
}
