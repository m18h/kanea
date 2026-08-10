import { z } from 'zod'
import { apiFetch } from './session'

/**
 * Wire schemas for everything the daemon sends.
 *
 * Parsed rather than cast. A `as ServicesResponse` would let a shape change in
 * the daemon surface as a blank screen or an undefined-property crash three
 * components away; a zod parse fails at the boundary and says which field.
 */

export const resourcesSchema = z.object({
  CPUMillis: z.number(),
  MemoryBytes: z.number(),
  PidsLimit: z.number().optional(),
})

export const exposeSchema = z.object({
  Domains: z.array(z.string()).nullish(),
  Port: z.number(),
  // Where the certificate comes from (R20). Empty means the node's
  // --tls-default decides, so this is not a value to render as "none".
  TLSMode: z.string().optional(),
  TLSName: z.string().optional(),
  // The pre-v1.33 spelling, still on records written before the upgrade.
  LetsEncrypt: z.boolean().optional(),
})

// A node port the edge binds for this service (R21, §7.2.2). A service can
// publish without being exposed: Jellyfin on :8096 with no domain is the case
// the feature exists for.
export const publishSchema = z.object({
  Port: z.string(),
  Host: z.number(),
  Mode: z.string().optional(),
  MaxConns: z.number().optional(),
})

// The declared autoscaling policy (§9.2). The outer key is PascalCase because
// Desired's field is untagged; the inner fields carry json tags.
export const scalingPolicySchema = z.object({
  min: z.number(),
  max: z.number(),
  metrics: z.array(z.object({ name: z.string(), target: z.number() })).nullish(),
  cooldown: z.string().optional(),
})

export const serviceSchema = z.object({
  Project: z.string(),
  Service: z.string(),
  Count: z.number(),
  Image: z.string(),
  Resources: resourcesSchema,
  Expose: exposeSchema.nullish(),
  Publish: z.array(publishSchema).nullish(),
  DependsOn: z.array(z.string()).nullish(),
  Scaling: scalingPolicySchema.nullish(),
  // v1.39: a service lowered from a `function` block. The marker is what the
  // Functions page filters on and the Services page filters out — one record,
  // shown on exactly one page. Both fields carry lowercase json tags.
  runtime: z.string().optional(),
  function: z.unknown().nullish(),
})

export const servicesResponseSchema = z.object({
  services: z.array(serviceSchema).nullish(),
})

// AllocRecord marshals with lowercase json tags (internal/reconciler/types.go),
// unlike Desired whose untagged fields ride as PascalCase. The distinction is
// the Go structs', not ours — match it field for field.
export const allocSchema = z.object({
  id: z.string(),
  project: z.string(),
  service: z.string(),
  index: z.number(),
  state: z.string(),
  image: z.string().optional(),
  restarts: z.number().optional(),
  last_exit_code: z.number().optional(),
  last_exit_at: z.string().optional(),
  healthy: z.boolean().optional(),
  health_message: z.string().optional(),
  last_probe_at: z.string().optional(),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
})

export const allocsResponseSchema = z.object({
  allocs: z.array(allocSchema).nullish(),
})

export const logLineSchema = z.object({
  alloc_id: z.string(),
  line: z.string(),
})

// Functions (v1.39, GET /v1/functions): wasm functions with their triggers,
// derived status and the invoker's counters.
export const eventTriggerSchema = z.object({
  on: z.array(z.string()),
  path: z.string().optional(),
})

export const cronTriggerSchema = z.object({
  schedule: z.string(),
  path: z.string().optional(),
})

export const invokerStatsSchema = z.object({
  invocations: z.number(),
  failures: z.number(),
  last_invoked: z.string().optional(),
  latencies_ms: z.array(z.number()).nullish(),
})

export const functionViewSchema = z.object({
  project: z.string(),
  service: z.string(),
  module: z.string(),
  run_module: z.string().optional(),
  count: z.number(),
  runtime: z.string(),
  memory_bytes: z.number(),
  http: z.boolean().optional(),
  domains: z.array(z.string()).nullish(),
  events: z.array(eventTriggerSchema).nullish(),
  crons: z.array(cronTriggerSchema).nullish(),
  status: z.string(),
  running: z.number(),
  healthy: z.number(),
  restarts: z.number(),
  // Absent means "not measured", never zero — the datapath is not scraped
  // under --network netns, and a dash is the honest render.
  invocations_per_minute: z.number().optional(),
  invoker: invokerStatsSchema.nullish(),
})

export const functionsResponseSchema = z.object({
  functions: z.array(functionViewSchema).nullish(),
  invoker_dropped: z.number().optional(),
})

export type FunctionView = z.infer<typeof functionViewSchema>
export type FunctionsResponse = z.infer<typeof functionsResponseSchema>

export async function fetchFunctions(signal?: AbortSignal): Promise<FunctionsResponse> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch('/v1/functions', init)
  if (!resp.ok) throw new Error(`functions: ${resp.status}`)
  return functionsResponseSchema.parse(await resp.json())
}

/**
 * What sign-in methods the daemon offers.
 *
 * It rides on health because that is the one route reachable without a
 * credential (PRD §5.2.1), and the login screen needs the answer before it has
 * one to ask with.
 */
export const oidcStatusSchema = z.object({
  enabled: z.boolean(),
  issuer: z.string().optional(),
  start_path: z.string().optional(),
})

export const healthSchema = z.object({
  status: z.string(),
  version: z.string(),
  store_index: z.number(),
  ws_connections: z.number(),
  oidc: oidcStatusSchema.nullish(),
  // Optional so the dashboard also renders against a pre-v1.38 daemon, which
  // simply has no uptime to report.
  pid: z.number().optional(),
  started_at: z.string().optional(),
  uptime_seconds: z.number().optional(),
})

export type Service = z.infer<typeof serviceSchema>
export type Alloc = z.infer<typeof allocSchema>
export type LogLine = z.infer<typeof logLineSchema>
export type Health = z.infer<typeof healthSchema>
export type OIDCStatus = z.infer<typeof oidcStatusSchema>

/**
 * Live resource and traffic samples for one service (PRD §9.1, §12.2).
 *
 * Every value is optional on purpose: the daemon omits a metric it has nothing
 * recent for, and a chart draws that as a gap. "No data" and "no load" are
 * different facts, and drawing them alike says a stopped scraper is an idle
 * service.
 */
export const allocStatsSchema = z.object({
  alloc_id: z.string(),
  cpu: z.number().optional(),
  memory: z.number().optional(),
  memory_bytes: z.number().optional(),
})

/**
 * The edge's labelled totals (PRD §9.1.1).
 *
 * Cumulative counters for the life of the edge process, not a rate. Absent
 * entirely when the edge has not been scraped or the service is not exposed —
 * which is a different fact from a service that has served nothing, and the
 * UI has to render the two differently.
 */
export const edgeBreakdownSchema = z.object({
  codes: z.record(z.string(), z.number()).nullish(),
  request_bytes: z.number(),
  response_bytes: z.number(),
})

export const statsSampleSchema = z.object({
  service: z.string(),
  at: z.string(),
  cpu: z.number().optional(),
  memory: z.number().optional(),
  rps: z.number().optional(),
  p95_latency_ms: z.number().optional(),
  allocs: z.array(allocStatsSchema).nullish(),
  edge: edgeBreakdownSchema.optional(),
})

export type StatsSample = z.infer<typeof statsSampleSchema>
export type AllocStats = z.infer<typeof allocStatsSchema>
export type EdgeBreakdown = z.infer<typeof edgeBreakdownSchema>

/** Topics the live socket carries (PRD §12.1). */
export const Topic = {
  Services: 'services',
  Allocs: 'allocs',
  Logs: 'logs',
  Stats: 'stats',
} as const

export type TopicName = (typeof Topic)[keyof typeof Topic]

export const serverFrameSchema = z.object({
  type: z.enum(['data', 'error', 'pong']),
  topic: z.string().optional(),
  key: z.string().optional(),
  data: z.unknown().optional(),
  error: z.string().optional(),
})

export type ServerFrame = z.infer<typeof serverFrameSchema>

export interface SubscribeRequest {
  topic: TopicName
  project?: string
  service?: string
  tail?: number
}

/** The subscription key the daemon echoes back, so frames can be routed. */
export function subscriptionKey(req: SubscribeRequest): string {
  if (!req.project && !req.service) return req.topic
  return `${req.topic}:${req.project ?? ''}/${req.service ?? ''}`
}

/** Fetch the daemon's health over REST. */
export async function fetchHealth(signal?: AbortSignal): Promise<Health> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch('/v1/healthz', init)
  if (!resp.ok) throw new Error(`health: ${resp.status}`)
  return healthSchema.parse(await resp.json())
}

/**
 * A pipeline run (PRD §10.2).
 *
 * Every optional field really is optional on the wire: a queued run has no
 * commit, a failed one has no image, and a step that is still going has no
 * finish time. Making them required would have the dashboard reject the exact
 * records an operator most wants to look at.
 */
export const runStepSchema = z.object({
  name: z.string(),
  state: z.string(),
  started_at: z.string(),
  finished_at: z.string().optional(),
  error: z.string().optional(),
})

export const runSchema = z.object({
  id: z.string(),
  project: z.string(),
  service: z.string(),
  state: z.string(),
  trigger: z.string(),
  triggered_by: z.string().optional(),
  commit: z.string().optional(),
  ref: z.string().optional(),
  image: z.string().optional(),
  digest: z.string().optional(),
  steps: z.array(runStepSchema).optional(),
  started_at: z.string(),
  finished_at: z.string().optional(),
  error: z.string().optional(),
})

export const runsResponseSchema = z.object({
  runs: z.array(runSchema),
})

export type Run = z.infer<typeof runSchema>
export type RunStep = z.infer<typeof runStepSchema>

/** Terminal run states — the ones that will not change again. */
const terminalRunStates = new Set(['succeeded', 'failed', 'cancelled'])

export function isRunFinished(run: Run): boolean {
  return terminalRunStates.has(run.state)
}

/** List pipeline runs, newest first. */
export async function fetchRuns(
  opts: { project?: string; service?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<Run[]> {
  const query = new URLSearchParams()
  if (opts.project) query.set('project', opts.project)
  if (opts.service) query.set('service', opts.service)
  if (opts.limit) query.set('limit', String(opts.limit))

  const suffix = query.toString() ? `?${query}` : ''
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch(`/v1/pipelines${suffix}`, init)
  // 503 is "this daemon has no builder", which is a normal configuration and
  // not an error worth a red banner. It reads as an empty list.
  if (resp.status === 503) return []
  if (!resp.ok) throw new Error(`pipelines: ${resp.status}`)
  return runsResponseSchema.parse(await resp.json()).runs
}

/** Fetch one run. */
export async function fetchRun(
  project: string,
  service: string,
  id: string,
  signal?: AbortSignal,
): Promise<Run> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch(`/v1/pipelines/${enc(project)}/${enc(service)}/${enc(id)}`, init)
  if (!resp.ok) throw new Error(`run: ${resp.status}`)
  return runSchema.parse(await resp.json())
}

/**
 * Fetch a run's build log as text.
 *
 * Polled rather than streamed, unlike workload logs. A build log is at most a
 * few hundred kilobytes and finishes on its own, so re-reading it costs less
 * than a second websocket topic that would exist for one page.
 */
export async function fetchRunLog(
  project: string,
  service: string,
  id: string,
  signal?: AbortSignal,
): Promise<string> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch(
    `/v1/pipelines/${enc(project)}/${enc(service)}/${enc(id)}/logs`,
    init,
  )
  // A queued run has no log file yet, which is not a failure.
  if (resp.status === 404) return ''
  if (!resp.ok) throw new Error(`build log: ${resp.status}`)
  return await resp.text()
}

/** Queue a build. */
export async function triggerBuild(
  project: string,
  service: string,
  deploy: boolean,
): Promise<Run> {
  const resp = await fetch(`/v1/pipelines/${enc(project)}/${enc(service)}/build`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deploy }),
  })
  if (!resp.ok) throw new Error(await refusalText(resp, 'build'))
  return runSchema.parse(await resp.json())
}

// ---- service lifecycle (PRD §5.2.1, v1.26) ----

/**
 * scaleService writes one number; the reconciler converges.
 *
 * Stop is a scale to zero and start is a scale back up — the same route the
 * autoscaler and `kanea scale` use, so there is no second path to the runtime
 * for the dashboard to disagree with.
 */
export async function scaleService(
  project: string,
  service: string,
  count: number,
  csrf?: string,
): Promise<void> {
  await apiFetch(`/v1/services/${enc(project)}/${enc(service)}/scale`, {
    method: 'POST',
    body: { count },
    ...(csrf ? { csrf } : {}),
  })
}

/** restartService bumps the restart generation — a rolling restart through the
 * same update policy a deploy uses. */
export async function restartService(project: string, service: string, csrf?: string): Promise<void> {
  await apiFetch(`/v1/services/${enc(project)}/${enc(service)}/restart`, {
    method: 'POST',
    ...(csrf ? { csrf } : {}),
  })
}

/** Sync a project's git source. */
export async function syncProject(project: string): Promise<void> {
  const resp = await fetch(`/v1/projects/${enc(project)}/sync`, { method: 'POST' })
  if (!resp.ok) throw new Error(await refusalText(resp, 'sync'))
}

/**
 * refusalText turns a refusal into something an operator can act on.
 *
 * The daemon's message says which of several conditions failed — no build
 * block, no git source, queue full — and a bare status code says none of it.
 */
async function refusalText(resp: Response, what: string): Promise<string> {
  try {
    const body: unknown = await resp.json()
    if (body && typeof body === 'object' && 'error' in body) {
      const message = body.error
      if (typeof message === 'string' && message) return message
    }
  } catch {
    // Not JSON. The status is all there is.
  }
  return `${what}: ${resp.status}`
}

/** enc escapes one path segment. Names are DNS-1123, but URLs are URLs. */
function enc(segment: string): string {
  return encodeURIComponent(segment)
}

// ---- events (PRD §11, §12) ----

export const eventSchema = z.object({
  id: z.string(),
  name: z.string(),
  // Severity arrives as a name — the Go side marshals it that way so a feed is
  // readable without a lookup table.
  severity: z.enum(['info', 'warning', 'error']).catch('warning'),
  project: z.string().optional(),
  service: z.string().optional(),
  message: z.string(),
  detail: z.string().optional(),
  at: z.string(),
})

export const eventsResponseSchema = z.object({
  events: z.array(eventSchema).default([]),
  // How many events the dispatcher could not queue. Surfaced rather than
  // hidden: a feed that is quiet because everything is fine and one that is
  // quiet because the queue overflowed look identical otherwise.
  dropped: z.number().optional(),
})

export type KaneaEvent = z.infer<typeof eventSchema>
export type EventsResponse = z.infer<typeof eventsResponseSchema>

/** Read the notification feed, newest first. */
export async function fetchEvents(
  opts: { project?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<EventsResponse> {
  const query = new URLSearchParams()
  if (opts.project) query.set('project', opts.project)
  if (opts.limit) query.set('limit', String(opts.limit))

  const suffix = query.toString() ? `?${query}` : ''
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch(`/v1/events${suffix}`, init)
  if (!resp.ok) throw new Error(`events: ${resp.status}`)
  return eventsResponseSchema.parse(await resp.json())
}

// ---- node stats (PRD §17) ----

/**
 * The machine's own numbers. Every metric is optional because the reader
 * reports nothing rather than a made-up figure — the first CPU read has no
 * delta to compute from, and procfs may be unreadable entirely.
 */
export const nodeMachineSchema = z.object({
  cpu_percent: z.number().optional(),
  load1: z.number().optional(),
  load5: z.number().optional(),
  load15: z.number().optional(),
  memory_total_bytes: z.number().optional(),
  memory_available_bytes: z.number().optional(),
  memory_percent: z.number().optional(),
  cores: z.number(),
  at: z.string(),
})

export const nodeStatsSchema = z.object({
  version: z.string(),
  projects: z.number(),
  services: z.number(),
  allocs: z.number(),
  running: z.number(),
  unhealthy: z.number(),
  failed: z.number(),
  metrics: z.object({ series: z.number(), dropped: z.number() }).nullish(),
  breaker_open: z.boolean(),
  events_dropped: z.number().optional(),
  node: nodeMachineSchema.nullish(),
  at: z.string(),
})

export type NodeStats = z.infer<typeof nodeStatsSchema>

/** Fetch the node summary: declared counts, alloc states, machine stats. */
export async function fetchNodeStats(signal?: AbortSignal): Promise<NodeStats> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch('/v1/stats', init)
  if (!resp.ok) throw new Error(`stats: ${resp.status}`)
  return nodeStatsSchema.parse(await resp.json())
}

// ---- stats history (PRD §9.1, v1.38) ----

export const historyPointSchema = z.object({
  at: z.string(),
  value: z.number(),
})

export const statsHistorySchema = z.object({
  subject: z.string(),
  from: z.string(),
  to: z.string(),
  interval_seconds: z.number(),
  // Sparse: a gap is an absent point, never a zero. The interval is what lets
  // the client rebuild fixed slots and put the gaps back.
  series: z.record(z.string(), z.array(historyPointSchema).nullable()),
})

export type StatsHistory = z.infer<typeof statsHistorySchema>

/**
 * Fetch a metric history for seeding sparklines. Returns null when the daemon
 * predates the route or has no metrics store — the charts then simply start
 * empty and accumulate live, exactly as they did before v1.38.
 */
export async function fetchStatsHistory(
  target: { project: string; service: string } | 'node',
  signal?: AbortSignal,
): Promise<StatsHistory | null> {
  const suffix =
    target === 'node' ? '' : `?project=${enc(target.project)}&service=${enc(target.service)}`
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch(`/v1/stats/history${suffix}`, init)
  if (resp.status === 404 || resp.status === 503) return null
  if (!resp.ok) throw new Error(`history: ${resp.status}`)
  return statsHistorySchema.parse(await resp.json())
}

// ---- projects (PRD §12.2) ----

export const projectGitSchema = z.object({
  url: z.string(),
  branch: z.string().optional(),
  path: z.string().optional(),
  last_commit: z.string().optional(),
  last_sync_at: z.string().optional(),
})

export const projectSummarySchema = z.object({
  name: z.string(),
  services: z.number(),
  allocs: z.number(),
  running: z.number(),
  git: projectGitSchema.nullish(),
  // Channel names only, never tokens — which is also all the routing hint on
  // the Events page needs.
  notifications: z.array(z.string()).nullish(),
})

export const projectsResponseSchema = z.object({
  projects: z.array(projectSummarySchema).nullish(),
})

export type ProjectSummary = z.infer<typeof projectSummarySchema>

/** List projects with their git and notification facts. */
export async function fetchProjects(signal?: AbortSignal): Promise<ProjectSummary[]> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch('/v1/projects', init)
  if (!resp.ok) throw new Error(`projects: ${resp.status}`)
  return projectsResponseSchema.parse(await resp.json()).projects ?? []
}

// ---- audit log (PRD §13.3, §14 A09) ----

export const auditEntrySchema = z.object({
  id: z.string(),
  time: z.string(),
  actor: z.string().optional(),
  role: z.string().optional(),
  via: z.string().optional(),
  action: z.string(),
  target: z.string().optional(),
  result: z.string(),
  status: z.number().optional(),
  source: z.string().optional(),
  detail: z.string().optional(),
})

export const auditResponseSchema = z.object({
  entries: z.array(auditEntrySchema).nullish(),
  next_after: z.string().optional(),
  more: z.boolean().optional(),
})

export type AuditEntry = z.infer<typeof auditEntrySchema>

/** Read the audit log, newest first. Admin-only at the daemon. */
export async function fetchAudit(limit: number, signal?: AbortSignal): Promise<AuditEntry[]> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch(`/v1/audit?limit=${limit}`, init)
  if (!resp.ok) throw new Error(`audit: ${resp.status}`)
  return auditResponseSchema.parse(await resp.json()).entries ?? []
}

// ---- backups (PRD §15.3) ----

export const backupPartSchema = z.object({
  name: z.string(),
  size: z.number(),
  sha256: z.string(),
})

export const backupSchema = z.object({
  id: z.string(),
  key_id: z.string().optional(),
  created_at: z.string(),
  index: z.number(),
  reason: z.string().optional(),
  node: z.string().optional(),
  version: z.string().optional(),
  snapshot: backupPartSchema,
  counts: z.record(z.string(), z.number()).optional(),
})

export const replicationStatusSchema = z.object({
  sink: z.string().default(''),
  shipped_to: z.number().default(0),
  last_segment_at: z.string().optional(),
  last_snapshot_at: z.string().optional(),
  failures: z.number().default(0),
})

export const backupsResponseSchema = z.object({
  backups: z.array(backupSchema).default([]),
  replication: replicationStatusSchema.default({
    sink: '',
    shipped_to: 0,
    failures: 0,
  }),
})

export type Backup = z.infer<typeof backupSchema>
export type ReplicationStatus = z.infer<typeof replicationStatusSchema>
export type BackupsResponse = z.infer<typeof backupsResponseSchema>

/**
 * List archives and report replication health.
 *
 * A 503 means no backup destination is configured, which is a supported (if
 * regrettable) state rather than a failure. The page says so explicitly — an
 * empty list with no explanation reads as "backups are fine and there are none
 * yet", which is the opposite of the truth.
 */
export async function fetchBackups(signal?: AbortSignal): Promise<BackupsResponse | null> {
  const init: RequestInit = signal ? { signal } : {}
  const resp = await fetch('/v1/backups', init)
  if (resp.status === 503) return null
  if (!resp.ok) throw new Error(`backups: ${resp.status}`)
  return backupsResponseSchema.parse(await resp.json())
}

/** Take an on-demand archive. */
export async function createBackup(reason: string): Promise<void> {
  const resp = await fetch('/v1/backups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  })
  if (!resp.ok) throw new Error(await refusalText(resp, 'backup'))
}

/** Check an archive against its manifest. */
export async function verifyBackup(id: string): Promise<void> {
  const resp = await fetch(`/v1/backups/${enc(id)}/verify`)
  if (!resp.ok) throw new Error(await refusalText(resp, 'verify'))
}

export const stageRestoreResponseSchema = z.object({
  staged: z.boolean(),
  message: z.string().optional(),
  at: z.string().optional(),
})

export type StageRestoreResponse = z.infer<typeof stageRestoreResponseSchema>

/**
 * Stage a restore for the next daemon start (PRD §15.3).
 *
 * Staged, never performed in place: the API has no route that restores a
 * running node, by design. This writes the request; the daemon acts on it at
 * its next start, before anything opens the Store.
 */
export async function stageRestore(id: string, csrf?: string): Promise<StageRestoreResponse> {
  const resp = await apiFetch(`/v1/backups/restore`, {
    method: 'POST',
    body: { archive: id },
    ...(csrf ? { csrf } : {}),
  })
  return stageRestoreResponseSchema.parse(await resp.json())
}
