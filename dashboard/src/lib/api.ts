import { z } from 'zod'

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
  LetsEncrypt: z.boolean().optional(),
})

export const serviceSchema = z.object({
  Project: z.string(),
  Service: z.string(),
  Count: z.number(),
  Image: z.string(),
  Resources: resourcesSchema,
  Expose: exposeSchema.nullish(),
  DependsOn: z.array(z.string()).nullish(),
})

export const servicesResponseSchema = z.object({
  services: z.array(serviceSchema).nullish(),
})

export const allocSchema = z.object({
  ID: z.string(),
  Project: z.string(),
  Service: z.string(),
  Index: z.number(),
  State: z.string(),
  Image: z.string().optional(),
  Restarts: z.number().optional(),
  ExitCode: z.number().optional(),
})

export const allocsResponseSchema = z.object({
  allocs: z.array(allocSchema).nullish(),
})

export const logLineSchema = z.object({
  alloc_id: z.string(),
  line: z.string(),
})

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

export const statsSampleSchema = z.object({
  service: z.string(),
  at: z.string(),
  cpu: z.number().optional(),
  memory: z.number().optional(),
  rps: z.number().optional(),
  p95_latency_ms: z.number().optional(),
  allocs: z.array(allocStatsSchema).nullish(),
})

export type StatsSample = z.infer<typeof statsSampleSchema>
export type AllocStats = z.infer<typeof allocStatsSchema>

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
