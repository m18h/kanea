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
