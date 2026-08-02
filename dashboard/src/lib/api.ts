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

export const healthSchema = z.object({
  status: z.string(),
  version: z.string(),
  store_index: z.number(),
  ws_connections: z.number(),
})

export type Service = z.infer<typeof serviceSchema>
export type Alloc = z.infer<typeof allocSchema>
export type LogLine = z.infer<typeof logLineSchema>
export type Health = z.infer<typeof healthSchema>

/** Topics the live socket carries (PRD §12.1). */
export const Topic = {
  Services: 'services',
  Allocs: 'allocs',
  Logs: 'logs',
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
