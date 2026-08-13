/**
 * The mock daemon's state and simulation: a small homelab that behaves —
 * services with allocs, wandering metrics, chatty logs, and rollouts that
 * actually roll when you press Restart. Shapes match src/lib's zod schemas;
 * a field the schemas would reject is a bug here, not there.
 */

interface MockService {
  project: string
  service: string
  count: number
  image: string
  generation: number
  scaling?: { min: number; max: number; metrics: { name: string; target: number }[] }
  expose?: { domains: string[]; port: number; tlsMode: string }
  isFunction?: boolean
}

export interface MockAlloc {
  id: string
  project: string
  service: string
  index: number
  state: string
  image: string
  restarts: number
  healthy: boolean
  spec_hash: string
  created_at: string
}

const startedAt = Date.now()
let storeIndex = 40

export function bumpIndex(): number {
  storeIndex += 1
  return storeIndex
}

export function currentIndex(): number {
  return storeIndex
}

export const services: MockService[] = [
  {
    project: 'media',
    service: 'jellyfin',
    count: 2,
    image: 'jellyfin/jellyfin:10.9.11',
    generation: 3,
    expose: { domains: ['tv.lab.example'], port: 8096, tlsMode: 'acme' },
    scaling: { min: 1, max: 4, metrics: [{ name: 'cpu', target: 70 }] },
  },
  {
    project: 'media',
    service: 'sonarr',
    count: 1,
    image: 'linuxserver/sonarr:4.0.10',
    generation: 1,
    expose: { domains: ['sonarr.lab.example'], port: 8989, tlsMode: 'acme' },
  },
  {
    project: 'blog',
    service: 'site',
    count: 1,
    image: 'ghcr.io/m18h/blog:2026-08-01',
    generation: 5,
    expose: { domains: ['blog.example.dev'], port: 80, tlsMode: 'acme' },
  },
  {
    project: 'media',
    service: 'thumbnailer',
    count: 1,
    image: 'registry.lab.example/thumbnailer:sha-90ffaa1',
    generation: 1,
    isFunction: true,
  },
]

export function specHash(svc: MockService): string {
  return `sha256:mock-${svc.service}-g${svc.generation}`
}

export const allocs: MockAlloc[] = []
for (const svc of services) {
  for (let i = 0; i < svc.count; i++) {
    allocs.push({
      id: `${svc.project}-${svc.service}-${i}`,
      project: svc.project,
      service: svc.service,
      index: i,
      state: 'running',
      image: svc.image,
      restarts: svc.service === 'sonarr' ? 2 : 0,
      healthy: true,
      spec_hash: specHash(svc),
      created_at: new Date(startedAt - (36 + i) * 3600 * 1000).toISOString(),
    })
  }
}

export function findService(project: string, service: string): MockService | undefined {
  return services.find((s) => s.project === project && s.service === service)
}

/** desiredJSON serializes one service the way GET /v1/services does. */
export function desiredJSON(svc: MockService) {
  return {
    Project: svc.project,
    Service: svc.service,
    Count: svc.count,
    Image: svc.image,
    Resources: svc.isFunction
      ? { CPUMillis: 500, MemoryBytes: 128 * 1024 * 1024 }
      : { CPUMillis: 0, MemoryBytes: 0 },
    Expose: svc.expose
      ? { Domains: svc.expose.domains, Port: svc.expose.port, TLSMode: svc.expose.tlsMode }
      : null,
    Scaling: svc.scaling ?? null,
    ...(svc.isFunction ? { runtime: 'wasm', function: { module: svc.image } } : {}),
    spec_hash: specHash(svc),
  }
}

export function servicesPayload() {
  return { services: services.map(desiredJSON) }
}

export function allocsPayload() {
  return { allocs: allocs.map((a) => ({ ...a })) }
}

// ---- events ----

export interface MockEvent {
  id: string
  name: string
  severity: 'info' | 'warning' | 'error'
  project?: string
  service?: string
  message: string
  at: string
}

let eventSeq = 100
export const events: MockEvent[] = []

export function pushEvent(e: Omit<MockEvent, 'id' | 'at'>): void {
  eventSeq += 1
  events.unshift({ ...e, id: `evt-${eventSeq}`, at: new Date().toISOString() })
  if (events.length > 200) events.pop()
}

pushEvent({ name: 'deploy.finished', severity: 'info', project: 'blog', service: 'site', message: 'blog/site rolled to generation 5' })
pushEvent({ name: 'scale.up', severity: 'info', project: 'media', service: 'jellyfin', message: 'jellyfin 1 → 2 (cpu 82% over target 70%)' })
pushEvent({ name: 'alloc.restarted', severity: 'warning', project: 'media', service: 'sonarr', message: 'media-sonarr-0 exited 137, restarted (2 in 24h)' })

// ---- metrics ----

/** A wandering value inside [min, max]: two sines and a whisper of noise —
 * time-coherent, because a real scrape does not teleport between samples. */
function wander(base: number, spread: number, min: number, max: number, phase: number): number {
  const t = Date.now() / 1000
  const v =
    base +
    Math.sin(t / 97 + phase) * spread +
    Math.sin(t / 17 + phase * 3) * spread * 0.3 +
    (Math.random() - 0.5) * spread * 0.1
  return Math.min(max, Math.max(min, v))
}

export function serviceStats(svc: MockService) {
  const mine = allocs.filter(
    (a) => a.project === svc.project && a.service === svc.service && a.state === 'running',
  )
  const cpu = wander(svc.service === 'jellyfin' ? 42 : 12, 14, 1, 98, svc.service.length)
  const memory = wander(svc.service === 'jellyfin' ? 55 : 30, 6, 5, 95, svc.service.length * 2)
  return {
    service: `${svc.project}/${svc.service}`,
    at: new Date().toISOString(),
    cpu,
    memory,
    rps: svc.expose ? wander(svc.service === 'site' ? 24 : 6, 5, 0, 200, 1) : undefined,
    p95_latency_ms: svc.expose ? wander(85, 30, 4, 900, 2) : undefined,
    allocs: mine.map((a) => ({
      alloc_id: a.id,
      cpu: Math.max(0.5, cpu + (Math.random() - 0.5) * 8),
      memory: Math.max(1, memory + (Math.random() - 0.5) * 6),
      memory_bytes: Math.round((memory / 100) * 512 * 1024 * 1024),
    })),
    edge: svc.expose
      ? {
          codes: { '200': 48211 + Math.round((Date.now() - startedAt) / 500), '404': 92, '502': 3 },
          request_bytes: 1_284_211_000,
          response_bytes: 9_412_338_000,
        }
      : undefined,
  }
}

export function nodeStats() {
  const running = allocs.filter((a) => a.state === 'running').length
  return {
    version: 'v0.16.1-mock',
    projects: new Set(services.map((s) => s.project)).size,
    services: services.length,
    allocs: allocs.length,
    running,
    unhealthy: allocs.filter((a) => !a.healthy).length,
    failed: allocs.filter((a) => a.state === 'failed').length,
    metrics: { series: 640, dropped: 0 },
    breaker_open: false,
    events_dropped: 0,
    node: {
      cpu_percent: wander(34, 18, 2, 97, 0),
      load1: wander(1.4, 0.8, 0.05, 16, 3),
      load5: wander(1.2, 0.5, 0.05, 16, 4),
      load15: wander(1.1, 0.3, 0.05, 16, 5),
      memory_total_bytes: 16 * 1024 * 1024 * 1024,
      memory_available_bytes: Math.round(wander(7, 2, 2, 12, 6) * 1024 * 1024 * 1024),
      memory_percent: wander(56, 8, 10, 95, 7),
      cores: 8,
      at: new Date().toISOString(),
    },
    at: new Date().toISOString(),
  }
}

/** history builds 15 minutes of 5s points ending now, with one honest gap. */
export function history(subject: string, seriesNames: string[]) {
  const interval = 5
  const points = 180
  const now = Math.floor(Date.now() / 1000 / interval) * interval
  const series: Record<string, { at: string; value: number }[]> = {}
  for (const [idx, name] of seriesNames.entries()) {
    const out: { at: string; value: number }[] = []
    for (let i = points; i > 0; i--) {
      if (i < 66 && i > 60) continue // a scrape gap, drawn as a hole
      const t = now - i * interval
      const base = name === 'memory' ? 55 : name === 'rps' ? 20 : name === 'p95_latency_ms' ? 90 : 35
      const spread = name === 'p95_latency_ms' ? 35 : 12
      const value = Math.max(
        0.2,
        base + Math.sin(t / 97 + idx) * spread + (((t * 2654435761) % 100) / 100 - 0.5) * spread * 0.5,
      )
      out.push({ at: new Date(t * 1000).toISOString(), value })
    }
    series[name] = out
  }
  return {
    subject,
    from: new Date((now - points * interval) * 1000).toISOString(),
    to: new Date(now * 1000).toISOString(),
    interval_seconds: interval,
    series,
  }
}

// ---- logs ----

const logSamples = [
  'GET /library/sections 200 12ms',
  'transcode session started (h264 -> hevc, 1080p)',
  'scan: 4 items updated in Movies',
  'GET /health 200 1ms',
  'db checkpoint completed in 84ms',
  'WARN slow query: 412ms SELECT * FROM history',
  'rss sync: 12 feeds, 3 new episodes queued',
  'ERROR upstream indexer timeout after 30s, will retry',
  'cache hit ratio 0.94 over last 5m',
  'session ended for user living-room',
]

export function logLine(svc: MockService): { alloc_id: string; line: string } | null {
  const mine = allocs.filter(
    (a) => a.project === svc.project && a.service === svc.service && a.state === 'running',
  )
  const alloc = mine[Math.floor(Math.random() * mine.length)]
  if (!alloc) return null
  const line = logSamples[Math.floor(Math.random() * logSamples.length)] ?? 'tick'
  return { alloc_id: alloc.id, line: `${new Date().toISOString().slice(11, 19)} ${line}` }
}

// ---- rollouts ----

export type ChangeListener = () => void
const changeListeners = new Set<ChangeListener>()

export function onChange(fn: ChangeListener): () => void {
  changeListeners.add(fn)
  return () => changeListeners.delete(fn)
}

function changed(): void {
  bumpIndex()
  for (const fn of changeListeners) fn()
}

/**
 * restart bumps the generation and rolls allocs one at a time, exactly the
 * shape the reconciler produces: each replica goes stale → torn down → a
 * pending replacement at the new hash → running, staggered so the rollout
 * line on the detail page visibly counts up.
 */
export function restartService(svc: MockService): void {
  svc.generation += 1
  const hash = specHash(svc)
  pushEvent({
    name: 'deploy.started',
    severity: 'info',
    project: svc.project,
    service: svc.service,
    message: `${svc.project}/${svc.service} restart: generation ${svc.generation}`,
  })
  changed()

  const mine = allocs.filter((a) => a.project === svc.project && a.service === svc.service)
  mine.forEach((alloc, i) => {
    setTimeout(() => {
      alloc.state = 'pending'
      alloc.spec_hash = hash
      alloc.created_at = new Date().toISOString()
      changed()
      setTimeout(() => {
        alloc.state = 'running'
        alloc.healthy = true
        changed()
        if (i === mine.length - 1) {
          pushEvent({
            name: 'deploy.finished',
            severity: 'info',
            project: svc.project,
            service: svc.service,
            message: `${svc.project}/${svc.service} converged at generation ${svc.generation}`,
          })
          changed()
        }
      }, 2500)
    }, 1500 + i * 4000)
  })
}

/** scale converges the alloc set to the new count through pending states. */
export function scaleService(svc: MockService, count: number): void {
  const previous = svc.count
  svc.count = count
  pushEvent({
    name: count === 0 ? 'service.stopped' : 'scale.set',
    severity: 'info',
    project: svc.project,
    service: svc.service,
    message: `${svc.project}/${svc.service} scaled ${previous} → ${count}`,
  })
  changed()

  const mine = () => allocs.filter((a) => a.project === svc.project && a.service === svc.service)
  // Down: drop from the top, after a beat.
  for (const alloc of mine().filter((a) => a.index >= count)) {
    setTimeout(() => {
      const at = allocs.indexOf(alloc)
      if (at >= 0) allocs.splice(at, 1)
      changed()
    }, 1200)
  }
  // Up: pending first, running shortly after.
  for (let i = mine().length; i < count; i++) {
    const alloc: MockAlloc = {
      id: `${svc.project}-${svc.service}-${i}`,
      project: svc.project,
      service: svc.service,
      index: i,
      state: 'pending',
      image: svc.image,
      restarts: 0,
      healthy: false,
      spec_hash: specHash(svc),
      created_at: new Date().toISOString(),
    }
    allocs.push(alloc)
    changed()
    setTimeout(() => {
      alloc.state = 'running'
      alloc.healthy = true
      changed()
    }, 2000 + i * 800)
  }
}

export function uptimeSeconds(): number {
  return Math.floor((Date.now() - startedAt) / 1000)
}
