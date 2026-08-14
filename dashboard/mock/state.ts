/**
 * The mock daemon's state and simulation: the PRD §6.1 sample — the shop
 * e-commerce stack — behaving: services with allocs, wandering metrics,
 * chatty logs, and rollouts that actually roll when you press Restart.
 * Shapes match src/lib's zod schemas; a field the schemas would reject is
 * a bug here, not there.
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
    project: 'shop',
    service: 'web',
    count: 3,
    image: 'registry.example.com/shop/web:f47c1e2',
    generation: 5,
    expose: { domains: ['shop.example.com', 'www.shop.example.com'], port: 3000, tlsMode: 'acme' },
    scaling: {
      min: 2,
      max: 10,
      metrics: [
        { name: 'cpu', target: 70 },
        { name: 'rps', target: 500 },
        { name: 'p95_latency_ms', target: 800 },
      ],
    },
  },
  {
    project: 'shop',
    service: 'api',
    count: 2,
    image: 'registry.example.com/shop/api:0.9.1',
    generation: 2,
  },
  {
    project: 'shop',
    service: 'postgres',
    count: 1,
    image: 'postgres:17',
    generation: 1,
  },
  {
    project: 'shop',
    service: 'assets',
    count: 1,
    image: 'nginx:1.27-alpine',
    generation: 1,
    expose: { domains: ['assets.shop.example.com'], port: 80, tlsMode: 'acme' },
  },
  {
    project: 'shop',
    service: 'resize-avatar',
    count: 1,
    image: 'registry.example.com/shop/resize-avatar:v3',
    generation: 3,
    isFunction: true,
  },
  {
    project: 'analytics',
    service: 'collector',
    count: 1,
    image: 'registry.example.com/analytics/collector:1.4.0',
    generation: 1,
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
      restarts: svc.service === 'api' ? 2 : 0,
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
      ? { CPUMillis: 100, MemoryBytes: 64 * 1024 * 1024 }
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

pushEvent({ name: 'deploy.finished', severity: 'info', project: 'shop', service: 'web', message: 'shop/web rolled to generation 5 (f47c1e2)' })
pushEvent({ name: 'scale.up', severity: 'info', project: 'shop', service: 'web', message: 'web 2 → 3 (rps 612 over target 500)' })
pushEvent({ name: 'alloc.restarted', severity: 'warning', project: 'shop', service: 'api', message: 'shop-api-1 exited 137, restarted (2 in 24h)' })

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

/** Per-service baselines: the storefront is busy, the database is steady. */
const statBase: Record<string, { cpu: number; memory: number; rps?: number }> = {
  web: { cpu: 46, memory: 52, rps: 380 },
  api: { cpu: 31, memory: 44 },
  postgres: { cpu: 18, memory: 71 },
  assets: { cpu: 7, memory: 16, rps: 90 },
  'resize-avatar': { cpu: 9, memory: 22 },
  collector: { cpu: 24, memory: 38 },
}

export function serviceStats(svc: MockService) {
  const mine = allocs.filter(
    (a) => a.project === svc.project && a.service === svc.service && a.state === 'running',
  )
  const base = statBase[svc.service] ?? { cpu: 12, memory: 30 }
  const cpu = wander(base.cpu, 14, 1, 98, svc.service.length)
  const memory = wander(base.memory, 6, 5, 95, svc.service.length * 2)
  return {
    service: `${svc.project}/${svc.service}`,
    at: new Date().toISOString(),
    cpu,
    memory,
    rps: base.rps !== undefined ? wander(base.rps, base.rps * 0.15, 0, 2000, 1) : undefined,
    p95_latency_ms: svc.expose ? wander(svc.service === 'web' ? 140 : 45, 30, 4, 900, 2) : undefined,
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

const logSamples: Record<string, string[]> = {
  web: [
    'GET /products 200 18ms',
    'GET /cart 200 6ms',
    'POST /checkout 201 84ms',
    'render /products/[slug] in 42ms (cache miss)',
    'GET /healthz 200 1ms',
    'session hydrated for 3 items',
    'WARN upstream api slow: 612ms GET /inventory',
  ],
  api: [
    'GET /v1/inventory 200 9ms',
    'POST /v1/orders 201 33ms',
    'db pool: 14/50 connections in use',
    'GET /healthz 200 1ms',
    'WARN slow query: 412ms SELECT * FROM orders WHERE status=$1',
    'ERROR payment provider timeout after 10s, retrying',
    'cache hit ratio 0.94 over last 5m',
  ],
  postgres: [
    'checkpoint complete: wrote 214 buffers in 1.2s',
    'automatic vacuum of table "orders"',
    'connection authorized: user=shop database=shop',
    'LOG: duration: 402.118 ms  statement: SELECT ...',
  ],
  assets: [
    'GET /media/catalog/hero-1.webp 200 0.002',
    'GET /media/avatars/u1042.png 200 0.001',
    'GET /media/missing.jpg 404 0.000',
    's3 read: 1.2 MiB in 38ms',
  ],
  'resize-avatar': [
    'POST /resize 200 14ms (256x256, webp)',
    'POST /resize 200 9ms (64x64, webp)',
    'GET /healthz 200 0ms',
    'rejected: source larger than 8 MiB',
  ],
  collector: [
    'ingested 1 204 events in 250ms',
    'flush: 5 000 rows to warehouse',
    'GET /healthz 200 1ms',
  ],
}

export function logLine(svc: MockService): { alloc_id: string; line: string } | null {
  const mine = allocs.filter(
    (a) => a.project === svc.project && a.service === svc.service && a.state === 'running',
  )
  const alloc = mine[Math.floor(Math.random() * mine.length)]
  if (!alloc) return null
  const samples = logSamples[svc.service] ?? ['tick']
  const line = samples[Math.floor(Math.random() * samples.length)] ?? 'tick'
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

// ---- pipelines ----

/**
 * One build slot, serialised (§10.2): the shop/web pipeline runs back to
 * back, a 168 s cycle — sync 6 s, build 144 s, deploy 18 s. A second push
 * mid-build becomes a queued run that takes the slot the moment it frees
 * (same run id and commit: the queued run IS the next running one). All of
 * it is derived from the wall clock, so a reload lands mid-build and the
 * sidebar badge, the Builds tile and the duration column keep moving.
 */
const CYCLE_S = 168
const SYNC_S = 6
const BUILD_S = 150
const QUEUE_AT_S = 105

function fakeHex(n: number, len: number): string {
  let out = ''
  let x = (Math.imul(n + 7, 0x9e3779b1) ^ 0x5bd1e995) >>> 0
  while (out.length < len) {
    x = (Math.imul(x ^ (x >>> 15), 0x85ebca6b) ^ 0xc2b2ae35) >>> 0
    out += x.toString(16).padStart(8, '0')
  }
  return out.slice(0, len)
}

const commitFor = (cycle: number): string => fakeHex(cycle, 40)
const runIdFor = (cycle: number): string =>
  `01J9MOCKRUN${String(((cycle % 100000) + 100000) % 100000).padStart(5, '0')}`

export interface MockRun {
  id: string
  project: string
  service: string
  state: string
  trigger: string
  triggered_by?: string
  commit?: string
  ref?: string
  image?: string
  digest?: string
  steps?: { name: string; state: string; started_at: string; finished_at?: string; error?: string }[]
  started_at: string
  finished_at?: string
  error?: string
}

function runForCycle(k: number, nowMs: number): MockRun {
  const startMs = k * CYCLE_S * 1000
  const t = (nowMs - startMs) / 1000
  const commit = commitFor(k)
  const short = commit.slice(0, 7)
  const at = (s: number) => new Date(startMs + s * 1000).toISOString()
  const syncDone = t >= SYNC_S
  const buildDone = t >= BUILD_S
  const deployDone = t >= CYCLE_S

  const run: MockRun = {
    id: runIdFor(k),
    project: 'shop',
    service: 'web',
    state: deployDone ? 'succeeded' : 'running',
    trigger: 'webhook',
    triggered_by: `git push (${short})`,
    commit,
    ref: 'refs/heads/main',
    steps: [
      {
        name: 'sync',
        state: syncDone ? 'succeeded' : 'running',
        started_at: at(0),
        ...(syncDone ? { finished_at: at(SYNC_S) } : {}),
      },
      {
        name: 'build',
        state: buildDone ? 'succeeded' : syncDone ? 'running' : 'pending',
        started_at: at(syncDone ? SYNC_S : 0),
        ...(buildDone ? { finished_at: at(BUILD_S) } : {}),
      },
      {
        name: 'deploy',
        state: deployDone ? 'succeeded' : buildDone ? 'running' : 'pending',
        started_at: at(buildDone ? BUILD_S : 0),
        ...(deployDone ? { finished_at: at(CYCLE_S) } : {}),
      },
    ],
    started_at: at(0),
  }
  if (deployDone) {
    run.image = `registry.example.com/shop/web:${short}`
    run.digest = `sha256:${fakeHex(k + 99, 64)}`
    run.finished_at = at(CYCLE_S)
  }
  return run
}

/** The second push of a cycle waits for the slot; it starts next cycle. */
function queuedRun(k: number): MockRun {
  const startMs = k * CYCLE_S * 1000
  const commit = commitFor(k + 1)
  return {
    id: runIdFor(k + 1),
    project: 'shop',
    service: 'web',
    state: 'queued',
    trigger: 'webhook',
    triggered_by: `git push (${commit.slice(0, 7)})`,
    commit,
    ref: 'refs/heads/main',
    started_at: new Date(startMs + QUEUE_AT_S * 1000).toISOString(),
  }
}

/** One honest failure in the history, old enough to be outside the 24 h
 * alert window: a build step that blew up on a missing package. */
function failedRun(): MockRun {
  const startMs = Date.now() - 26 * 3600 * 1000
  const at = (s: number) => new Date(startMs + s * 1000).toISOString()
  const commit = commitFor(0xf00d)
  return {
    id: runIdFor(0xf00d),
    project: 'shop',
    service: 'web',
    state: 'failed',
    trigger: 'webhook',
    triggered_by: `git push (${commit.slice(0, 7)})`,
    commit,
    ref: 'refs/heads/main',
    error: 'build: executor failed: exit code 1',
    steps: [
      { name: 'sync', state: 'succeeded', started_at: at(0), finished_at: at(5) },
      {
        name: 'build',
        state: 'failed',
        started_at: at(5),
        finished_at: at(41),
        error: 'executor failed: exit code 1',
      },
    ],
    started_at: at(0),
    finished_at: at(41),
  }
}

export function runsAt(nowMs: number): MockRun[] {
  const k = Math.floor(nowMs / 1000 / CYCLE_S)
  const t = nowMs / 1000 - k * CYCLE_S
  const list: MockRun[] = [runForCycle(k, nowMs)]
  if (t >= QUEUE_AT_S) list.push(queuedRun(k))
  for (let i = 1; i <= 6; i++) list.push(runForCycle(k - i, nowMs))
  list.push(failedRun())
  return list.sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at))
}

const buildLines = [
  '#2 building with buildkit',
  '#2 [internal] load metadata for docker.io/library/node:22-alpine',
  '#2 [1/6] FROM node:22-alpine',
  '#2 [2/6] COPY package.json package-lock.json ./',
  '#2 [3/6] RUN npm ci',
  '#2 [4/6] COPY . .',
  '#2 [5/6] RUN npm run build',
  '#2 [6/6] RUN npm prune --omit=dev',
]

/** runLogFor renders the build log as far as the run has got. */
export function runLogFor(run: MockRun): string {
  if (run.state === 'queued') return ''
  if (run.state === 'failed') {
    return [
      '#1 resolving git ref main',
      `#1 locked ${(run.commit ?? '').slice(0, 12)} (0.2s)`,
      '#2 building with buildkit',
      '#2 [internal] load metadata for docker.io/library/node:22-alpine',
      '#2 [3/6] RUN npm ci',
      '#2 ERROR: executor failed: exit code 1',
      'npm error code E404: Not Found - GET https://registry.npmjs.org/@shop/checkout-ui',
      'error: build failed',
    ].join('\n')
  }

  const startMs = Date.parse(run.started_at)
  const t = run.state === 'succeeded' ? CYCLE_S : (Date.now() - startMs) / 1000
  const short = (run.commit ?? '').slice(0, 7)
  const lines = ['#1 resolving git ref main', `#1 locked ${(run.commit ?? '').slice(0, 12)} (0.2s)`]
  if (t >= SYNC_S) {
    const shown =
      run.state === 'succeeded'
        ? buildLines.length
        : Math.min(buildLines.length, 1 + Math.floor((t - SYNC_S) / 16))
    lines.push(...buildLines.slice(0, shown))
  }
  if (t >= BUILD_S) {
    lines.push(
      `#2 done: ${BUILD_S - SYNC_S}.1s`,
      '#3 exporting image',
      `#3 pushing manifest for registry.example.com/shop/web:${short}`,
    )
  }
  if (run.state === 'succeeded') {
    lines.push('#3 done: 12.1s', `done: ${(run.digest ?? '').slice(7, 19)}…`)
  }
  return lines.join('\n')
}
