import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import type { Plugin } from 'vite'
import { WebSocketServer, type WebSocket } from 'ws'
import {
  allocHistory,
  allocs,
  allocsPayload,
  currentIndex,
  events,
  findService,
  history,
  logLine,
  nodeSeriesNames,
  nodeStats,
  onChange,
  restartService,
  runLogFor,
  runsAt,
  scaleService,
  services,
  servicesPayload,
  serviceSeriesNames,
  serviceStats,
  uptimeSeconds,
} from './state'

/**
 * mockApi is a Vite plugin standing in for kanead: the REST routes the
 * dashboard reads, the /v1/ws live socket, and a fake shell on /v1/exec.
 * Enabled by MOCK_API=1 (npm run dev:mock / make dashboard-dev); the real
 * proxy to 127.0.0.1:8600 is switched off in its place.
 *
 * Auth is theatre by design: any non-empty user/password signs in as admin.
 * The value of the mock is layout, charts, streams and rollouts, not a
 * second implementation of §13.
 */
export function mockApi(): Plugin {
  return {
    name: 'kanea-mock-api',
    configureServer(server) {
      const wss = new WebSocketServer({ noServer: true })
      const execWss = new WebSocketServer({
        noServer: true,
        handleProtocols: (protocols) => (protocols.has('kanea.exec.v1') ? 'kanea.exec.v1' : false),
      })

      server.httpServer?.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
        const path = (req.url ?? '').split('?')[0]
        if (path === '/v1/ws') {
          wss.handleUpgrade(req, socket, head, (ws) => liveSocket(ws))
        } else if (path === '/v1/exec') {
          execWss.handleUpgrade(req, socket, head, (ws) => execShell(ws, req))
        }
      })

      server.middlewares.use((req, res, next) => {
        if (!req.url?.startsWith('/v1/')) return next()
        void route(req, res).catch((err: unknown) => {
          res.statusCode = 500
          res.end(JSON.stringify({ error: String(err) }))
        })
      })
    },
  }
}

// ---- REST ----

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(body))
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  const raw = Buffer.concat(chunks).toString()
  if (raw === '') return {}
  try {
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

const sessionUser = { name: 'mock-admin' }

function sessionBody() {
  return {
    subject: sessionUser.name,
    role: 'admin',
    via: 'session',
    csrf: 'mock-csrf-token',
    expires: new Date(Date.now() + 12 * 3600 * 1000).toISOString(),
  }
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://mock')
  const path = url.pathname
  const method = req.method ?? 'GET'

  // --- auth ---
  if (path === '/v1/auth/login' && method === 'POST') {
    const body = (await readBody(req)) as { user?: string; password?: string }
    if (!body.user || !body.password) {
      return json(res, 401, { error: 'mock: any non-empty user and password sign in' })
    }
    sessionUser.name = body.user
    res.setHeader('Set-Cookie', 'kanea_session=mock; Path=/; HttpOnly; SameSite=Lax')
    return json(res, 200, sessionBody())
  }
  if (path === '/v1/auth/session') {
    if (!req.headers.cookie?.includes('kanea_session=mock')) {
      return json(res, 401, { error: 'no session' })
    }
    return json(res, 200, sessionBody())
  }
  if (path === '/v1/auth/logout' && method === 'POST') {
    res.setHeader('Set-Cookie', 'kanea_session=; Path=/; Max-Age=0')
    return json(res, 200, {})
  }

  // --- health, stats, history ---
  if (path === '/v1/healthz') {
    return json(res, 200, {
      status: 'ok',
      version: 'v0.16.1-mock',
      store_index: currentIndex(),
      ws_connections: 1,
      oidc: { enabled: false },
      pid: 4242,
      started_at: new Date(Date.now() - uptimeSeconds() * 1000).toISOString(),
      uptime_seconds: uptimeSeconds(),
    })
  }
  if (path === '/v1/stats') {
    const project = url.searchParams.get('project')
    const service = url.searchParams.get('service')
    if (project && service) {
      const svc = findService(project, service)
      if (!svc) return json(res, 404, { error: 'no such service' })
      return json(res, 200, serviceStats(svc))
    }
    return json(res, 200, nodeStats())
  }
  if (path === '/v1/stats/history') {
    const project = url.searchParams.get('project')
    const service = url.searchParams.get('service')
    // The v1.79 selector, so the dev server exercises the same shapes the
    // daemon serves rather than only the default set.
    const named = (url.searchParams.get('series') ?? '').split(',').filter(Boolean)
    const wantAllocs = url.searchParams.get('allocs') === 'true'
    if (project && service) {
      const svc = findService(project, service)
      const body = history(`${project}/${service}`, named.length > 0 ? named : serviceSeriesNames)
      return json(res, 200, {
        ...body,
        ...(wantAllocs && svc ? { allocs: allocHistory(project, service) } : {}),
      })
    }
    return json(res, 200, history('node', named.length > 0 ? named : nodeSeriesNames))
  }

  // --- services and lifecycle ---
  if (path === '/v1/services' && method === 'GET') return json(res, 200, servicesPayload())
  if (path === '/v1/allocs') return json(res, 200, allocsPayload())

  const lifecycle = /^\/v1\/services\/([^/]+)\/([^/]+)\/(restart|scale)$/.exec(path)
  if (lifecycle && method === 'POST') {
    const [, project, service, verb] = lifecycle
    const svc = findService(project ?? '', service ?? '')
    if (!svc) return json(res, 404, { error: 'no such service' })
    if (verb === 'restart') {
      restartService(svc)
    } else {
      const body = (await readBody(req)) as { count?: number }
      scaleService(svc, Math.max(0, body.count ?? 1))
    }
    return json(res, 200, { applied: [`${svc.project}/${svc.service}`], index: currentIndex() })
  }

  // --- feeds and lists ---
  if (path === '/v1/events') {
    const project = url.searchParams.get('project')
    const limit = Number(url.searchParams.get('limit') ?? 100)
    const list = events.filter((e) => !project || e.project === project).slice(0, limit)
    return json(res, 200, { events: list, dropped: 0 })
  }
  if (path === '/v1/functions') {
    const fns = services.filter((s) => s.isFunction)
    return json(res, 200, {
      functions: fns.map((svc) => ({
        project: svc.project,
        service: svc.service,
        module: svc.image,
        count: svc.count,
        runtime: 'io.containerd.wasmtime.v1',
          memory_bytes: 64 * 1024 * 1024,
          http: true,
          domains: [],
          events: [{ on: ['deploy.failed', 'service.unhealthy'], path: '/kanea/event' }],
          crons: [{ schedule: '0 3 * * *', path: '/nightly' }],
        status: 'active',
        running: allocs.filter(
          (a) => a.project === svc.project && a.service === svc.service && a.state === 'running',
        ).length,
        healthy: 1,
        restarts: 0,
        invocations_per_minute: 3.2,
        invoker: { invocations: 1841, failures: 2, last_invoked: new Date().toISOString() },
      })),
      invoker_dropped: 0,
    })
  }
  if (path === '/v1/pipelines') {
    return json(res, 200, { runs: runsAt(Date.now()) })
  }
  const runPath = /^\/v1\/pipelines\/([^/]+)\/([^/]+)\/([^/]+)(\/logs)?$/.exec(path)
  if (runPath) {
    const run = runsAt(Date.now()).find((r) => r.id === runPath[3])
    if (!run) return json(res, 404, { error: 'no such run' })
    if (runPath[4]) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8')
      res.end(runLogFor(run))
      return
    }
    return json(res, 200, run)
  }
  if (path === '/v1/backups') {
    return json(res, 200, {
      backups: [
        {
          id: '2026-08-13T18-00-00Z-full',
          key_id: 'k1',
          created_at: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
          index: currentIndex() - 5,
          reason: 'interval',
          node: 'shop-node',
          version: 'v0.16.1',
          snapshot: { name: 'snapshot.bin.enc', size: 1_482_112, sha256: 'ab'.repeat(32) },
          counts: { services: services.length, allocs: allocs.length, secrets: 6, certs: 3, projects: 2 },
        },
      ],
      replication: {
        sink: 's3://kanea-backups/shop-node',
        shipped_to: currentIndex() - 1,
        last_segment_at: new Date(Date.now() - 42 * 1000).toISOString(),
        last_snapshot_at: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
        failures: 0,
      },
    })
  }
  if (path === '/v1/projects' && method === 'GET') {
    const names = [...new Set(services.map((s) => s.project))]
    return json(res, 200, {
      projects: names.map((name) => ({
        name,
        services: services.filter((s) => s.project === name).length,
        allocs: allocs.filter((a) => a.project === name).length,
        running: allocs.filter((a) => a.project === name && a.state === 'running').length,
        git:
          name === 'shop'
            ? {
                url: 'https://github.com/example/shop-deploy.git',
                branch: 'main',
                last_commit: 'f47c1e2',
                last_sync_at: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
              }
            : null,
        notifications: name === 'shop' ? ['telegram', 'slack'] : [],
      })),
    })
  }
  // A sync is fire-and-forget from the client's side: the daemon marks the
  // project and the sync loop re-reads the source.
  if (/^\/v1\/projects\/[^/]+\/sync$/.test(path) && method === 'POST') return json(res, 200, {})

  // The volume view (v1.69), derived: one resource per storage block, one
  // mount per volume that uses it. The fixture is chosen for the three states
  // the page has to keep apart: measured and inside its budget, measured and
  // over it, and never measured at all, which for s3 is permanent.
  if (path === '/v1/volumes') {
    return json(res, 200, {
      storages: [
        {
          project: 'shop',
          name: 'pgdata',
          type: 'local',
          mounts: [
            {
              project: 'shop',
              service: 'postgres',
              volume: 'pgdata[0]',
              mount_path: '/var/lib/postgresql/data',
              path: '/var/lib/kanea/volumes/shop/postgres/pgdata/0',
              used_bytes: 3_221_225_472,
              size_bytes: 10_737_418_240,
              state: 'ok',
            },
          ],
        },
        {
          project: 'shop',
          name: 'uploads',
          type: 'nfs',
          target: 'nas.lan:/export/uploads',
          mounts: [
            {
              project: 'shop',
              service: 'web',
              volume: 'uploads',
              mount_path: '/srv/uploads',
              path: '/var/lib/kanea/mounts/shop/uploads',
              used_bytes: 6_012_954_214,
              size_bytes: 5_368_709_120,
              state: 'over',
            },
            {
              project: 'shop',
              service: 'api',
              volume: 'uploads',
              mount_path: '/srv/uploads',
              read_only: true,
              path: '/var/lib/kanea/mounts/shop/uploads',
              used_bytes: 6_012_954_214,
              state: 'ok',
            },
          ],
        },
        {
          project: 'analytics',
          name: 'archive',
          type: 's3',
          target: 's3://analytics-archive',
          mounts: [
            {
              project: 'analytics',
              service: 'collector',
              volume: 'archive',
              mount_path: '/var/archive',
              path: '/var/lib/kanea/mounts/analytics/archive',
              // No reading, ever: an s3 volume is not walked (R31).
              state: 'unmeasured',
            },
          ],
        },
      ],
    })
  }

  const projectNotify = /^\/v1\/projects\/([^/]+)\/notifications$/.exec(path)
  if (projectNotify) {
    if (method === 'GET') {
      return json(res, 200, {
        project: projectNotify[1],
        notifications: {
          Telegram: { TokenRef: 'secret:shop/telegram-bot', ChatID: '-1001234567890' },
          Slack: { URLRef: 'secret:shop/slack-webhook' },
          On: ['deploy.failed', 'service.unhealthy', 'scale.*'],
          Severity: 'warning',
        },
        git_managed: projectNotify[1] === 'shop',
      })
    }
    return json(res, 200, {})
  }

  // --- settings surfaces ---
  if (path === '/v1/settings' && method === 'GET') return json(res, 200, settingsView())
  if (path.startsWith('/v1/settings/') && (method === 'PUT' || method === 'DELETE' || method === 'POST')) {
    if (path.endsWith('/test')) {
      return json(res, 200, [{ channel: 'webhook', ok: true }])
    }
    return json(res, 200, {})
  }
  if (path === '/v1/edge/policy') {
    return json(res, 200, {
      publish_enabled: true,
      publish_ports: '8000-9000',
      ranges: [{ from: 8000, to: 9000 }],
      reserved: [22, 53, 8600],
    })
  }
  if (path === '/v1/secrets/providers') return json(res, 404, { error: 'no providers configured' })
  if (path === '/v1/users' && method === 'GET') {
    return json(res, 200, {
      users: [
        { name: sessionUser.name, role: 'admin', created: '2026-06-01T10:00:00Z', updated: '2026-08-01T09:00:00Z' },
        { name: 'guest', role: 'viewer', created: '2026-07-10T18:00:00Z', updated: '2026-07-10T18:00:00Z' },
      ],
    })
  }
  if (path.startsWith('/v1/users/') || path.startsWith('/v1/tokens/')) return json(res, 200, {})
  if (path === '/v1/users' || path === '/v1/tokens') {
    if (method === 'POST' && path === '/v1/tokens') {
      return json(res, 200, { id: 'tok_new', token: 'kanea_mock_token_value', name: 'minted', role: 'viewer' })
    }
    return json(res, 200, {
      tokens: [
        {
          id: 'tok_ci',
          name: 'ci',
          role: 'admin',
          created: '2026-07-01T00:00:00Z',
          expires: '0001-01-01T00:00:00Z',
          last_used: new Date(Date.now() - 3600 * 1000).toISOString(),
        },
      ],
    })
  }
  if (path === '/v1/audit') {
    return json(res, 200, { entries: auditEntries(), more: false })
  }

  // --- spec editor ---
  if (path === '/v1/spec/render' && method === 'POST') {
    return json(res, 200, {
      valid: true,
      diagnostics: [],
      services: services.filter((s) => !s.isFunction).map((s) => ({
        Project: s.project,
        Service: s.service,
        Count: s.count,
        Image: s.image,
      })),
    })
  }
  if (path === '/v1/spec/apply' && method === 'POST') {
    return json(res, 200, { applied: services.map((s) => `${s.project}/${s.service}`), index: currentIndex() })
  }
  if (path === '/v1/spec/source') {
    return json(res, 200, {
      hcl: `# generated from the mock's desired state\nproject "shop" {\n  service "web" {\n    count = 3\n    task { image = "registry.example.com/shop/web:f47c1e2" }\n  }\n}\n`,
      generated: true,
    })
  }

  json(res, 404, { error: `mock: no handler for ${method} ${path}` })
}

// ---- the live socket ----

function liveSocket(ws: WebSocket): void {
  const subs = new Map<
    string,
    {
      topic: string
      project?: string
      service?: string
      history?: boolean
      series?: string[]
      allocs?: boolean
      seeded?: boolean
    }
  >()

  const send = (key: string, topic: string, data: unknown) => {
    if (ws.readyState !== ws.OPEN) return
    ws.send(JSON.stringify({ type: 'data', topic, key, data }))
  }

  const snapshot = (key: string) => {
    const sub = subs.get(key)
    if (!sub) return
    if (sub.topic === 'services') send(key, 'services', servicesPayload())
    if (sub.topic === 'allocs') send(key, 'allocs', allocsPayload())
    // The seed rides the first frame and no frame after it, exactly as the
    // daemon does, so dev exercises the contract rather than a friendlier
    // version of it.
    type Seeded = { history?: ReturnType<typeof history> & { allocs?: Record<string, unknown> } }
    const seed = (names: string[], subject: string, allocsOf?: [string, string]): Seeded => {
      if (!sub.history || sub.seeded) return {}
      sub.seeded = true
      const body = history(subject, sub.series ?? names)
      return {
        history: allocsOf ? { ...body, allocs: allocHistory(allocsOf[0], allocsOf[1]) } : body,
      }
    }
    if (sub.topic === 'node') {
      send(key, 'node', { ...nodeStats(), ...seed(nodeSeriesNames, 'node') })
    }
    if (sub.topic === 'stats' && sub.project && sub.service) {
      const svc = findService(sub.project, sub.service)
      if (svc) {
        send(key, 'stats', {
          ...serviceStats(svc),
          ...seed(
            serviceSeriesNames,
            `${sub.project}/${sub.service}`,
            sub.allocs ? [sub.project, sub.service] : undefined,
          ),
        })
      }
    }
  }

  ws.on('message', (raw: Buffer) => {
    let frame: {
      type?: string
      topic?: string
      project?: string
      service?: string
      tail?: number
      history?: boolean
      history_series?: string[]
      history_allocs?: boolean
    }
    try {
      frame = JSON.parse(raw.toString()) as typeof frame
    } catch {
      return
    }
    if (frame.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', topic: 'ping' }))
      return
    }
    const scoped = frame.project || frame.service
    const key = scoped ? `${frame.topic}:${frame.project ?? ''}/${frame.service ?? ''}` : (frame.topic ?? '')
    if (frame.type === 'subscribe' && frame.topic) {
      const sub: {
        topic: string
        project?: string
        service?: string
        history?: boolean
        series?: string[]
        allocs?: boolean
        seeded?: boolean
      } = { topic: frame.topic }
      if (frame.history) sub.history = true
      if (frame.history_series) sub.series = frame.history_series
      if (frame.history_allocs) sub.allocs = true
      if (frame.project) sub.project = frame.project
      if (frame.service) sub.service = frame.service
      subs.set(key, sub)
      snapshot(key)
    }
    if (frame.type === 'unsubscribe') subs.delete(key)
  })

  // Store changes push services + allocs immediately (the rollout heartbeat).
  const offChange = onChange(() => {
    for (const key of subs.keys()) snapshot(key)
  })

  // Stats tick every 2s; logs stream at a chatty-but-readable clip.
  const statsTimer = setInterval(() => {
    for (const [key, sub] of subs) {
      if (sub.topic === 'stats' || sub.topic === 'node') snapshot(key)
    }
  }, 2000)
  const logTimer = setInterval(() => {
    for (const [key, sub] of subs) {
      if (sub.topic !== 'logs' || !sub.project || !sub.service) continue
      const svc = findService(sub.project, sub.service)
      if (!svc) continue
      // A batch per tick, like the daemon (PRD v1.70): one frame per line is
      // what overran its send buffer. Two lines a tick keeps the mock chatty
      // enough to read while exercising the batched shape.
      const lines = [logLine(svc), logLine(svc)].filter((l) => l !== null)
      if (lines.length > 0) send(key, 'logs', { lines })
    }
  }, 450)

  ws.on('close', () => {
    offChange()
    clearInterval(statsTimer)
    clearInterval(logTimer)
  })
}

// ---- the fake shell ----

function execShell(ws: WebSocket, req: IncomingMessage): void {
  const url = new URL(req.url ?? '/', 'http://mock')
  const alloc = url.searchParams.get('alloc') ?? 'alloc'
  // Refuse like the daemon would when the CSRF entry is missing: the mock
  // negotiated kanea.exec.v1 already (handleProtocols), so just check the
  // token entry exists.
  const protocols = req.headers['sec-websocket-protocol'] ?? ''
  if (!protocols.includes('kanea-csrf.')) {
    ws.close(1008, 'missing CSRF token')
    return
  }

  const stdout = (text: string) => {
    const body = Buffer.from(text)
    ws.send(Buffer.concat([Buffer.from([1]), body]))
  }
  const prompt = () => stdout(`\x1b[36m${alloc}\x1b[0m:/$ `)

  stdout(`mock shell: this is the dashboard's mock daemon, not a container\r\n`)
  prompt()

  let line = ''
  ws.on('message', (raw: Buffer, isBinary: boolean) => {
    if (!isBinary) {
      // Control frames: resize is ignored, eof ends the session.
      try {
        const frame = JSON.parse(raw.toString()) as { type?: string }
        if (frame.type === 'eof') {
          ws.send(JSON.stringify({ type: 'exit', code: 0 }))
          ws.close()
        }
      } catch {
        /* ignore */
      }
      return
    }
    for (const ch of raw.toString()) {
      if (ch === '\r') {
        stdout('\r\n')
        const cmd = line.trim()
        line = ''
        if (cmd === 'exit') {
          ws.send(JSON.stringify({ type: 'exit', code: 0 }))
          ws.close()
          return
        }
        if (cmd === 'ls') stdout('bin  etc  media  proc  srv  tmp\r\n')
        else if (cmd !== '') stdout(`mock: ${cmd}: try ls or exit\r\n`)
        prompt()
      } else if (ch === '\x7f') {
        if (line.length > 0) {
          line = line.slice(0, -1)
          stdout('\b \b')
        }
      } else if (ch === '\x03') {
        line = ''
        stdout('^C\r\n')
        prompt()
      } else {
        line += ch
        stdout(ch) // a TTY echoes
      }
    }
  })
}

// ---- fixtures ----

function settingsView() {
  return {
    node: {
      listen: '0.0.0.0:8600',
      tls: true,
      base_domain: 'example.com',
      network_mode: 'ebpf (mock)',
      node_cidr: '10.100.1.0/24',
      cluster_cidr: '10.100.0.0/16',
      service_cidr: '10.96.0.0/16',
      data_dir: '/var/lib/kanea',
      log_dir: '/var/log/kanea',
      publish_ports: '8000-9000',
      tls_default: 'acme',
    },
    backup: {
      source: 'store',
      settings: {
        s3: {
          url: 's3://kanea-backups/shop-node',
          endpoint: 'https://s3.lab.example',
          region: 'us-east-1',
          access_key: 'MOCKKEY',
          secret_key_ref: 'secret:shared/backup-s3',
          path_style: true,
        },
        snapshot_interval: '6h0m0s',
        retention: 10,
      },
      status: {
        sink: 's3://kanea-backups/shop-node',
        shipped_to: currentIndex() - 1,
        last_segment_at: new Date(Date.now() - 42 * 1000).toISOString(),
        last_snapshot_at: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
        failures: 0,
      },
    },
    notifications: {
      source: 'store',
      settings: {
        channels: {
          Webhook: { URL: 'https://hooks.lab.example/kanea', SecretRef: 'secret:shared/hook' },
          On: ['deploy.*', '*.failed'],
          Severity: 'warning',
        },
      },
    },
  }
}

function auditEntries() {
  const now = Date.now()
  const actions = [
    { action: 'service.restart', target: 'shop/web', result: 'ok', status: 200 },
    { action: 'service.apply', target: 'shop/api', result: 'ok', status: 200 },
    { action: 'auth.login', target: '', result: 'ok', status: 200 },
    { action: 'auth.login', target: '', result: 'denied', status: 401, actor: 'mallory' },
    { action: 'alloc.exec', target: 'shop/shop-postgres-0', result: 'ok', status: 200 },
  ]
  return actions.map((a, i) => ({
    id: `01AUDIT${i}`,
    time: new Date(now - (i + 1) * 47 * 60 * 1000).toISOString(),
    actor: a.actor ?? sessionUser.name,
    role: a.actor ? undefined : 'admin',
    via: 'session',
    action: a.action,
    target: a.target || undefined,
    result: a.result,
    status: a.status,
    source: '192.168.1.23',
  }))
}
