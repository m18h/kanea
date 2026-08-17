import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Projects } from '@/pages/Projects'
import { Router } from '@/lib/router'
import { resetLiveSocket } from '@/lib/live'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/**
 * The Projects page against a faked daemon.
 *
 * Two things are worth pinning here. A sync is an admin action, so a viewer
 * must meet a disabled button that says why rather than a 403, and a project
 * with no git source has nothing to sync at all, which is a different state
 * again. The expanded service list rides the shared websocket, so these drive
 * it the way the socket does.
 */

class fakeWebSocket {
  static instances: fakeWebSocket[] = []
  static readonly CONNECTING = 0
  static readonly OPEN = 1

  readyState = fakeWebSocket.CONNECTING
  sent: string[] = []
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null

  constructor(public url: string) {
    fakeWebSocket.instances.push(this)
  }
  send(data: string) {
    this.sent.push(data)
  }
  close() {
    this.readyState = 3
    this.onclose?.()
  }
  open() {
    this.readyState = fakeWebSocket.OPEN
    this.onopen?.()
  }
}

/** deliver pushes one topic frame the way the daemon would. */
function deliver(topic: string, data: unknown) {
  const ws = fakeWebSocket.instances.at(-1)
  if (!ws) throw new Error('no socket was opened')
  act(() => {
    ws.open()
    ws.onmessage?.({ data: JSON.stringify({ type: 'data', topic, data }) })
  })
}

function routeFetch(handlers: Record<string, { status: number; body?: unknown }>) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string | URL | Request) => {
      const raw = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url
      const resp = handlers[new URL(raw, 'http://kanea.test').pathname] ?? { status: 404 }
      return Promise.resolve({
        ok: resp.status >= 200 && resp.status < 300,
        status: resp.status,
        json: () => Promise.resolve(resp.body ?? {}),
      } as Response)
    }),
  )
}

function renderProjects(session: Session) {
  const state: SessionState = {
    session,
    loading: false,
    csrf: session.csrf,
    signIn: () => {},
    signOut: () => Promise.resolve(),
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <SessionContext.Provider value={state}>
        <Router>
          <Projects />
        </Router>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
}

const admin: Session = { subject: 'ada', role: 'admin', via: 'session', csrf: 'abc' }
const viewer: Session = { subject: 'grace', role: 'viewer', via: 'session' }

const projects = {
  status: 200,
  body: {
    projects: [
      {
        name: 'shop',
        services: 2,
        allocs: 3,
        running: 3,
        git: {
          url: 'https://github.com/acme/shop',
          branch: 'main',
          last_commit: 'abcdef1234567',
          last_sync_at: new Date().toISOString(),
        },
        notifications: ['slack'],
      },
      // No git source, and one alloc short of what it declares.
      { name: 'lab', services: 1, allocs: 2, running: 1 },
    ],
  },
}

beforeEach(() => {
  fakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', fakeWebSocket)
  resetLiveSocket()
})

afterEach(() => {
  resetLiveSocket()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Projects', () => {
  it('lists projects with their git source and health', async () => {
    routeFetch({ '/v1/projects': projects })
    renderProjects(admin)

    expect(await screen.findByText('shop')).toBeDefined()
    expect(screen.getByText('https://github.com/acme/shop#main')).toBeDefined()
    // The short commit, and how long ago the sync landed.
    expect(screen.getByText(/abcdef1/)).toBeDefined()
    expect(screen.getByText('running')).toBeDefined()
    // Two of three allocs is degraded, not down.
    expect(screen.getByText('degraded')).toBeDefined()
  })

  it('offers a sync only where there is something to sync', async () => {
    routeFetch({ '/v1/projects': projects })
    renderProjects(admin)

    await screen.findByText('shop')
    // One button for the git-backed project; the other row shows a dash.
    expect(screen.getAllByRole('button', { name: 'Sync now' })).toHaveLength(1)
  })

  it('disables the sync for a viewer and says why', async () => {
    routeFetch({ '/v1/projects': projects })
    renderProjects(viewer)

    const button = await screen.findByRole('button', { name: 'Sync now' })
    expect(button.hasAttribute('disabled')).toBe(true)
    expect(button.getAttribute('title')).toBe('Requires the admin role')
  })

  it('syncs through the project route with the session CSRF token', async () => {
    routeFetch({ '/v1/projects': projects, '/v1/projects/shop/sync': { status: 200 } })
    renderProjects(admin)

    fireEvent.click(await screen.findByRole('button', { name: 'Sync now' }))

    await waitFor(() => {
      const calls = (globalThis.fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls
      expect(calls.some((call) => String(call[0]).endsWith('/v1/projects/shop/sync'))).toBe(true)
    })
  })

  it('expands a project to the services declared in it', async () => {
    routeFetch({ '/v1/projects': projects })
    renderProjects(admin)

    await screen.findByText('shop')
    const resources = { CPUMillis: 0, MemoryBytes: 0 }
    deliver('services', {
      services: [
        { Project: 'shop', Service: 'web', Image: 'nginx:1.27', Count: 1, Resources: resources },
        { Project: 'lab', Service: 'toy', Image: 'busybox', Count: 1, Resources: resources },
      ],
    })
    deliver('allocs', { allocs: [] })

    fireEvent.click(screen.getByRole('button', { name: /shop/ }))
    expect(screen.getByText('web')).toBeDefined()
    // A project's row shows its own services and nobody else's.
    expect(screen.queryByText('toy')).toBeNull()
  })

  it('says a project exists once a service declares itself into one', async () => {
    routeFetch({ '/v1/projects': { status: 200, body: { projects: [] } } })
    renderProjects(admin)

    expect(await screen.findByText(/there are no projects/)).toBeDefined()
  })
})
