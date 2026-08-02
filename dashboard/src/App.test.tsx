import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from '@/App'

/**
 * The gate is presentation, not enforcement — the daemon refuses every route
 * behind it regardless. What these check is that an operator meets a password
 * field rather than a screenful of 401s, and that a session ending returns
 * them to it.
 */

/** silentWebSocket keeps jsdom from dialling a socket nothing here is about. */
class silentWebSocket {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  readyState = silentWebSocket.CONNECTING
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  send() {}
  close() {}
}

/** routeFetch answers each path a rendered App asks for. */
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

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  )
}

const healthy = {
  status: 200,
  body: { status: 'ok', version: 'test', store_index: 1, ws_connections: 0 },
}

const signedIn = {
  status: 200,
  body: { subject: 'ada', role: 'admin', via: 'session', csrf: 'abc' },
}

beforeEach(() => {
  vi.stubGlobal('WebSocket', silentWebSocket)
  // Node's own globals shadow jsdom's here, so neither of these exists in the
  // test environment even though every browser has both. The shell reads them
  // for the theme toggle, which is not what these tests are about.
  vi.stubGlobal('matchMedia', () => ({ matches: false }))
  const store = new Map<string, string>()
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  })
  window.history.pushState({}, '', '/')
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('App', () => {
  it('shows the login form when nobody is signed in', async () => {
    routeFetch({ '/v1/auth/session': { status: 401 }, '/v1/healthz': healthy })
    renderApp()

    expect(await screen.findByLabelText('Password')).toBeDefined()
    expect(screen.queryByLabelText('Sign out')).toBeNull()
  })

  it('shows the app, and who is signed in, once the session resolves', async () => {
    routeFetch({
      '/v1/auth/session': signedIn,
      '/v1/healthz': healthy,
      '/v1/services': { status: 200, body: { services: [] } },
      '/v1/allocs': { status: 200, body: { allocs: [] } },
    })
    renderApp()

    // The role is on screen because a viewer who does not know they are one
    // reads every missing button as a broken dashboard.
    expect(await screen.findByText(/ada/)).toBeDefined()
    expect(screen.getByText(/admin/)).toBeDefined()
    expect(screen.getByLabelText('Sign out')).toBeDefined()
    expect(screen.queryByLabelText('Password')).toBeNull()
  })

  it('returns to the login form when a request is refused mid-visit', async () => {
    routeFetch({
      '/v1/auth/session': signedIn,
      '/v1/healthz': healthy,
      '/v1/services': { status: 200, body: { services: [] } },
      '/v1/allocs': { status: 200, body: { allocs: [] } },
    })
    renderApp()
    await screen.findByLabelText('Sign out')

    // What an expired session looks like to the app: a 401 from anywhere.
    act(() => {
      window.dispatchEvent(new CustomEvent('kanea:unauthorized'))
    })

    await waitFor(() => {
      expect(screen.getByLabelText('Password')).toBeDefined()
    })
  })
})
