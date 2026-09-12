import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Updates } from '@/pages/Updates'
import { Router } from '@/lib/router'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/** routeFetch answers each path the rendered page asks for. */
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

function renderUpdates(session: Session) {
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
          <Updates />
        </Router>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
}

const admin: Session = { subject: 'ada', role: 'admin', via: 'session', csrf: 'abc' }
const viewer: Session = { subject: 'grace', role: 'viewer', via: 'session' }

const checkBody = {
  running: 'v0.34.0',
  latest: 'v0.35.0',
  update_available: true,
  checked_at: '2026-09-12T09:41:00Z',
}

const updatesBody = {
  os: {
    name: 'Debian GNU/Linux 12 (bookworm)',
    kernel: '6.1.0-37-amd64',
    package_manager: 'apt',
    pending: [
      {
        name: 'libssl3',
        installed: '3.0.16-1~deb12u1',
        candidate: '3.0.17-1~deb12u2',
        origin: 'Debian-Security:12/stable-security',
        security: true,
      },
      { name: 'curl', installed: '1', candidate: '2', origin: 'Debian:12.12/stable' },
    ],
    pending_total: 14,
    security_total: 3,
    lists_refreshed_at: '2026-09-11T22:10:00Z',
    reboot_required: true,
  },
  components: [
    { name: 'containerd', pinned: '2.3.3', installed: '2.3.3' },
    { name: 'runc', pinned: '1.5.1' },
  ],
  checked_at: '2026-09-12T10:00:00Z',
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Updates', () => {
  it('explains itself to a viewer instead of a page of 403s', () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    renderUpdates(viewer)

    expect(screen.getByText(/admin-only/)).toBeTruthy()
    // The queries are disabled for a viewer: the daemon would refuse them,
    // and asking anyway is noise in its log.
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('shows the release, the OS and both tables to an admin', async () => {
    routeFetch({
      '/v1/upgrade': { status: 200, body: checkBody },
      '/v1/updates': { status: 200, body: updatesBody },
    })
    renderUpdates(admin)

    // The Kanea card: running vs latest, and the upgrade control.
    expect(await screen.findByText('v0.34.0')).toBeTruthy()
    expect(screen.getByText('update available')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Upgrade to v0.35.0' })).toBeTruthy()

    // The OS card, with the reboot flag loud.
    expect(screen.getByText('Debian GNU/Linux 12 (bookworm)')).toBeTruthy()
    expect(screen.getByText('reboot required')).toBeTruthy()
    expect(screen.getByText('3 security')).toBeTruthy()

    // The component matrix: a receipt-less component is unknown, not absent.
    expect(screen.getByText('containerd')).toBeTruthy()
    expect(screen.getByText('no receipt')).toBeTruthy()

    // The pending table, bounded with the total carrying the truth.
    expect(screen.getByText('libssl3')).toBeTruthy()
    expect(screen.getByText('security')).toBeTruthy()
    expect(screen.getByText(/and 12 more/)).toBeTruthy()
  })

  it('says what a 503 means on both halves', async () => {
    // A daemon with no upgrader or inspector wired (a dev run) hides the
    // controls rather than erroring.
    routeFetch({
      '/v1/upgrade': { status: 503 },
      '/v1/updates': { status: 503 },
    })
    renderUpdates(admin)

    expect(await screen.findByText(/cannot upgrade itself/)).toBeTruthy()
    expect(screen.getByText(/does not inspect its host/)).toBeTruthy()
  })
})
