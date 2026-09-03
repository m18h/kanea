import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { UpgradeControl } from '@/components/layout/UpgradeControl'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/**
 * The sidebar's version control (PRD v1.107).
 *
 * The rules under test: a viewer keeps the plain version text and never
 * causes a check; an admin gets the dot exactly when a newer release exists;
 * the upgrade is a two-click arm/disarm; and the two endings (restarting vs
 * restart_required) each say what happens next.
 */

/** routeFetch fakes the daemon, keyed on "METHOD /path". */
function routeFetch(handlers: Record<string, { status: number; body?: unknown }>) {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const raw = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url
      const key = `${init?.method ?? 'GET'} ${new URL(raw, 'http://kanea.test').pathname}`
      calls.push(key)
      const resp = handlers[key] ?? { status: 404 }
      return Promise.resolve({
        ok: resp.status >= 200 && resp.status < 300,
        status: resp.status,
        json: () => Promise.resolve(resp.body ?? {}),
        text: () => Promise.resolve(JSON.stringify(resp.body ?? {})),
      } as Response)
    }),
  )
  return calls
}

const adminSession: Session = { subject: 'ada', role: 'admin', via: 'session', csrf: 'abc' }
const viewerSession: Session = { subject: 'grace', role: 'viewer', via: 'session' }

function renderControl(session: Session) {
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
        <UpgradeControl version="v0.30.0" />
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
}

const updateAvailable = {
  status: 200,
  body: {
    running: 'v0.30.0',
    latest: 'v0.31.0',
    update_available: true,
    checked_at: '2026-09-03T09:00:00Z',
  },
}

const current = {
  status: 200,
  body: { running: 'v0.30.0', latest: 'v0.30.0', update_available: false },
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('UpgradeControl', () => {
  it('a viewer gets the plain version and no check leaves the browser', () => {
    const calls = routeFetch({})
    renderControl(viewerSession)
    expect(screen.getByText('v0.30.0')).toBeTruthy()
    expect(screen.queryByRole('button')).toBeNull()
    expect(calls).toHaveLength(0)
  })

  it('an admin sees the dot only when a newer release exists', async () => {
    routeFetch({ 'GET /v1/upgrade': updateAvailable })
    renderControl(adminSession)
    await waitFor(() =>
      expect(screen.getByLabelText('new release v0.31.0 available')).toBeTruthy(),
    )
  })

  it('no dot when the node is current, and the dialog says so', async () => {
    routeFetch({ 'GET /v1/upgrade': current })
    renderControl(adminSession)
    await waitFor(() => expect(screen.getByRole('button', { name: /v0\.30\.0/ })).toBeTruthy())
    expect(screen.queryByLabelText(/new release/)).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: /v0\.30\.0/ }))
    expect(screen.getByText('This node is on the latest release.')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Upgrade to/ })).toBeNull()
  })

  it('a daemon with no upgrader (503) keeps the plain text', async () => {
    routeFetch({ 'GET /v1/upgrade': { status: 503 } })
    renderControl(adminSession)
    await waitFor(() => expect(screen.queryByRole('button')).toBeNull())
    expect(screen.getByText('v0.30.0')).toBeTruthy()
  })

  it('upgrading is a two-click arm/disarm and reports the restart', async () => {
    const calls = routeFetch({
      'GET /v1/upgrade': updateAvailable,
      'POST /v1/upgrade': {
        status: 200,
        body: {
          installed: 'v0.31.0',
          restarting: true,
          notes: ['signature verified', 'installed v0.31.0'],
        },
      },
      // The post-restart health poll: still the old version, so the page
      // must keep waiting rather than reloading under this test.
      'GET /v1/healthz': { status: 200, body: { status: 'ok', version: 'v0.30.0' } },
    })
    renderControl(adminSession)
    await waitFor(() => expect(screen.getByRole('button', { name: /v0\.30\.0/ })).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /v0\.30\.0/ }))

    // First click arms; nothing is sent yet.
    fireEvent.click(screen.getByRole('button', { name: 'Upgrade to v0.31.0' }))
    expect(calls).not.toContain('POST /v1/upgrade')
    fireEvent.click(screen.getByRole('button', { name: 'Confirm upgrade?' }))
    await waitFor(() => expect(calls).toContain('POST /v1/upgrade'))

    // The daemon's own notes are the operator's evidence (the cosign posture
    // among them), and the dialog says the page reloads by itself.
    await waitFor(() => expect(screen.getByText('signature verified')).toBeTruthy())
    expect(screen.getByText(/Restarting the daemons/)).toBeTruthy()
  })

  it('an unsupervised daemon reports the manual restart instead', async () => {
    routeFetch({
      'GET /v1/upgrade': updateAvailable,
      'POST /v1/upgrade': {
        status: 200,
        body: {
          installed: 'v0.31.0',
          restarting: false,
          restart_required: true,
          notes: ['installed v0.31.0'],
        },
      },
    })
    renderControl(adminSession)
    await waitFor(() => expect(screen.getByRole('button', { name: /v0\.30\.0/ })).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /v0\.30\.0/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Upgrade to v0.31.0' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm upgrade?' }))

    await waitFor(() =>
      expect(screen.getByText(/not running under systemd/)).toBeTruthy(),
    )
    expect(screen.queryByText(/Restarting the daemons/)).toBeNull()
  })
})
