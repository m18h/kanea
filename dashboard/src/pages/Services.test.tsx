import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Services } from '@/pages/Services'
import { Router } from '@/lib/router'
import { resetLiveSocket } from '@/lib/live'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/**
 * The Services page's filters, which live in the URL.
 *
 * The acceptance test for the whole feature is "a popstate restores the
 * inputs": searching, clicking into a service and pressing Back used to land
 * on an unfiltered list with an empty box.
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

const viewer: Session = { subject: 'grace', role: 'viewer', via: 'session' }

function renderServices() {
  const state: SessionState = {
    session: viewer,
    loading: false,
    csrf: undefined,
    signIn: () => {},
    signOut: () => Promise.resolve(),
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <SessionContext.Provider value={state}>
        <Router>
          <Services />
        </Router>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
}

function service(project: string, name: string, count = 1) {
  return {
    Project: project,
    Service: name,
    Image: `registry.example/${name}:v1`,
    Count: count,
    Resources: { CPUMillis: 0, MemoryBytes: 0 },
    spec_hash: `sha256:${name}`,
  }
}

/** Three services, one of them degraded: enough to tell a filter worked. */
function seedServices() {
  deliver('services', {
    services: [service('shop', 'api'), service('shop', 'web'), service('lab', 'notes')],
  })
  deliver('allocs', {
    allocs: [
      { id: 'shop-api-0', project: 'shop', service: 'api', index: 0, state: 'running' },
      { id: 'shop-web-0', project: 'shop', service: 'web', index: 0, state: 'running' },
      { id: 'lab-notes-0', project: 'lab', service: 'notes', index: 0, state: 'failed' },
    ],
  })
}

const rows = () => screen.queryAllByText(/^(shop|lab)\//).map((el) => el.textContent)

beforeEach(() => {
  fakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', fakeWebSocket)
  resetLiveSocket()
  // The URL is global state; vitest isolates per file, not per test.
  window.history.pushState({}, '', '/services')
})

afterEach(() => {
  resetLiveSocket()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Services filters in the URL', () => {
  it('applies a search seeded on the URL to the first paint', () => {
    window.history.pushState({}, '', '/services?q=api')
    renderServices()
    seedServices()

    expect(rows()).toEqual(['shop/api'])
    expect(screen.getByLabelText<HTMLInputElement>('Search services').value).toBe('api')
  })

  it('applies a chip seeded on the URL', () => {
    window.history.pushState({}, '', '/services?status=degraded')
    renderServices()
    seedServices()

    expect(rows()).toEqual(['lab/notes'])
  })

  it('writes the search to the URL as it is typed', () => {
    renderServices()
    seedServices()

    fireEvent.change(screen.getByLabelText('Search services'), { target: { value: 'web' } })

    expect(window.location.search).toBe('?q=web')
    expect(rows()).toEqual(['shop/web'])
  })

  // The whole point: leaving the page and coming back keeps the filter.
  it('restores the inputs and the rows on a popstate', () => {
    window.history.pushState({}, '', '/services?q=api')
    renderServices()
    seedServices()
    expect(rows()).toEqual(['shop/api'])

    // What going Back to a different filter looks like to the page.
    window.history.pushState({}, '', '/services?q=web')
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'))
    })

    expect(screen.getByLabelText<HTMLInputElement>('Search services').value).toBe('web')
    expect(rows()).toEqual(['shop/web'])
  })

  it('leaves a clean URL once the filters are cleared', () => {
    window.history.pushState({}, '', '/services?q=api')
    renderServices()
    seedServices()

    fireEvent.change(screen.getByLabelText('Search services'), { target: { value: '' } })

    expect(window.location.search).toBe('')
    expect(window.location.pathname).toBe('/services')
    expect(rows()).toHaveLength(3)
  })

  it('carries the sort column and direction, and drops it on the third click', () => {
    renderServices()
    seedServices()

    const ready = screen.getByRole('columnheader', { name: /Ready/ })
    fireEvent.click(screen.getByRole('button', { name: /Ready/ }))
    expect(window.location.search).toBe('?sort=allocs%3Aasc')
    expect(ready.getAttribute('aria-sort')).toBe('ascending')

    fireEvent.click(screen.getByRole('button', { name: /Ready/ }))
    expect(window.location.search).toBe('?sort=allocs%3Adesc')

    fireEvent.click(screen.getByRole('button', { name: /Ready/ }))
    expect(window.location.search).toBe('')
  })

  // A hand-edited or stale URL must not crash the page or filter it to
  // nothing it can explain.
  it('ignores a status and a sort it does not have', () => {
    window.history.pushState({}, '', '/services?status=banana&sort=nope:sideways')
    renderServices()
    seedServices()

    expect(rows()).toHaveLength(3)
  })
})
