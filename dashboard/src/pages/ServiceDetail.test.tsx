import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ServiceDetail } from '@/pages/ServiceDetail'
import { Router } from '@/lib/router'
import { resetLiveSocket } from '@/lib/live'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/**
 * The Service detail page's identity.
 *
 * A service name is unique only inside its project, so `web` alone names two
 * different things on a node running `shop` and `blog`, and the page's own
 * title was the one surface still spelling it that way: the CLI takes
 * `project/service`, PipelineDetail's title is `project/service`, and the
 * stats subject on this very page is `project/service`.
 *
 * Both render paths are pinned, because the page has two and they are easy to
 * change apart: a skeleton while the socket is still connecting, and the real
 * header once a service record has arrived.
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

function stubFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ events: [] }),
      } as Response),
    ),
  )
}

const viewer: Session = { subject: 'grace', role: 'viewer', via: 'session' }

function renderDetail(project: string, service: string) {
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
          <ServiceDetail project={project} service={service} />
        </Router>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  fakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', fakeWebSocket)
  stubFetch()
  resetLiveSocket()
})

afterEach(() => {
  resetLiveSocket()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('ServiceDetail', () => {
  it('titles the page with the full project/service name while connecting', () => {
    renderDetail('shop', 'web')

    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading.textContent).toBe('shop/web')
  })

  it('titles the page with the full project/service name once the record arrives', () => {
    renderDetail('shop', 'web')

    deliver('services', {
      services: [
        {
          Project: 'shop',
          Service: 'web',
          Image: 'nginx:1.27',
          Count: 1,
          // Required by serviceSchema; a record that omits it is rejected and
          // the page stays on its skeleton, which is how this test first
          // failed to leave one.
          Resources: { CPUMillis: 0, MemoryBytes: 0 },
          spec_hash: 'abc123',
        },
      ],
    })

    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading.textContent).toBe('shop/web')
    // Scoped to the header, because the image also appears in the spec panel
    // below: the title carries identity and the subtitle beside it carries
    // facts, which is the split this change preserves.
    expect(heading.parentElement?.textContent).toContain('nginx:1.27')
  })

  it('distinguishes two services that share a name across projects', () => {
    const first = renderDetail('shop', 'web')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('shop/web')
    first.unmount()

    renderDetail('blog', 'web')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('blog/web')
  })
})
