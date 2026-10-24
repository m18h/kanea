import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, within } from '@testing-library/react'
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

/** deliver pushes one topic frame the way the daemon would. A subscription
 * scoped to a project/service listens under a composite key, so frames for
 * one (the logs topic here) must carry it or they land on no listener. */
function deliver(topic: string, data: unknown, key?: string) {
  const ws = fakeWebSocket.instances.at(-1)
  if (!ws) throw new Error('no socket was opened')
  act(() => {
    ws.open()
    ws.onmessage?.({ data: JSON.stringify({ type: 'data', topic, data, ...(key ? { key } : {}) }) })
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
    // The heading starts with the full name; the status pill rides inside it
    // (v2), so equality would couple this to whatever the pill says.
    expect(heading.textContent?.startsWith('shop/web')).toBe(true)
    // Scoped to the header block, because the image also appears in the Spec
    // tab: the title carries identity, the subtitle carries facts.
    expect(heading.parentElement?.textContent).toContain('nginx:1.27')
  })

  // The spec card's inline edit (v1.103) stays visible for a viewer but
  // disabled with the title, the page's own convention: a viewer who does
  // not know they are a viewer reads a missing button as a broken dashboard.
  it('offers the inline spec edit to a viewer as disabled, with the title', () => {
    renderDetail('shop', 'web')
    deliver('services', {
      services: [
        {
          Project: 'shop',
          Service: 'web',
          Image: 'nginx:1.27',
          Count: 1,
          Resources: { CPUMillis: 0, MemoryBytes: 0 },
          spec_hash: 'abc123',
        },
      ],
    })

    fireEvent.click(screen.getByRole('tab', { name: 'Spec' }))
    const edit = screen.getByRole('button', { name: 'Edit spec inline' })
    expect((edit as HTMLButtonElement).disabled).toBe(true)
    expect(edit.getAttribute('title')).toBe('Requires the admin role')
  })

  it('distinguishes two services that share a name across projects', () => {
    const first = renderDetail('shop', 'web')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('shop/web')
    first.unmount()

    renderDetail('blog', 'web')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('blog/web')
  })

  // The log picker lists every alloc by name and filters the one merged
  // stream by alloc_id: a second subscription would be a protocol change,
  // and every line already says which alloc wrote it.
  it('filters the log stream to the alloc picked in the dropdown', async () => {
    renderDetail('shop', 'web')
    deliver('services', {
      services: [
        {
          Project: 'shop',
          Service: 'web',
          Image: 'nginx:1.27',
          Count: 2,
          Resources: { CPUMillis: 0, MemoryBytes: 0 },
          spec_hash: 'abc123',
        },
      ],
    })
    deliver('allocs', {
      allocs: [
        { id: 'shop-web-0', project: 'shop', service: 'web', index: 0, state: 'running' },
        { id: 'shop-web-1', project: 'shop', service: 'web', index: 1, state: 'running' },
      ],
    })
    fireEvent.click(screen.getByRole('tab', { name: 'Logs' }))
    deliver(
      'logs',
      {
        lines: [
          { alloc_id: 'shop-web-0', line: 'from the leader' },
          { alloc_id: 'shop-web-1', line: 'from the follower' },
        ],
      },
      'logs:shop/web',
    )

    // The stream hook buffers frames and flushes on an interval, so the
    // lines land a beat after the frame does.
    expect(await screen.findByText('from the leader')).toBeTruthy()
    expect(screen.getByText('from the follower')).toBeTruthy()

    const picker = screen.getByLabelText("Which allocation's log to show")
    expect(within(picker).getAllByRole('option').map((o) => o.textContent)).toEqual([
      'all allocs',
      'shop-web-0',
      'shop-web-1',
    ])

    fireEvent.change(picker, { target: { value: 'shop-web-0' } })
    expect(screen.getByText('from the leader')).toBeTruthy()
    expect(screen.queryByText('from the follower')).toBeNull()
  })

  // The init sequence runs once per service, on the leader alone (R32,
  // v1.92): its row carries the declared steps with each one's state, and a
  // follower's row carries none, because it never ran them.
  it("shows the leader's init steps on the allocations table", () => {
    renderDetail('shop', 'web')
    deliver('services', {
      services: [
        {
          Project: 'shop',
          Service: 'web',
          Image: 'nginx:1.27',
          Count: 2,
          Resources: { CPUMillis: 0, MemoryBytes: 0 },
          spec_hash: 'abc123',
          init: [
            { name: 'wait-for-postgres', image: 'busybox:1.36' },
            { name: 'migrate', image: 'nginx:1.27' },
          ],
        },
      ],
    })
    deliver('allocs', {
      allocs: [
        {
          id: 'shop-web-0',
          project: 'shop',
          service: 'web',
          index: 0,
          state: 'init',
          init_step: 1,
          init_name: 'migrate',
          init_started_at: new Date(Date.now() - 90_000).toISOString(),
        },
        { id: 'shop-web-1', project: 'shop', service: 'web', index: 1, state: 'running' },
      ],
    })

    const steps = screen.getByLabelText('Init steps for shop-web-0')
    const items = within(steps).getAllByRole('listitem')
    expect(items.map((li) => li.getAttribute('title'))).toEqual([
      'init "wait-for-postgres": done',
      'init "migrate": running',
    ])
    // The running step carries its elapsed time; absence would leave a stuck
    // migration indistinguishable from one that just started.
    expect(items[1]?.textContent).toContain('1m')
    expect(screen.queryByLabelText('Init steps for shop-web-1')).toBeNull()
  })

  // The picker is a sequence, so it reads in the order the daemon runs it:
  // every init step, numbered, then the task that starts once they are done.
  // `task` sat first, above steps that run before it.
  it('lists the log containers in run order, task last', () => {
    renderDetail('shop', 'web')
    deliver('services', {
      services: [
        {
          Project: 'shop',
          Service: 'web',
          Image: 'nginx:1.27',
          Count: 1,
          Resources: { CPUMillis: 0, MemoryBytes: 0 },
          spec_hash: 'abc123',
          init: [
            { name: 'wait-for-postgres', image: 'busybox:1.36' },
            { name: 'migrate', image: 'nginx:1.27' },
          ],
        },
      ],
    })
    deliver('allocs', {
      allocs: [{ id: 'shop-web-0', project: 'shop', service: 'web', index: 0, state: 'running' }],
    })
    fireEvent.click(screen.getByRole('tab', { name: 'Logs' }))

    const picker = screen.getByLabelText("Which container's log to follow")
    expect(within(picker).getAllByRole('option').map((o) => o.textContent)).toEqual([
      '1. wait-for-postgres',
      '2. migrate',
      'task',
    ])
    // The task is still what the panel opens on, wherever its option sits.
    expect((picker as HTMLSelectElement).value).toBe('')

    // The label carries the ordinal; the value stays the bare block name,
    // which is what the daemon resolves back to a step index.
    fireEvent.change(picker, { target: { value: 'migrate' } })
    expect((picker as HTMLSelectElement).value).toBe('migrate')
  })
})
