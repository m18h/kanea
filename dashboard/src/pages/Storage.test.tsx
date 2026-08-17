import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Storage } from '@/pages/Storage'
import { Router } from '@/lib/router'

/**
 * The Storage page against a faked `GET /v1/volumes`.
 *
 * The fixtures are about one distinction the route is built around and the
 * page has to keep: a mount with no `used_bytes` has not been measured, and
 * must not read as an empty one. Everything else on the page is a total over
 * those readings, so getting it wrong once shows up three times.
 */

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

function renderStorage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <Router>
        <Storage />
      </Router>
    </QueryClientProvider>,
  )
}

const volumes = {
  status: 200,
  body: {
    storages: [
      {
        project: 'shop',
        name: 'media',
        type: 'nfs',
        target: 'nas.lan:/export/media',
        mounts: [
          {
            project: 'shop',
            service: 'web',
            volume: 'media',
            mount_path: '/var/media',
            path: '/var/lib/kanea/volumes/shop/media',
            used_bytes: 2048,
            size_bytes: 1024,
            state: 'over',
          },
        ],
      },
      {
        project: 'shop',
        name: 'cache',
        type: 's3',
        target: 's3://shop-cache',
        // No usage at all: an s3 volume is never walked, by design.
        mounts: [{ project: 'shop', service: 'api', volume: 'cache', state: 'unmeasured' }],
      },
    ],
  },
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Storage', () => {
  it('lists storage resources with their driver and target', async () => {
    routeFetch({ '/v1/volumes': volumes })
    renderStorage()

    expect(await screen.findByText('shop/media')).toBeDefined()
    expect(screen.getByText('nas.lan:/export/media')).toBeDefined()
    expect(screen.getByText('shop/cache')).toBeDefined()
    expect(screen.getByText('s3://shop-cache')).toBeDefined()
  })

  it('shows a mount over its budget as over, still serving', async () => {
    routeFetch({ '/v1/volumes': volumes })
    renderStorage()

    expect(await screen.findByText('over budget')).toBeDefined()
    // The tile says why, because a budget that is not a quota is the thing
    // people misread about this number.
    expect(screen.getByText('still serving; a budget is not a quota')).toBeDefined()
  })

  it('renders an unmeasured volume as a gap, never as empty', async () => {
    routeFetch({ '/v1/volumes': volumes })
    renderStorage()

    await screen.findByText('shop/cache')
    // One resource measured out of two: the total counts only what was walked,
    // and the unmeasured row shows a dash rather than 0 B.
    expect(screen.getByText('across 1 of 2 mounts')).toBeDefined()
    expect(screen.getAllByText('unmeasured').length).toBeGreaterThan(0)
    expect(screen.queryByText('0 B')).toBeNull()
  })

  it('expands a resource to its mounts', async () => {
    routeFetch({ '/v1/volumes': volumes })
    renderStorage()

    const toggle = await screen.findByRole('button', { name: /shop\/media/ })
    expect(screen.queryByText('shop/web')).toBeNull()

    fireEvent.click(toggle)
    expect(screen.getByText('shop/web')).toBeDefined()
    expect(screen.getByText('media → /var/media')).toBeDefined()
  })

  it('says nothing is mounted rather than showing an empty table', async () => {
    routeFetch({ '/v1/volumes': { status: 200, body: { storages: [] } } })
    renderStorage()

    expect(await screen.findByText(/No volumes are mounted/)).toBeDefined()
  })
})
