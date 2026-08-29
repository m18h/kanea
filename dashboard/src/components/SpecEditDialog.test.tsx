import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SpecEditDialog } from '@/components/SpecEditDialog'
import { Router } from '@/lib/router'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/**
 * The inline spec editor (v1.103).
 *
 * What is pinned: the dialog seeds from the generated source and never from
 * the template (a generation refusal shows the refusal plus the full-editor
 * link instead); validate runs the scope check against the HTTP record and an
 * out-of-scope edit names its fields and keeps Apply disabled; a git-synced
 * project demands the acknowledgement; a successful apply closes the dialog.
 */

const record = () => ({
  Project: 'shop',
  Service: 'web',
  Count: 1,
  Image: 'nginx:1.29',
  Volumes: null,
})

type Route = { status: number; body: unknown }

function routeFetch(routes: Record<string, Route | ((init?: RequestInit) => Route)>) {
  const calls: { path: string; init: RequestInit | undefined }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      const path = raw.split('?')[0] ?? ''
      calls.push({ path, init })
      const route = routes[path]
      const r = typeof route === 'function' ? route(init) : route
      if (!r) throw new Error(`unrouted fetch: ${path}`)
      return Promise.resolve({
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        json: () => Promise.resolve(r.body),
      } as Response)
    }),
  )
  return calls
}

const baseRoutes = {
  '/v1/spec/source': { status: 200, body: { hcl: 'service "web" { project = "shop" }', generated: true } },
  '/v1/projects': { status: 200, body: { projects: [{ name: 'shop', services: 1, allocs: 1, running: 1 }] } },
  '/v1/services': { status: 200, body: { services: [record()] } },
}

const admin: Session = { subject: 'ada', role: 'admin', via: 'session' }
const viewer: Session = { subject: 'grace', role: 'viewer', via: 'session' }

function renderDialog(session: Session, onClose = vi.fn()) {
  const state: SessionState = {
    session,
    loading: false,
    csrf: 'csrf-token',
    signIn: () => {},
    signOut: () => Promise.resolve(),
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <SessionContext.Provider value={state}>
        <Router>
          <SpecEditDialog project="shop" service="web" open onClose={onClose} />
        </Router>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
  return onClose
}

beforeEach(() => {
  vi.stubGlobal('WebSocket', class { close() {} })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('SpecEditDialog', () => {
  it('seeds the textarea from the generated source', async () => {
    routeFetch(baseRoutes)
    renderDialog(admin)
    const area = await screen.findByLabelText('Job spec HCL')
    await waitFor(() =>
      expect((area as HTMLTextAreaElement).value).toContain('service "web"'),
    )
  })

  it('shows a generation refusal with the full-editor link, never the template', async () => {
    routeFetch({
      ...baseRoutes,
      '/v1/spec/source': {
        status: 422,
        body: { error: 'project shop has a git or build pipeline' },
      },
    })
    renderDialog(admin)
    expect(await screen.findByText(/git or build pipeline/)).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Open the full spec editor' })).toBeTruthy()
    expect(screen.queryByLabelText('Job spec HCL')).toBeNull()
  })

  it('refuses an out-of-scope edit by name and keeps Apply disabled', async () => {
    routeFetch({
      ...baseRoutes,
      '/v1/spec/render': {
        status: 200,
        body: {
          valid: true,
          services: [
            { ...record(), Volumes: [{ Name: 'data', Storage: 'media', Path: '/data' }] },
          ],
        },
      },
    })
    renderDialog(admin)
    await screen.findByLabelText('Job spec HCL')
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }))
    expect(await screen.findByText(/may not change volumes/)).toBeTruthy()
    const apply = screen.getByRole('button', { name: 'Apply' })
    expect((apply as HTMLButtonElement).disabled).toBe(true)
  })

  it('enables Apply for an admin once an in-scope edit validates', async () => {
    routeFetch({
      ...baseRoutes,
      '/v1/spec/render': {
        status: 200,
        body: { valid: true, services: [{ ...record(), Count: 3 }] },
      },
    })
    renderDialog(admin)
    await screen.findByLabelText('Job spec HCL')
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }))
    await screen.findByText('valid')
    const apply = screen.getByRole('button', { name: 'Apply' })
    expect((apply as HTMLButtonElement).disabled).toBe(false)
  })

  it('keeps Apply visible but disabled for a viewer, with the title', async () => {
    routeFetch(baseRoutes)
    renderDialog(viewer)
    await screen.findByLabelText('Job spec HCL')
    const apply = screen.getByRole('button', { name: 'Apply' })
    expect((apply as HTMLButtonElement).disabled).toBe(true)
    expect(apply.getAttribute('title')).toBe('Requires the admin role')
  })

  it('demands the acknowledgement on a git-synced project', async () => {
    routeFetch({
      ...baseRoutes,
      '/v1/projects': {
        status: 200,
        body: {
          projects: [
            {
              name: 'shop',
              services: 1,
              allocs: 1,
              running: 1,
              git: { url: 'https://git.example/shop.git' },
            },
          ],
        },
      },
      '/v1/spec/render': {
        status: 200,
        body: { valid: true, services: [{ ...record(), Count: 3 }] },
      },
    })
    renderDialog(admin)
    await screen.findByLabelText('Job spec HCL')
    await screen.findByText('Apply anyway; the next sync wins.')
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }))
    await screen.findByText('valid')
    const apply = screen.getByRole('button', { name: 'Apply' })
    expect((apply as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('checkbox'))
    expect((apply as HTMLButtonElement).disabled).toBe(false)
  })

  it('applies the validated bytes and closes', async () => {
    const calls = routeFetch({
      ...baseRoutes,
      '/v1/spec/render': {
        status: 200,
        body: { valid: true, services: [{ ...record(), Count: 3 }] },
      },
      '/v1/spec/apply': { status: 200, body: { applied: ['shop/web'], index: 9 } },
    })
    const onClose = renderDialog(admin)
    await screen.findByLabelText('Job spec HCL')
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }))
    await screen.findByText('valid')
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(onClose).toHaveBeenCalled())
    const apply = calls.find((c) => c.path === '/v1/spec/apply')
    expect(apply).toBeTruthy()
    const body = JSON.parse(apply?.init?.body as string) as {
      files: Record<string, string>
      project: string
    }
    expect(body.project).toBe('shop')
    expect(body.files['editor.hcl']).toContain('service "web"')
  })
})
