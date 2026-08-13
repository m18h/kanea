import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Settings } from '@/pages/Settings'
import { Router } from '@/lib/router'
import { SessionContext, type SessionState } from '@/lib/session-context'
import type { Session } from '@/lib/session'

/**
 * The Settings page against a faked daemon. The fixtures exercise the wire
 * shapes the zod schemas pin: Go-named notification channels, the zero time
 * on an unexpiring token, and the settings view's three sources.
 */

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

function renderSettings(session: Session, tab?: string) {
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
          <Settings {...(tab !== undefined ? { tab } : {})} />
        </Router>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
}

const admin: Session = { subject: 'ada', role: 'admin', via: 'session', csrf: 'abc' }
const viewer: Session = { subject: 'grace', role: 'viewer', via: 'session' }

const settingsBody = {
  node: {
    listen: ':8600',
    tls: true,
    base_domain: 'lab.example',
    network_mode: 'ebpf',
    node_cidr: '10.100.1.0/24',
    cluster_cidr: '10.100.0.0/16',
    service_cidr: '10.96.0.0/16',
    node_cidr6: 'fd00:64::/64',
    data_dir: '/var/lib/kanea',
    log_dir: '/var/log/kanea',
    publish_ports: '8000-9000',
    tls_default: 'acme',
  },
  backup: {
    source: 'store',
    settings: {
      s3: {
        url: 's3://kanea/backups',
        endpoint: 'https://s3.example.com',
        region: 'us-east-1',
        access_key: 'AK',
        secret_key_ref: 'secret:shared/backup-s3',
        path_style: true,
      },
      snapshot_interval: '6h0m0s',
      retention: 10,
    },
    status: {
      sink: 's3://kanea/backups',
      shipped_to: 42,
      last_segment_at: '2026-01-01T00:00:30Z',
      last_snapshot_at: '2026-01-01T00:00:00Z',
      failures: 0,
    },
  },
  notifications: {
    source: 'store',
    settings: {
      channels: {
        Telegram: null,
        Webhook: { URL: 'https://example.com/hook', SecretRef: 'secret:shared/hook' },
        Slack: null,
        Ntfy: null,
        SMTP: null,
        On: ['deploy.*', '*.failed'],
        Severity: 'warning',
        // The wire really carries this — jobspec.Notifications is untagged —
        // and the schema must strip it rather than choke on it.
        DefRange: { Filename: 'x.hcl' },
      },
    },
  },
}

const fixtures = {
  '/v1/settings': { status: 200, body: settingsBody },
  '/v1/edge/policy': {
    status: 200,
    body: {
      publish_enabled: true,
      publish_ports: '8000-9000',
      ranges: [{ from: 8000, to: 9000 }],
      reserved: [22, 53, 8600],
    },
  },
  '/v1/secrets/providers': { status: 404 },
  '/v1/projects': {
    status: 200,
    body: {
      projects: [
        {
          name: 'blog',
          services: 1,
          allocs: 1,
          running: 1,
          git: { url: 'https://git.example.com/blog.git' },
          notifications: ['webhook'],
        },
      ],
    },
  },
  '/v1/projects/blog/notifications': {
    status: 200,
    body: {
      project: 'blog',
      notifications: {
        Slack: { URLRef: 'secret:blog/slack' },
        On: ['deploy.*'],
        Severity: '',
        DefRange: {},
      },
      git_managed: true,
      warning: 'this project is synced from git; the next sync wins',
    },
  },
  '/v1/users': {
    status: 200,
    body: {
      users: [
        { name: 'ada', role: 'admin', created: '2026-01-01T00:00:00Z', updated: '2026-01-02T00:00:00Z' },
        { name: 'grace', role: 'viewer', created: '2026-01-01T00:00:00Z', updated: '2026-01-01T00:00:00Z' },
      ],
    },
  },
  '/v1/tokens': {
    status: 200,
    body: {
      tokens: [
        {
          id: 'tok_1',
          name: 'ci',
          role: 'admin',
          created: '2026-01-01T00:00:00Z',
          // The Go zero time: an unexpiring token cannot omit the field.
          expires: '0001-01-01T00:00:00Z',
          last_used: '0001-01-01T00:00:00Z',
        },
      ],
    },
  },
  '/v1/audit': {
    status: 200,
    body: {
      entries: [
        {
          id: '01ABC',
          time: '2026-01-01T12:00:00Z',
          actor: 'ada',
          role: 'admin',
          via: 'session',
          action: 'service.apply',
          target: 'blog/web',
          result: 'ok',
          status: 200,
          source: '192.0.2.1',
        },
        {
          id: '01ABD',
          time: '2026-01-01T11:00:00Z',
          actor: 'mallory',
          via: 'session',
          action: 'auth.login',
          result: 'denied',
          status: 401,
          source: '198.51.100.7',
        },
      ],
      more: false,
    },
  },
}

beforeEach(() => {
  routeFetch(fixtures)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Settings', () => {
  it('tells a viewer the page is admin-only instead of a wall of 403s', () => {
    renderSettings(viewer)
    expect(screen.getByText(/admin-only/)).toBeDefined()
    expect(screen.queryByText('Node')).toBeNull()
  })

  it('the rail is real links, one per section, and node is the default tab', async () => {
    renderSettings(admin)
    const nav = screen.getByRole('navigation', { name: 'Settings sections' })
    const links = nav.querySelectorAll('a')
    expect([...links].map((a) => a.getAttribute('href'))).toEqual([
      '/settings/node',
      '/settings/backup',
      '/settings/notifications',
      '/settings/accounts',
      '/settings/audit',
    ])
    // Bare /settings renders the node tab, marked current on the rail.
    expect(nav.querySelector('[aria-current="page"]')?.textContent).toBe('Node')
    expect(await screen.findByText('10.100.1.0/24')).toBeDefined()
  })

  it('an unknown tab gets a message under the rail, not a blank page', () => {
    renderSettings(admin, 'nope')
    expect(screen.getByText('No such settings tab.')).toBeDefined()
    expect(screen.getByRole('navigation', { name: 'Settings sections' })).toBeDefined()
  })

  it('renders the node facts, flag-decided and read-only', async () => {
    renderSettings(admin)
    expect(await screen.findByText('10.100.1.0/24')).toBeDefined()
    expect(screen.getByText('fd00:64::/64')).toBeDefined()
    expect(screen.getByText('/var/lib/kanea')).toBeDefined()
    expect(await screen.findByText('22, 53, 8600')).toBeDefined()
    expect(screen.getAllByText(/unit flags/).length).toBeGreaterThan(0)
  })

  it('shows the backup source and seeds the form from the stored record', async () => {
    renderSettings(admin, 'backup')
    expect(await screen.findByText('from settings')).toBeDefined()
    expect(screen.getByLabelText('Bucket URL')).toHaveProperty('value', 's3://kanea/backups')
    expect(screen.getByLabelText('Secret key reference')).toHaveProperty(
      'value',
      'secret:shared/backup-s3',
    )
    expect(screen.getByLabelText('Retention (archives)')).toHaveProperty('value', '10')
    // The record is set, so reverting to the unit flags is offered.
    expect(screen.getByText('Revert to unit flags')).toBeDefined()
  })

  it('refuses an empty directory destination before any round trip', async () => {
    renderSettings(admin, 'backup')
    await screen.findByText('from settings')
    fireEvent.click(screen.getByRole('button', { name: 'Directory' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByText('A directory destination needs a path.')).toBeDefined()
  })

  it('seeds the node channel editor from the Go-named wire record', async () => {
    renderSettings(admin, 'notifications')
    expect(await screen.findByText('node defaults set')).toBeDefined()
    expect(screen.getByLabelText('URL')).toHaveProperty('value', 'https://example.com/hook')
    const on = screen.getByLabelText(/Send on/)
    expect(on).toHaveProperty('value', 'deploy.*, *.failed')
    // One configured channel, one test button.
    expect(screen.getByRole('button', { name: 'Test webhook' })).toBeDefined()
  })

  it('opens a project override and shows the git-managed warning prominently', async () => {
    renderSettings(admin, 'notifications')
    const row = await screen.findByRole('button', { name: /blog/ })
    fireEvent.click(row)
    expect(await screen.findByText(/synced from git/)).toBeDefined()
    // The project's own slack ref is on screen, in reference form only.
    expect(screen.getByDisplayValue('secret:blog/slack')).toBeDefined()
  })

  it('lists accounts and tokens, rendering the zero time as never', async () => {
    renderSettings(admin, 'accounts')
    expect(await screen.findByText('ci')).toBeDefined()
    expect(screen.getAllByText('never').length).toBeGreaterThanOrEqual(2)
    // Deleting yourself is greyed out, with the reason on the title.
    const del = screen.getAllByRole('button', { name: 'Delete' })
    expect(del.some((b) => (b as HTMLButtonElement).disabled)).toBe(true)
  })

  it('pages the audit log with the daemon-side filters', async () => {
    renderSettings(admin, 'audit')
    expect(await screen.findByText('service.apply')).toBeDefined()
    expect(screen.getByText('denied')).toBeDefined()
    // No more pages: Older is disabled.
    expect(screen.getByRole('button', { name: 'Older' })).toHaveProperty('disabled', true)
  })
})
