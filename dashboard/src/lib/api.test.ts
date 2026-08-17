import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  allocsResponseSchema,
  createBackup,
  logBatchSchema,
  servicesResponseSchema,
  subscriptionKey,
  syncProject,
  Topic,
  triggerBuild,
  verifyBackup,
} from './api'
import { csrfHeader } from './session'

describe('subscriptionKey', () => {
  it('is the bare topic when nothing scopes it', () => {
    expect(subscriptionKey({ topic: Topic.Services })).toBe('services')
  })

  it('includes the service so two log streams can share one socket', () => {
    expect(subscriptionKey({ topic: Topic.Logs, project: 'shop', service: 'web' })).toBe(
      'logs:shop/web',
    )
  })
})

describe('servicesResponseSchema', () => {
  it('accepts a null list, which is what Go sends for an empty slice', () => {
    const parsed = servicesResponseSchema.parse({ services: null })
    expect(parsed.services).toBeNull()
  })

  // Parsing rather than casting is the point: a daemon that changed shape
  // should fail here with a field name, not crash three components away.
  it('rejects a payload missing a required field', () => {
    const result = servicesResponseSchema.safeParse({
      services: [{ Project: 'shop', Service: 'web' }],
    })
    expect(result.success).toBe(false)
  })
})

describe('logBatchSchema', () => {
  it('parses a tick of lines with no drops', () => {
    const parsed = logBatchSchema.parse({
      lines: [
        { alloc_id: 'shop-web-0', line: 'listening on :8080' },
        { alloc_id: 'shop-web-1', line: 'ready' },
      ],
    })
    expect(parsed.lines).toHaveLength(2)
    // Absent, not zero; the daemon omits it on the ordinary frame.
    expect(parsed.dropped).toBeUndefined()
  })

  it('carries a daemon-side drop count', () => {
    expect(logBatchSchema.parse({ lines: [], dropped: 412 }).dropped).toBe(412)
  })

  it('accepts a null list, which is what Go sends for an empty slice', () => {
    expect(logBatchSchema.parse({ lines: null }).lines).toBeNull()
  })

  // The pre-v1.70 shape was one line per frame. It must fail here, in a test,
  // rather than silently in a browser: a tab left open across an upgrade is
  // the one place the old shape can still show up.
  it('rejects the old one-line-per-frame shape', () => {
    const result = logBatchSchema.safeParse({ alloc_id: 'shop-web-0', line: 'hello' })
    expect(result.success).toBe(false)
  })
})

describe('allocsResponseSchema', () => {
  // AllocRecord marshals lowercase json tags, unlike Desired's PascalCase.
  // This fixture is a real daemon payload; the PascalCase schema this replaced
  // rejected every frame the allocs topic ever sent.
  it('parses the lowercase wire shape AllocRecord actually sends', () => {
    const parsed = allocsResponseSchema.parse({
      allocs: [
        {
          id: 'shop-web-0-abc12',
          project: 'shop',
          service: 'web',
          index: 0,
          image: 'reg.kanea.dev/web:1.9.2',
          state: 'running',
          spec_hash: 'deadbeef',
          restarts: 1,
          last_exit_code: 137,
          last_exit_at: '2026-08-09T14:25:17Z',
          healthy: true,
          last_probe_at: '2026-08-09T14:32:00Z',
          created_at: '2026-06-29T08:00:00Z',
          updated_at: '2026-08-09T14:32:00Z',
        },
      ],
    })
    expect(parsed.allocs?.[0]?.id).toBe('shop-web-0-abc12')
    expect(parsed.allocs?.[0]?.created_at).toBe('2026-06-29T08:00:00Z')
  })

  it('rejects the PascalCase shape that never matched the wire', () => {
    const result = allocsResponseSchema.safeParse({
      allocs: [{ ID: 'x', Project: 'shop', Service: 'web', Index: 0, State: 'running' }],
    })
    expect(result.success).toBe(false)
  })
})

/** stubFetch records what was sent and answers with a fixed response. */
function stubFetch(status: number, body: unknown = {}) {
  const calls: { url: string; init: RequestInit | undefined }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: typeof url === 'string' ? url : url instanceof URL ? url.href : url.url, init })
      return Promise.resolve({
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(body),
      } as Response)
    }),
  )
  return calls
}

afterEach(() => {
  vi.unstubAllGlobals()
})

// The daemon checks the double-submit token on every cookie-authenticated
// mutation (§13.3), so each mutating helper must route through apiFetch with
// its token. These pin the wire shape a missing token would silently break.
describe('mutations carry the CSRF token', () => {
  it('triggerBuild posts with the header', async () => {
    const calls = stubFetch(200, {
      id: 'run-1', project: 'shop', service: 'web', state: 'queued',
      trigger: 'manual', started_at: '2026-08-11T00:00:00Z',
    })
    await triggerBuild('shop', 'web', true, 'token-value')
    const headers = calls[0]?.init?.headers as Record<string, string>
    expect(calls[0]?.init?.method).toBe('POST')
    expect(headers[csrfHeader]).toBe('token-value')
  })

  it('syncProject posts with the header', async () => {
    const calls = stubFetch(204)
    await syncProject('shop', 'token-value')
    const headers = calls[0]?.init?.headers as Record<string, string>
    expect(calls[0]?.init?.method).toBe('POST')
    expect(headers[csrfHeader]).toBe('token-value')
  })

  it('createBackup posts with the header', async () => {
    const calls = stubFetch(204)
    await createBackup('from the dashboard', 'token-value')
    const headers = calls[0]?.init?.headers as Record<string, string>
    expect(calls[0]?.init?.method).toBe('POST')
    expect(headers[csrfHeader]).toBe('token-value')
  })

  // verify is a GET at the daemon, and reads carry no token.
  it('verifyBackup reads without the header', async () => {
    const calls = stubFetch(204)
    await verifyBackup('arch-1')
    const headers = (calls[0]?.init?.headers ?? {}) as Record<string, string>
    expect(calls[0]?.init?.method ?? 'GET').toBe('GET')
    expect(headers[csrfHeader]).toBeUndefined()
  })
})
