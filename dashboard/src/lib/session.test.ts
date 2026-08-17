import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  apiFetch,
  ApiError,
  csrfHeader,
  fetchSession,
  login,
  logout,
  UnauthorizedError,
  unauthorizedEvent,
} from './session'

/** stubFetch replaces global fetch and records what was sent. */
function stubFetch(resp: { status: number; body?: unknown }) {
  const calls: { url: string; init: RequestInit | undefined }[] = []
  const impl = vi.fn((url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: urlOf(url), init })
    return Promise.resolve({
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      json: () => Promise.resolve(resp.body ?? {}),
    } as Response)
  })
  vi.stubGlobal('fetch', impl)
  return calls
}

/** urlOf normalises what fetch accepts into the path a test asserts on. */
function urlOf(input: string | URL | Request): string {
  if (typeof input === 'string') return input
  return input instanceof URL ? input.href : input.url
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('apiFetch', () => {
  it('sends the CSRF token on a mutation', async () => {
    const calls = stubFetch({ status: 204 })
    await apiFetch('/v1/services', { method: 'PUT', body: {}, csrf: 'token-value' })

    const headers = calls[0]?.init?.headers as Record<string, string>
    expect(headers[csrfHeader]).toBe('token-value')
  })

  it('does not send it on a read, which the daemon does not check', async () => {
    const calls = stubFetch({ status: 200 })
    await apiFetch('/v1/services', { csrf: 'token-value' })

    const headers = calls[0]?.init?.headers as Record<string, string>
    expect(headers[csrfHeader]).toBeUndefined()
  })

  it('sends the cookie, which is the whole credential', async () => {
    const calls = stubFetch({ status: 200 })
    await apiFetch('/v1/services')
    expect(calls[0]?.init?.credentials).toBe('same-origin')
  })

  // A session that expired mid-visit affects the whole app, so the refusal is
  // broadcast rather than handled by whichever component happened to ask.
  it('broadcasts on a 401 and throws UnauthorizedError', async () => {
    stubFetch({ status: 401 })
    const heard = vi.fn()
    window.addEventListener(unauthorizedEvent, heard)

    await expect(apiFetch('/v1/services')).rejects.toBeInstanceOf(UnauthorizedError)
    expect(heard).toHaveBeenCalledOnce()

    window.removeEventListener(unauthorizedEvent, heard)
  })

  it('carries the message the daemon sent on other failures', async () => {
    stubFetch({ status: 409, body: { error: 'ada is the only admin account' } })
    await expect(apiFetch('/v1/users/ada', { method: 'DELETE' })).rejects.toThrow(/only admin/)
  })

  it('does not broadcast on a 403, which answers permission, not identity', async () => {
    stubFetch({ status: 403, body: { error: 'not authorised' } })
    const heard = vi.fn()
    window.addEventListener(unauthorizedEvent, heard)

    await expect(apiFetch('/v1/services', { method: 'PUT' })).rejects.toBeInstanceOf(ApiError)
    expect(heard).not.toHaveBeenCalled()

    window.removeEventListener(unauthorizedEvent, heard)
  })
})

describe('login', () => {
  it('parses the session the daemon returns', async () => {
    stubFetch({
      status: 200,
      body: { subject: 'ada', role: 'admin', via: 'session', csrf: 'abc' },
    })
    const session = await login('ada', 'a-long-passphrase')
    expect(session.subject).toBe('ada')
    expect(session.csrf).toBe('abc')
  })

  // A refused login is an answer for the form, not a signal that the app's
  // session went away: the app has no session yet.
  it('does not broadcast an unauthorized event', async () => {
    stubFetch({ status: 401 })
    const heard = vi.fn()
    window.addEventListener(unauthorizedEvent, heard)

    await expect(login('ada', 'wrong')).rejects.toThrow(/wrong user name or password/)
    expect(heard).not.toHaveBeenCalled()

    window.removeEventListener(unauthorizedEvent, heard)
  })

  it('explains a rate-limited attempt rather than repeating "unauthorised"', async () => {
    stubFetch({ status: 429 })
    await expect(login('ada', 'wrong')).rejects.toThrow(/too many attempts/)
  })

  it('rejects a response that is not a session', async () => {
    stubFetch({ status: 200, body: { subject: 'ada', role: 'superuser', via: 'session' } })
    await expect(login('ada', 'pw')).rejects.toBeTruthy()
  })
})

describe('logout', () => {
  it('sends the CSRF token, without which the daemon refuses it', async () => {
    const calls = stubFetch({ status: 204 })
    await logout('token-value')

    const headers = calls[0]?.init?.headers as Record<string, string>
    expect(calls[0]?.init?.method).toBe('POST')
    expect(headers[csrfHeader]).toBe('token-value')
  })
})

describe('fetchSession', () => {
  it('returns the caller the daemon reports', async () => {
    stubFetch({ status: 200, body: { subject: 'vic', role: 'viewer', via: 'session' } })
    const session = await fetchSession()
    expect(session.role).toBe('viewer')
  })
})
