import { z } from 'zod'

/**
 * The dashboard's half of PRD §13.3.
 *
 * Three things live here, and each is a consequence of the cookie being
 * HttpOnly: the app cannot read its own session, so it *asks* who it is; it
 * cannot read the CSRF token from the cookie, so the daemon returns one; and it
 * cannot know the session expired until a request is refused, so a 401 has to
 * be a signal the whole app hears rather than one component's error.
 */

export const sessionSchema = z.object({
  subject: z.string(),
  role: z.enum(['admin', 'viewer']),
  via: z.string(),
  csrf: z.string().optional(),
  expires: z.string().optional(),
})

export type Session = z.infer<typeof sessionSchema>

/** The header the daemon expects on cookie-authenticated mutations. */
export const csrfHeader = 'X-Kanea-CSRF'

/** UnauthorizedError marks a refusal that should return the app to login. */
export class UnauthorizedError extends Error {
  constructor() {
    super('not authenticated')
    this.name = 'UnauthorizedError'
  }
}

/** ApiError carries what the daemon said, which is usually the useful part. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/** unauthorizedEvent is broadcast when any request is refused. */
export const unauthorizedEvent = 'kanea:unauthorized'

const errorSchema = z.object({ error: z.string() })

/**
 * apiFetch is the only way this app talks to the daemon.
 *
 * It attaches the CSRF token to every mutating request rather than leaving it
 * to each call site: a token each caller has to remember is one that gets
 * forgotten on the call that mattered, and the failure mode — a 403 on a button
 * nobody clicked during testing — is exactly the kind that ships.
 */
export async function apiFetch(
  path: string,
  opts: { method?: string; body?: unknown; csrf?: string; signal?: AbortSignal } = {},
): Promise<Response> {
  const method = opts.method ?? 'GET'
  const headers: Record<string, string> = {}
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD' && opts.csrf) headers[csrfHeader] = opts.csrf

  const init: RequestInit = {
    method,
    headers,
    // The session cookie is the credential; without this a cross-origin dev
    // server would send none and every request would 401 for the wrong reason.
    credentials: 'same-origin',
  }
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body)
  if (opts.signal) init.signal = opts.signal

  const resp = await fetch(path, init)
  if (resp.status === 401) {
    // Broadcast rather than thrown-and-handled-per-caller: a session that
    // expired mid-visit affects the whole app, and every component discovering
    // it separately is how half the screen ends up rendering stale data.
    window.dispatchEvent(new CustomEvent(unauthorizedEvent))
    throw new UnauthorizedError()
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, await errorMessage(resp))
  }
  return resp
}

async function errorMessage(resp: Response): Promise<string> {
  try {
    const parsed = errorSchema.safeParse(await resp.json())
    if (parsed.success) return parsed.data.error
  } catch {
    // A body that is not the daemon's error shape tells us nothing more than
    // the status already did.
  }
  return `request failed: ${resp.status}`
}

/** fetchSession asks the daemon who the caller is. */
export async function fetchSession(signal?: AbortSignal): Promise<Session> {
  const resp = await apiFetch('/v1/auth/session', signal ? { signal } : {})
  return sessionSchema.parse(await resp.json())
}

/** login exchanges a password for a session cookie. */
export async function login(user: string, password: string): Promise<Session> {
  // Not through apiFetch: a refused login is an answer to show on the form,
  // not a signal that the app's session went away.
  const resp = await fetch('/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ user, password }),
  })
  if (resp.status === 401) throw new ApiError(401, 'wrong user name or password')
  if (resp.status === 429) {
    throw new ApiError(429, 'too many attempts — wait a minute and try again')
  }
  if (!resp.ok) throw new ApiError(resp.status, await errorMessage(resp))
  return sessionSchema.parse(await resp.json())
}

/** logout revokes the session server-side, not just in this browser. */
export async function logout(csrf?: string): Promise<void> {
  await apiFetch('/v1/auth/logout', { method: 'POST', ...(csrf ? { csrf } : {}) })
}
