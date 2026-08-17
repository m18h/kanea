import { useCallback, useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { SessionContext, type SessionState } from '@/lib/session-context'
import {
  fetchSession,
  logout,
  UnauthorizedError,
  unauthorizedEvent,
  type Session,
} from '@/lib/session'
import { resetLiveSocket } from '@/lib/live'

/** revalidateInterval is how often the app re-asks who it is. */
const revalidateInterval = 60_000

/**
 * SessionProvider resolves who the caller is and keeps the answer current.
 *
 * The daemon is the only source of truth here. The session cookie is HttpOnly
 * by design (§14, A03), so there is nothing in the browser to read and no local
 * "am I logged in" flag to go stale: the app asks on load, and listens for the
 * 401 that says the answer changed.
 */
export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const queryClient = useQueryClient()

  const resolve = useCallback(async (signal?: AbortSignal) => {
    try {
      setSession(await fetchSession(signal))
    } catch {
      // Any failure here means "not signed in as far as this app is
      // concerned". A daemon that is down looks the same as a session that
      // expired, and both lead to the same screen.
      setSession(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    // The initial fetch of the session is the external system this effect
    // exists to talk to; the synchronous setLoading inside is its beginning.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void resolve(controller.signal)
    return () => controller.abort()
  }, [resolve])

  // A session expires on the daemon's clock (12 h absolute, §13.3) or is
  // revoked from elsewhere, and the live socket cannot report either: a browser
  // sees a refused upgrade as an indistinguishable close. So the app asks.
  //
  // Only a 401 signs the user out. A daemon that restarts, or a laptop that
  // sleeps through a lost connection, must not throw away a valid session and
  // make someone type their password because of a two-second blip: the 401
  // event above already covers the case where the daemon actually says no.
  useEffect(() => {
    const timer = setInterval(() => {
      fetchSession()
        .then(setSession)
        .catch((err: unknown) => {
          if (err instanceof UnauthorizedError) setSession(null)
        })
    }, revalidateInterval)
    return () => clearInterval(timer)
  }, [])

  // A 401 from anywhere returns the whole app to the login screen. Cached data
  // is dropped with it: it belongs to a session that no longer exists, and
  // leaving it on screen behind a login form is how one user's data ends up in
  // front of the next one.
  useEffect(() => {
    const onUnauthorized = () => {
      setSession(null)
      queryClient.clear()
      resetLiveSocket()
    }
    window.addEventListener(unauthorizedEvent, onUnauthorized)
    return () => window.removeEventListener(unauthorizedEvent, onUnauthorized)
  }, [queryClient])

  const signIn = useCallback(
    (next: Session) => {
      setSession(next)
      // The socket was refused while signed out; drop it so the next
      // subscription dials again with the cookie now set.
      resetLiveSocket()
      void queryClient.invalidateQueries()
    },
    [queryClient],
  )

  const signOut = useCallback(async () => {
    try {
      await logout(session?.csrf)
    } finally {
      // Whatever the daemon said, this browser is done: a logout that failed
      // must not leave someone looking at a signed-in screen.
      setSession(null)
      queryClient.clear()
      resetLiveSocket()
    }
  }, [queryClient, session?.csrf])

  const value = useMemo<SessionState>(
    () => ({ session, loading, csrf: session?.csrf, signIn, signOut }),
    [session, loading, signIn, signOut],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
