import { createContext } from 'react'
import type { Session } from '@/lib/session'

export interface SessionState {
  /** session is null while nobody is authenticated. */
  session: Session | null
  /** loading is true only on the first resolution, so the app does not flash
   * the login form at someone who is already signed in. */
  loading: boolean
  /** csrf is the token every mutating request must carry (PRD §13.3). */
  csrf: string | undefined
  signIn: (session: Session) => void
  signOut: () => Promise<void>
}

/**
 * The session context, in its own module.
 *
 * Same reason as the router's: a module that exports both a context and
 * components breaks fast refresh, and every consumer remounts on each edit.
 */
export const SessionContext = createContext<SessionState | null>(null)
