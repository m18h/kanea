import { useContext } from 'react'
import { SessionContext, type SessionState } from '@/lib/session-context'

/** useSession exposes the authenticated caller and how to end the session. */
export function useSession(): SessionState {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error('useSession must be used inside a SessionProvider')
  return ctx
}
