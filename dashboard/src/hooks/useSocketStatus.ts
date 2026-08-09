import { useSyncExternalStore } from 'react'
import { liveSocket } from '@/lib/live'

/**
 * useSocketStatus reports whether the page's shared live socket is open.
 *
 * The sidebar holds a services subscription for its counts, so while anyone is
 * signed in the socket has a reason to be open — which is what makes the
 * indicator a fact about connectivity rather than about idleness.
 */
export function useSocketStatus(): boolean {
  return useSyncExternalStore(
    (onChange) => liveSocket().onStatus(() => onChange()),
    () => liveSocket().connected,
  )
}
