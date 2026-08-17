import { useEffect, useState } from 'react'
import type { z } from 'zod'
import { liveSocket } from '@/lib/live'
import type { SubscribeRequest } from '@/lib/api'

export interface LiveState<T> {
  data: T | null
  error: string | null
  /**
   * connected means a frame has arrived on the *current* connection; it
   * resets to false when the transport drops. "We have data and it is
   * current" is the question pages actually ask; a flag that stayed true
   * across a reconnect gap made a missing service look deliberately absent.
   */
  connected: boolean
  /** up is the transport alone: the socket is open right now. */
  up: boolean
}

/**
 * useLiveTopic subscribes to one topic and returns the latest payload.
 *
 * The payload is validated against the caller's schema rather than cast: a
 * daemon that changed shape should surface as a visible error on one panel, not
 * as an undefined-property crash somewhere else.
 *
 * data survives a disconnect on purpose: stale beats blank while the socket
 * reconnects; `connected` is what says whether to trust it as current.
 */
export function useLiveTopic<S extends z.ZodTypeAny>(
  req: SubscribeRequest,
  schema: S,
): LiveState<z.infer<S>> {
  const [state, setState] = useState<LiveState<z.infer<S>>>(() => ({
    data: null,
    error: null,
    connected: false,
    up: liveSocket().connected,
  }))

  const { topic, project, service, tail } = req

  useEffect(() => {
    const request: SubscribeRequest = { topic }
    if (project !== undefined) request.project = project
    if (service !== undefined) request.service = service
    if (tail !== undefined) request.tail = tail

    const socket = liveSocket()
    const unsubscribeStatus = socket.onStatus((up) => {
      if (up) {
        setState((s) => ({ ...s, up: true }))
      } else {
        // The connection died: whatever we hold is stale until a frame
        // arrives on the next one. The data itself is kept.
        setState((s) => ({ ...s, up: false, connected: false }))
      }
    })
    const unsubscribe = socket.subscribe(request, (frame) => {
      if (frame.type === 'error') {
        setState((s) => ({ ...s, data: null, error: frame.error ?? 'unknown error', connected: true }))
        return
      }
      if (frame.type !== 'data') return

      const parsed = schema.safeParse(frame.data) as z.SafeParseReturnType<unknown, z.infer<S>>
      if (!parsed.success) {
        setState((s) => ({
          ...s,
          data: null,
          error: 'unexpected payload from the daemon',
          connected: true,
        }))
        return
      }
      setState((s) => ({ ...s, data: parsed.data, error: null, connected: true }))
    })
    return () => {
      unsubscribe()
      unsubscribeStatus()
    }
    // schema is a module-level constant at every call site; including it would
    // resubscribe on every render for callers that build it inline.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topic, project, service, tail])

  return state
}
