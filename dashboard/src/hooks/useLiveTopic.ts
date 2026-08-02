import { useEffect, useState } from 'react'
import type { z } from 'zod'
import { liveSocket } from '@/lib/live'
import type { SubscribeRequest } from '@/lib/api'

export interface LiveState<T> {
  data: T | null
  error: string | null
  /** connected is false until the first frame arrives. */
  connected: boolean
}

/**
 * useLiveTopic subscribes to one topic and returns the latest payload.
 *
 * The payload is validated against the caller's schema rather than cast: a
 * daemon that changed shape should surface as a visible error on one panel, not
 * as an undefined-property crash somewhere else.
 */
export function useLiveTopic<S extends z.ZodTypeAny>(
  req: SubscribeRequest,
  schema: S,
): LiveState<z.infer<S>> {
  const [state, setState] = useState<LiveState<z.infer<S>>>({
    data: null,
    error: null,
    connected: false,
  })

  const { topic, project, service, tail } = req

  useEffect(() => {
    const request: SubscribeRequest = { topic }
    if (project !== undefined) request.project = project
    if (service !== undefined) request.service = service
    if (tail !== undefined) request.tail = tail

    return liveSocket().subscribe(request, (frame) => {
      if (frame.type === 'error') {
        setState({ data: null, error: frame.error ?? 'unknown error', connected: true })
        return
      }
      if (frame.type !== 'data') return

      const parsed = schema.safeParse(frame.data) as z.SafeParseReturnType<unknown, z.infer<S>>
      if (!parsed.success) {
        setState({ data: null, error: 'unexpected payload from the daemon', connected: true })
        return
      }
      setState({ data: parsed.data, error: null, connected: true })
    })
    // schema is a module-level constant at every call site; including it would
    // resubscribe on every render for callers that build it inline.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topic, project, service, tail])

  return state
}
