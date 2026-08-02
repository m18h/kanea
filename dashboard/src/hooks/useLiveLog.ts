import { useEffect, useRef, useState } from 'react'
import { liveSocket } from '@/lib/live'
import { Topic, logLineSchema, type LogLine } from '@/lib/api'

/**
 * MaxLogLines bounds what a tab holds.
 *
 * A dashboard left open on a chatty service would otherwise grow without limit
 * — the daemon streams as fast as the workload writes, and the browser has
 * nowhere to put it. Dropping the oldest is the same trade §17 makes for the
 * log pipeline: recent output is what anyone is looking at.
 */
export const MaxLogLines = 2000

export interface LogState {
  lines: LogLine[]
  error: string | null
  /** dropped counts lines discarded to stay within MaxLogLines. */
  dropped: number
}

/** useLiveLog follows one service's logs over the shared socket. */
export function useLiveLog(project: string, service: string, tail = 200): LogState {
  const [state, setState] = useState<LogState>({ lines: [], error: null, dropped: 0 })

  // Buffered between renders: a busy service can emit hundreds of lines a
  // second, and a setState per line would re-render the page just as often.
  const pending = useRef<LogLine[]>([])

  useEffect(() => {
    setState({ lines: [], error: null, dropped: 0 })
    pending.current = []

    const unsubscribe = liveSocket().subscribe(
      { topic: Topic.Logs, project, service, tail },
      (frame) => {
        if (frame.type === 'error') {
          setState((prev) => ({ ...prev, error: frame.error ?? 'unknown error' }))
          return
        }
        if (frame.type !== 'data') return

        const parsed = logLineSchema.safeParse(frame.data)
        if (!parsed.success) return
        pending.current.push(parsed.data)
      },
    )

    const flush = setInterval(() => {
      if (pending.current.length === 0) return
      const batch = pending.current
      pending.current = []

      setState((prev) => {
        const combined = [...prev.lines, ...batch]
        if (combined.length <= MaxLogLines) {
          return { ...prev, lines: combined }
        }
        const overflow = combined.length - MaxLogLines
        return {
          ...prev,
          lines: combined.slice(overflow),
          dropped: prev.dropped + overflow,
        }
      })
    }, flushInterval)

    return () => {
      unsubscribe()
      clearInterval(flush)
    }
  }, [project, service, tail])

  return state
}

/** flushInterval is a render budget, not a latency budget: ~7 renders a second
 * is smooth to read and cheap enough for a page that may also be charting. */
const flushInterval = 150
