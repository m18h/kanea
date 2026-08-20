import { useEffect, useRef, useState } from 'react'
import { liveSocket } from '@/lib/live'
import { Topic, logBatchSchema, type LogLine } from '@/lib/api'

/**
 * MaxLogLines bounds what a tab holds.
 *
 * A dashboard left open on a chatty service would otherwise grow without limit:
 * the daemon streams as fast as the workload writes, and the browser has
 * nowhere to put it. Dropping the oldest is the same trade §17 makes for the
 * log pipeline: recent output is what anyone is looking at. Ten thousand
 * because the viewer virtualizes: render cost is the viewport's, so the
 * buffer's price is memory alone.
 */
export const MaxLogLines = 10_000

export interface LogState {
  lines: LogLine[]
  error: string | null
  /** dropped counts lines discarded here to stay within MaxLogLines. */
  dropped: number
  /**
   * droppedByDaemon counts lines the node never sent; trimmed by its per-frame
   * cap, clamped off an oversized tail, or lost with a frame a full send buffer
   * refused (PRD v1.70).
   *
   * Deliberately separate from `dropped`: they are different facts about
   * different ends of the pipe, and collapsing them would report a node under
   * pressure as a browser running out of buffer.
   */
  droppedByDaemon: number
}

/**
 * useLiveLog follows one service's logs over the shared socket.
 *
 * `container` names an init container (R32) to follow instead of the task, by
 * its block name; empty follows the task. It is part of the subscription key
 * server-side, because it selects a different stream rather than more of the
 * same one, so switching steps opens a new feed rather than replacing a wanted
 * one.
 */
export function useLiveLog(project: string, service: string, tail = 200, container = ''): LogState {
  const [state, setState] = useState<LogState>({
    lines: [],
    error: null,
    dropped: 0,
    droppedByDaemon: 0,
  })

  // Buffered between renders: a busy service can emit hundreds of lines a
  // second, and a setState per line would re-render the page just as often.
  const pending = useRef<LogLine[]>([])
  // Accumulated on the same schedule, for the same reason.
  const pendingDaemonDrops = useRef(0)

  useEffect(() => {
    // A new subscription target is a new log: the reset belongs with the
    // subscribe it precedes, not in a second effect racing this one.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setState({ lines: [], error: null, dropped: 0, droppedByDaemon: 0 })
    pending.current = []
    pendingDaemonDrops.current = 0

    const unsubscribe = liveSocket().subscribe(
      { topic: Topic.Logs, project, service, tail, container },
      (frame) => {
        if (frame.type === 'error') {
          setState((prev) => ({ ...prev, error: frame.error ?? 'unknown error' }))
          return
        }
        if (frame.type !== 'data') return

        // One frame is a tick's worth of lines, not one line (PRD v1.70).
        const parsed = logBatchSchema.safeParse(frame.data)
        if (!parsed.success) return
        pending.current.push(...(parsed.data.lines ?? []))
        pendingDaemonDrops.current += parsed.data.dropped ?? 0
      },
    )

    const flush = setInterval(() => {
      const daemonDrops = pendingDaemonDrops.current
      if (pending.current.length === 0 && daemonDrops === 0) return
      const batch = pending.current
      pending.current = []
      pendingDaemonDrops.current = 0

      setState((prev) => {
        const droppedByDaemon = prev.droppedByDaemon + daemonDrops
        const combined = [...prev.lines, ...batch]
        if (combined.length <= MaxLogLines) {
          return { ...prev, lines: combined, droppedByDaemon }
        }
        const overflow = combined.length - MaxLogLines
        return {
          ...prev,
          lines: combined.slice(overflow),
          dropped: prev.dropped + overflow,
          droppedByDaemon,
        }
      })
    }, flushInterval)

    return () => {
      unsubscribe()
      clearInterval(flush)
    }
  }, [project, service, tail, container])

  return state
}

/** flushInterval is a render budget, not a latency budget: ~7 renders a second
 * is smooth to read and cheap enough for a page that may also be charting. */
const flushInterval = 150
