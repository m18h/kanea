import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

export interface LogViewerLine {
  key: string
  /** prefix is the muted-amber column before the text — an alloc name. */
  prefix?: string | undefined
  text: string
}

export interface LogViewerProps {
  lines: LogViewerLine[]
  /** live styles the newest line as in-progress and keeps the tail followed. */
  live: boolean
  showLineNumbers?: boolean | undefined
  /** follow forces pinning regardless of scroll position (the checkbox on the
   * service page). undefined means pinned-scroll only. */
  follow?: boolean | undefined
  notice?: React.ReactNode | undefined
  emptyText: string
  maxHeightClass?: string | undefined
}

/**
 * LogViewer renders a log tail, service or build alike.
 *
 * The scroll rule is the build log's: follow only when the reader is already
 * at the bottom. Yanking the view down while someone is reading the line that
 * broke the build is the one thing a live log must not do. The follow prop
 * (the service page's checkbox) forces pinning back on.
 */
export function LogViewer({
  lines,
  live,
  showLineNumbers,
  follow,
  notice,
  emptyText,
  maxHeightClass,
}: LogViewerProps) {
  const ref = useRef<HTMLDivElement>(null)
  const pinned = useRef(true)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (follow || (live && pinned.current)) el.scrollTop = el.scrollHeight
  }, [lines.length, live, follow])

  return (
    <div>
      {notice}
      <div
        ref={ref}
        onScroll={(event) => {
          const el = event.currentTarget
          // A small slack: a scroll position is rarely exactly at the end.
          pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
        }}
        className={cn(
          'overflow-auto rounded-md bg-muted/40 p-2.5 font-mono text-xs leading-relaxed',
          maxHeightClass ?? 'max-h-96',
        )}
      >
        {lines.length === 0 ? (
          <p className="text-muted-foreground">{emptyText}</p>
        ) : (
          lines.map((entry, i) => {
            const isTail = live && i === lines.length - 1
            return (
              // Log output is attacker-controlled whenever the workload is.
              // Everything here is a text child, never markup (PRD §14, A03).
              <div
                key={entry.key}
                className={cn('flex whitespace-pre-wrap break-all', isTail && 'text-primary')}
              >
                {showLineNumbers ? (
                  <span className="mr-3 w-8 shrink-0 select-none text-right text-muted-foreground/60">
                    {i + 1}
                  </span>
                ) : null}
                {entry.prefix !== undefined ? (
                  <span className="mr-2 shrink-0 text-primary/80">{entry.prefix}</span>
                ) : null}
                <span className="min-w-0">{entry.text}</span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
