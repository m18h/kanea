import { useEffect, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Check, Copy, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
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
  /** toolbar adds copy/download actions over the whole buffer. */
  toolbar?: { copy?: boolean; download?: { filename: string } } | undefined
  /** tintSeverity colors lines matching error/warn heuristics. Text nodes
   * only — the classification reads the text, it never interprets it. */
  tintSeverity?: boolean | undefined
}

/**
 * lineSeverity classifies a log line for tinting. A heuristic, stated as one:
 * it reads common severity words, not a format, so a false negative is normal
 * and a line's content is never parsed beyond this test.
 */
export function lineSeverity(text: string): 'error' | 'warn' | null {
  if (/\b(error|err|fatal|panic|failed)\b/i.test(text)) return 'error'
  if (/\bwarn(ing)?\b/i.test(text)) return 'warn'
  return null
}

/** flatten renders the buffer back to text for copy and download. */
function flatten(lines: LogViewerLine[]): string {
  return lines
    .map((l) => (l.prefix !== undefined ? `${l.prefix} ${l.text}` : l.text))
    .join('\n')
}

/**
 * LogViewer renders a log tail, service or build alike.
 *
 * Rows are virtualized: the buffer may hold ten thousand wrapped lines, and
 * only the viewport's worth exists in the DOM. Heights vary (lines wrap), so
 * rows measure themselves and the virtualizer keeps the scroll math honest.
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
  toolbar,
  tintSeverity,
}: LogViewerProps) {
  const ref = useRef<HTMLDivElement>(null)
  const pinned = useRef(true)
  const [copied, setCopied] = useState(false)

  const virtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => ref.current,
    estimateSize: () => 20,
    overscan: 20,
    // Measure immediately, then let ResizeObserver keep it current. The
    // default waits for the observer's first callback, which leaves the first
    // paint empty — and never comes at all where ResizeObserver is missing
    // (jsdom). The fallback height is max-h-96 (384px), the container's own
    // default.
    observeElementRect: (instance, cb) => {
      const el = instance.scrollElement
      if (!el) return
      const report = () => {
        const rect = el.getBoundingClientRect()
        cb({
          width: rect.width || el.clientWidth || 800,
          height: rect.height || el.clientHeight || 384,
        })
      }
      report()
      if (typeof ResizeObserver === 'undefined') return
      const observer = new ResizeObserver(report)
      observer.observe(el)
      return () => observer.disconnect()
    },
  })

  useEffect(() => {
    if (lines.length === 0) return
    if (follow || (live && pinned.current)) {
      virtualizer.scrollToIndex(lines.length - 1, { align: 'end' })
    }
    // The virtualizer is a stable instance; scrolling reacts to content, not
    // to it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lines.length, live, follow])

  useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), 1_500)
    return () => clearTimeout(timer)
  }, [copied])

  const copyAll = () => {
    void navigator.clipboard.writeText(flatten(lines)).then(() => setCopied(true))
  }

  const downloadAll = (filename: string) => {
    const blob = new Blob([flatten(lines) + '\n'], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const hasToolbar = toolbar && (toolbar.copy || toolbar.download) && lines.length > 0

  return (
    <div className="relative">
      {notice}
      {hasToolbar ? (
        <div className="absolute right-2 top-2 z-10 flex gap-1">
          {toolbar.copy ? (
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1.5 bg-card/80 px-2 text-xs backdrop-blur"
              onClick={copyAll}
              aria-label="Copy log"
            >
              {copied ? <Check size={13} /> : <Copy size={13} />}
              {copied ? 'Copied' : 'Copy'}
            </Button>
          ) : null}
          {toolbar.download ? (
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1.5 bg-card/80 px-2 text-xs backdrop-blur"
              onClick={() => downloadAll(toolbar.download!.filename)}
              aria-label="Download log"
            >
              <Download size={13} />
              Download
            </Button>
          ) : null}
        </div>
      ) : null}
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
          <div
            style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}
          >
            {virtualizer.getVirtualItems().map((item) => {
              const entry = lines[item.index]
              if (!entry) return null
              const isTail = live && item.index === lines.length - 1
              const severity = tintSeverity && !isTail ? lineSeverity(entry.text) : null
              return (
                // Log output is attacker-controlled whenever the workload is.
                // Everything here is a text child, never markup (PRD §14, A03).
                <div
                  key={entry.key}
                  data-index={item.index}
                  // A zero-height measurement is a row that has not laid out
                  // (jsdom always, browsers never once painted); feeding it to
                  // the virtualizer would fight the estimate forever.
                  ref={(el) => {
                    if (el && el.getBoundingClientRect().height > 0) {
                      virtualizer.measureElement(el)
                    }
                  }}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    transform: `translateY(${item.start}px)`,
                  }}
                  className={cn(
                    'flex whitespace-pre-wrap break-all',
                    isTail && 'text-primary',
                    severity === 'error' && 'text-status-error',
                    severity === 'warn' && 'text-status-warn',
                  )}
                >
                  {showLineNumbers ? (
                    <span className="mr-3 w-8 shrink-0 select-none text-right text-muted-foreground/60">
                      {item.index + 1}
                    </span>
                  ) : null}
                  {entry.prefix !== undefined ? (
                    <span className="mr-2 shrink-0 text-primary/80">{entry.prefix}</span>
                  ) : null}
                  <span className="min-w-0">{entry.text}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
