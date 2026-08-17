import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Check, Copy, Download, Maximize2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { cn } from '@/lib/utils'

export interface LogViewerLine {
  key: string
  /** prefix is the muted-amber column before the text; an alloc name. */
  prefix?: string | undefined
  text: string
}

export interface LogViewerProps {
  lines: LogViewerLine[]
  /** live styles the newest line as in-progress and keeps the tail followed. */
  live: boolean
  showLineNumbers?: boolean | undefined
  /** follow keeps the view at the tail (the checkbox on the service page).
   * undefined means pinned-scroll only. */
  follow?: boolean | undefined
  /** onFollowChange reports that the reader's own scrolling changed whether the
   * view is at the tail, so the caller's checkbox can say what is true. Without
   * it a `follow` of true would override the reader forever. */
  onFollowChange?: ((follow: boolean) => void) | undefined
  notice?: React.ReactNode | undefined
  emptyText: string
  /** heightClass fixes the box's size; the viewer never grows with its
   * content, so a filling buffer cannot push the page around. */
  heightClass?: string | undefined
  /** toolbar adds actions over the whole buffer. `expand` opens the viewer in
   * a full-screen dialog, closable with the X, the backdrop or Escape. */
  toolbar?: { copy?: boolean; download?: { filename: string }; expand?: boolean } | undefined
  /** title heads the expanded dialog. Ignored inline, where the surrounding
   * card already says what this is. */
  title?: React.ReactNode | undefined
  /** controls are the caller's own filter/follow inputs. They are rendered
   * again inside the dialog so they stay reachable full screen: the page's
   * copies are behind the backdrop, so nothing is visibly duplicated. Keep
   * them controlled by the caller's state and both copies stay in step. */
  controls?: React.ReactNode | undefined
  /** tintSeverity colors lines matching error/warn heuristics. Text nodes
   * only: the classification reads the text, it never interprets it. */
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
 * broke the build is the one thing a live log must not do.
 *
 * `follow` used to short-circuit that check: `follow || (live && pinned)`;
 * and the service page passes a `follow` that defaults to true and had nothing
 * to turn it off, so the detection was dead code on the one page that used it
 * and scrolling up snapped straight back. The reader's gesture now *drives*
 * `follow` through onFollowChange instead of being overridden by it.
 */
export function LogViewer({
  lines,
  live,
  showLineNumbers,
  follow,
  onFollowChange,
  notice,
  emptyText,
  heightClass,
  toolbar,
  tintSeverity,
  title,
  controls,
}: LogViewerProps) {
  const ref = useRef<HTMLDivElement>(null)
  const pinned = useRef(true)
  const [copied, setCopied] = useState(false)
  const [expanded, setExpanded] = useState(false)
  // The row the reader was looking at when they expanded or collapsed. Moving
  // the viewer in or out of the dialog remounts its DOM, and a fresh scroll
  // container starts at the top, which is the *oldest* line in the buffer,
  // the least useful place to land.
  const anchorRow = useRef<number | null>(null)

  const virtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => ref.current,
    estimateSize: () => 20,
    overscan: 20,
    // Measure immediately, then let ResizeObserver keep it current. The
    // default waits for the observer's first callback, which leaves the first
    // paint empty, and never comes at all where ResizeObserver is missing
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

  // The last line's identity, not the count: at MaxLogLines the buffer
  // saturates and the length stops changing, so a length dependency silently
  // stops following on exactly the busy service someone is watching. A filter
  // whose match count happens to hold steady does the same.
  const tailKey = lines.length > 0 ? lines[lines.length - 1]?.key : undefined

  useEffect(() => {
    if (lines.length === 0) return
    // follow is a request to be at the tail; pinned is where the reader is. An
    // explicit follow={false} is the reader having scrolled away, so it wins.
    if (follow === false || !(follow || (live && pinned.current))) return
    virtualizer.scrollToIndex(lines.length - 1, { align: 'end' })
    // The virtualizer is a stable instance; scrolling reacts to content, not
    // to it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tailKey, lines.length, live, follow])

  // Restore the reader's place across the remount that expanding or collapsing
  // causes. `pinned` is a ref on this component, which does not itself
  // unmount, so following survives the move on its own: only the scroll
  // position is lost with the old DOM node, and it comes back by row index
  // rather than by pixels, because the box is a different height on each side.
  useLayoutEffect(() => {
    if (lines.length === 0) return
    if (pinned.current) {
      virtualizer.scrollToIndex(lines.length - 1, { align: 'end' })
    } else if (anchorRow.current !== null) {
      virtualizer.scrollToIndex(anchorRow.current, { align: 'start' })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expanded])

  const toggleExpanded = () => {
    anchorRow.current = virtualizer.getVirtualItems()[0]?.index ?? null
    setExpanded((open) => !open)
  }

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

  // Expand stays available on an empty buffer: "waiting for output" is a
  // thing people watch, and the other two actions have nothing to act on.
  const hasActions = toolbar && (toolbar.copy || toolbar.download) && lines.length > 0
  const hasToolbar = hasActions || toolbar?.expand

  const body = (
    <div className={cn('relative', expanded && 'flex h-full flex-col')}>
      {notice}
      {hasToolbar ? (
        <div className="absolute right-2 top-2 z-10 flex gap-1">
          {hasActions && toolbar?.copy ? (
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
          {hasActions && toolbar?.download ? (
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
          {/* Only offered from the inline view. Inside the dialog the X, the
              backdrop and Escape all close it, and a third control that looks
              like a window button next to them reads as "make it bigger
              still". */}
          {toolbar?.expand && !expanded ? (
            <Button
              size="sm"
              variant="outline"
              className="h-7 gap-1.5 bg-card/80 px-2 text-xs backdrop-blur"
              onClick={toggleExpanded}
              aria-label="Expand log"
            >
              <Maximize2 size={13} />
              Expand
            </Button>
          ) : null}
        </div>
      ) : null}
      <div
        ref={ref}
        onScroll={(event) => {
          const el = event.currentTarget
          // A small slack: a scroll position is rarely exactly at the end.
          const atTail = el.scrollHeight - el.scrollTop - el.clientHeight < 24
          // Only a *change* is reported, which is also what makes this safe
          // against the scroll events our own scrollToIndex causes: that lands
          // at the tail, where pinned already is, so it says nothing. A flag
          // guarding the programmatic scroll instead would stay armed whenever
          // the scroll moved nothing (already at the bottom) and swallow the
          // reader's next real gesture.
          if (atTail === pinned.current) return
          pinned.current = atTail
          onFollowChange?.(atTail)
        }}
        className={cn(
          'overflow-auto rounded-md bg-muted/40 p-2.5 font-mono text-xs leading-relaxed',
          // Expanded, the box takes whatever the dialog gives it rather than a
          // fixed height. min-h-0 is what lets a flex child actually shrink and
          // scroll instead of growing its parent past the viewport.
          expanded ? 'min-h-0 flex-1' : heightClass ?? 'h-96',
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

  if (!expanded) return body

  return (
    <>
      {/* The viewer itself has moved into the dialog, so the card would
          otherwise collapse to nothing and the page behind the backdrop would
          reflow: visible as a jump the moment it closes. This holds the
          space. */}
      <div className={cn('rounded-md bg-muted/40', heightClass ?? 'h-96')} aria-hidden />
      <Dialog
        open
        onClose={toggleExpanded}
        title={title ?? 'Logs'}
        className="h-[90vh] w-[95vw] max-w-none"
      >
        <div className="flex h-full flex-col gap-2">
          {controls ? <div className="flex items-center justify-end gap-2">{controls}</div> : null}
          <div className="min-h-0 flex-1">{body}</div>
        </div>
      </Dialog>
    </>
  )
}
