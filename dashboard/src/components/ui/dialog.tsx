import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface DialogProps {
  open: boolean
  onClose: () => void
  title?: React.ReactNode
  /** dismiss on backdrop click and Escape; the terminal passes false so a
   * stray click cannot kill a shell; only the X button closes it. */
  dismissable?: boolean
  /** className sizes the panel, e.g. 'w-[90vw] max-w-4xl'. */
  className?: string | undefined
  children: React.ReactNode
}

/**
 * Dialog is the one modal primitive: portal, backdrop, focus capture and
 * return, body scroll lock. Deliberately small (no stacking, no nesting,
 * no animation machinery) because one dialog at a time is all this app has
 * a use for.
 */
export function Dialog({ open, onClose, title, dismissable = true, className, children }: DialogProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const restoreRef = useRef<Element | null>(null)

  // onClose is almost always an inline arrow at the call site, so its
  // identity changes on every parent render. The capture effect below must
  // depend on `open` alone: re-running it steals focus from the dialog's
  // content back to the panel (the exec terminal loses its cursor on every
  // live-stats frame). Escape reads the latest props through these refs.
  const onCloseRef = useRef(onClose)
  const dismissableRef = useRef(dismissable)
  useEffect(() => {
    onCloseRef.current = onClose
    dismissableRef.current = dismissable
  })

  useEffect(() => {
    if (!open) return
    restoreRef.current = document.activeElement
    panelRef.current?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && dismissableRef.current) onCloseRef.current()
    }
    document.addEventListener('keydown', onKey)
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = previous
      if (restoreRef.current instanceof HTMLElement) restoreRef.current.focus()
    }
  }, [open])

  if (!open) return null

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="presentation"
      onMouseDown={(e) => {
        if (dismissable && e.target === e.currentTarget) onClose()
      }}
    >
      <div aria-hidden className="absolute inset-0 bg-black/50" />
      {/* A plain div with the Card look: Card is not forwardRef, and the
          panel needs a ref for focus capture. */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        className={cn(
          'relative z-10 flex max-h-[90vh] flex-col rounded-lg border bg-card p-4 text-card-foreground shadow-lg outline-none',
          className,
        )}
      >
        <div className="mb-3 flex items-center justify-between gap-4">
          <h2 className="min-w-0 truncate text-sm font-semibold tracking-tight">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <X size={16} />
          </button>
        </div>
        <div className="min-h-0 flex-1">{children}</div>
      </div>
    </div>,
    document.body,
  )
}
