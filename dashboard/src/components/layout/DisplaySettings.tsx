import { useEffect, useId, useRef, useState } from 'react'
import { Settings } from 'lucide-react'

import { Select } from '@/components/ui/select'
import { useDateStyle } from '@/hooks/useDateStyle'
import { DateStyles, type DateStyle, setDateStyle } from '@/lib/datetime'

/**
 * DisplaySettings is the sidebar's cog: how this browser renders the app.
 *
 * What is inside it is a property of whoever is looking rather than of the
 * node - it lives in localStorage, reaches no API, and appears in no audit
 * line - which is also why it is here rather than on the Settings page,
 * which is admin-only at the daemon and would hide it from a viewer. The
 * dark-mode toggle lived here until v1.108; it is an icon beside the version
 * now, and the cog keeps the date format, which needs a label rather than an
 * icon because no icon says which of three orders is in force.
 *
 * It is a **disclosure holding form controls, not a menu**, and carries
 * `aria-expanded` without `role="menu"` for OpenUrlMenu's reason: menu
 * semantics promise arrow-key navigation, and a switch and a select reached by
 * Tab is the honest description. Closing is the only behaviour written by
 * hand - Escape, an outside press - plus returning focus to the cog, because a
 * panel that closes and drops focus to the document leaves a keyboard user at
 * the top of the page.
 */
export function DisplaySettings() {
  const [open, setOpen] = useState(false)
  const style = useDateStyle()
  const ref = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const dateId = useId()

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        trigger.current?.focus()
      }
    }
    // mousedown rather than click: a press that lands outside should close
    // this before whatever it hits gets to act.
    const onDown = (e: MouseEvent) => {
      if (ref.current && e.target instanceof Node && !ref.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onDown)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onDown)
    }
  }, [open])

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        ref={trigger}
        aria-expanded={open}
        aria-label="Display settings"
        title="Display settings"
        className="rounded-md p-1.5 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
        onClick={() => setOpen((v) => !v)}
      >
        <Settings size={15} />
      </button>
      {open ? (
        // Two constraints, both from where this lives rather than from taste.
        // It opens **upward** because it sits in the sidebar's last row. And it
        // is narrow enough to fit **inside the sidebar**: the panel is anchored
        // to the cog, whose right edge is short of the sidebar's by the width
        // of the sign-out button beside it, so anything wider than about 180px
        // runs off the left of the viewport and is simply cut off - which is
        // what a 240px panel did. The sidebar is 230px in both the desktop rail
        // and the mobile drawer, so one width is correct in both.
        <div
          className="absolute bottom-full right-0 z-20 mb-1 w-44 rounded-md border bg-card p-3 shadow-lg"
          aria-label="Display settings"
        >
          <p className="mb-2 text-xs font-medium text-muted-foreground">Display</p>

          <div className="py-1.5">
            <label htmlFor={dateId} className="mb-1 block text-sm">
              Date format
            </label>
            <Select
              id={dateId}
              value={style}
              onChange={(e) => setDateStyle(e.target.value as DateStyle)}
              className="h-8 font-mono text-xs"
            >
              {DateStyles.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </Select>
          </div>

          {/* The setting is per browser and nowhere else, which is worth
              saying: somebody changing it on one machine should not wonder
              why another did not follow. */}
          <p className="mt-2 text-[11px] leading-snug text-muted-foreground">
            Stored in this browser only.
          </p>
        </div>
      ) : null}
    </div>
  )
}
