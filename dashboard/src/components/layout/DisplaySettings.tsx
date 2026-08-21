import { useEffect, useId, useRef, useState } from 'react'
import { Settings } from 'lucide-react'

import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useDateStyle } from '@/hooks/useDateStyle'
import { useTheme } from '@/hooks/useTheme'
import { DateStyles, type DateStyle, setDateStyle } from '@/lib/datetime'

/**
 * DisplaySettings is the sidebar's cog: how this browser renders the app.
 *
 * Both settings inside it are properties of whoever is looking rather than of
 * the node - they live in localStorage, they reach no API, and they appear in
 * no audit line - which is also why they are here rather than on the Settings
 * page, which is admin-only at the daemon and would hide them from a viewer.
 *
 * Gathering them behind one control rather than lining them up in the footer
 * is what makes room for a third: two icon buttons were already competing with
 * sign-out for a strip about a hundred pixels wide, and a date format needed a
 * label rather than an icon because no icon says which of three orders is in
 * force.
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
  const [theme, setTheme] = useTheme()
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

          <div className="flex items-center justify-between gap-3 py-1.5">
            {/* A span, not a label: Switch renders a button and takes no id,
                so an htmlFor here would point at nothing. The control carries
                its own aria-label, which is what a screen reader reads. */}
            <span className="text-sm">Dark mode</span>
            <Switch
              checked={theme === 'dark'}
              onCheckedChange={(on) => setTheme(on ? 'dark' : 'light')}
              aria-label="Dark mode"
            />
          </div>

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
