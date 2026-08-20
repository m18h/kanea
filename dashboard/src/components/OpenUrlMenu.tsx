import { useEffect, useRef, useState } from 'react'
import { ChevronDown, ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'

/**
 * OpenUrlMenu offers a service's public addresses.
 *
 * One address is a plain link button; several are a dropdown, because a menu
 * that always holds exactly one item is chrome standing between a reader and
 * the thing they wanted. The caller renders nothing at all for none.
 *
 * Deliberately not a general dropdown primitive. This app had no menu at all
 * before, and a reusable one is a set of promises about keyboard behaviour
 * (roving focus, typeahead, arrow keys) that this needs none of. What it is
 * instead: a disclosure holding real links, so Tab already walks them, Enter
 * already follows them, and the only behaviour written by hand is closing —
 * on Escape, on an outside press, and on choosing something.
 *
 * For the same reason it carries `aria-expanded` but not `role="menu"`:
 * claiming menu semantics would promise the arrow-key navigation a real menu
 * has, and a list of links reached by Tab is the honest description.
 */
export function OpenUrlMenu({ urls }: { urls: string[] }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    // mousedown rather than click: a click that lands outside should close
    // this before anything it hits gets to act.
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

  if (urls.length === 0) return null

  // rel="noopener noreferrer" on every link: a target=_blank link without it
  // hands the opened page a handle on this one.
  if (urls.length === 1) {
    const only = urls[0] as string
    return (
      <a href={only} target="_blank" rel="noopener noreferrer">
        <Button size="sm" variant="outline" title={`Open ${only} in a new tab`}>
          <ExternalLink size={14} />
          Open
        </Button>
      </a>
    )
  }

  return (
    <div className="relative" ref={ref}>
      <Button
        size="sm"
        variant="outline"
        aria-expanded={open}
        title={`${urls.length} public addresses`}
        onClick={() => setOpen((v) => !v)}
      >
        <ExternalLink size={14} />
        Open
        <ChevronDown size={14} className={open ? 'rotate-180 transition-transform' : 'transition-transform'} />
      </Button>
      {open ? (
        <div
          className="absolute right-0 z-20 mt-1 min-w-64 overflow-hidden rounded-md border bg-card p-1 shadow-lg"
          aria-label="Public addresses"
        >
          {urls.map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setOpen(false)}
              className="block truncate rounded px-2 py-1.5 text-left font-mono text-xs hover:bg-muted focus-visible:bg-muted focus-visible:outline-none"
            >
              {url}
            </a>
          ))}
        </div>
      ) : null}
    </div>
  )
}
