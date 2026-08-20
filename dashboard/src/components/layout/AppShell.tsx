import { useState } from 'react'
import { Menu, X } from 'lucide-react'
import { Mark } from '@/components/Mark'
import { Sidebar } from '@/components/layout/Sidebar'
import { useRouter } from '@/hooks/useRouter'

/**
 * AppShell is the signed-in frame: fixed sidebar, independently scrolling
 * main column, and a content area that is fluid rather than boxed. Below md
 * the sidebar becomes an overlay drawer behind a top bar, closed again on
 * every navigation.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const { path } = useRouter()
  // The drawer records which path it was opened on, so navigating anywhere
  // closes it without an effect: a stale path is a closed drawer.
  const [openedOn, setOpenedOn] = useState<string | null>(null)
  const open = openedOn === path
  const setOpen = (next: boolean) => setOpenedOn(next ? path : null)

  return (
    <div className="flex h-screen bg-background">
      <Sidebar className="hidden md:flex" />

      {open ? (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <Sidebar className="h-full" />
          <button
            type="button"
            aria-label="Close navigation"
            className="flex-1 bg-background/60 backdrop-blur-sm"
            onClick={() => setOpen(false)}
          />
        </div>
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2 border-b px-4 py-2.5 md:hidden">
          <button
            type="button"
            aria-label={open ? 'Close navigation' : 'Open navigation'}
            className="rounded-md p-1.5 hover:bg-muted"
            onClick={() => setOpen(!open)}
          >
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
          <Mark size={20} />
          <span className="text-sm font-semibold">kanea</span>
        </div>

        {/* Fluid, not boxed: the content column fills the width the sidebar
            leaves it, with a gutter that grows a little on large screens
            rather than a centred column with empty margins. What this page
            shows is tables, allocation rows and time-series charts, and every
            one of them is worth more width — a max-width would spend a 32"
            monitor on whitespace. The charts follow, because UPlotChart sizes
            itself from a ResizeObserver rather than from a fixed pixel width. */}
        <main className="flex-1 overflow-y-auto">
          <div className="space-y-4 px-4 py-6 md:px-6 md:py-8 xl:px-8">{children}</div>
        </main>
      </div>
    </div>
  )
}
