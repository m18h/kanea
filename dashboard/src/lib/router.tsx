import { useRouter } from '@/hooks/useRouter'
import { RouterContext } from '@/lib/router-context'
import { useCallback, useEffect, useMemo, useState } from 'react'

/**
 * A minimal client-side router.
 *
 * Hand-written rather than depending on react-router, which is not a decision
 * about wheel-reinvention: every published version carries open high-severity
 * advisories, and `npm audit --audit-level=high` is a release gate (AGENTS.md
 * constraint #7), not a judgement call. Almost all of those advisories are in
 * SSR, RSC and framework-mode features this dashboard does not use, but a
 * dependency cannot be partially adopted, and the gate cannot be waived.
 *
 * What the dashboard actually needs is small: the current path, a way to
 * navigate without a reload, and one dynamic segment. That is this file.
 */

export function Router({ children }: { children: React.ReactNode }) {
  const [path, setPath] = useState(() => window.location.pathname)
  // Two states rather than one object: each bails out of a re-render on its
  // own, so going back to the same path with a different query re-renders the
  // pages that read the query and nothing else.
  const [search, setSearch] = useState(() => window.location.search)

  useEffect(() => {
    // Back and forward must work: a dashboard where the browser's own
    // navigation does nothing feels broken in a way people do not report.
    // Reading the query here is what restores a list's filters on the way
    // back: the history entry carries them, so the page does not have to.
    const onPop = () => {
      setPath(window.location.pathname)
      setSearch(window.location.search)
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  const navigate = useCallback((to: string, opts?: { replace?: boolean }) => {
    // Resolved once and handed to both: passing `to` to history would resolve
    // a relative target against the document base while this resolves it
    // against the origin, and the two disagree.
    const url = new URL(to, window.location.origin)
    try {
      if (opts?.replace) window.history.replaceState(null, '', url)
      else window.history.pushState(null, '', url)
    } catch {
      // History writes are rate-limited in some browsers. A filter that will
      // not apply because the address bar refused is worse than an address bar
      // that lags, so the state below moves either way.
    }
    setPath(url.pathname)
    setSearch(url.search)
  }, [])

  const value = useMemo(() => ({ path, search, navigate }), [path, search, navigate])
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

export interface LinkProps extends Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> {
  to: string
}

/**
 * Link navigates without a reload, while remaining a real anchor.
 *
 * Modified clicks fall through to the browser: middle-click and cmd-click must
 * still open a new tab, which is the behaviour an intercepting onClick quietly
 * breaks.
 */
export function Link({ to, onClick, ...props }: LinkProps) {
  const { navigate } = useRouter()

  return (
    <a
      href={to}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented) return
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
        if (event.button !== 0) return
        event.preventDefault()
        navigate(to)
      }}
      {...props}
    />
  )
}
