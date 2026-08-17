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

  useEffect(() => {
    // Back and forward must work: a dashboard where the browser's own
    // navigation does nothing feels broken in a way people do not report.
    const onPop = () => setPath(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  const navigate = useCallback((to: string) => {
    window.history.pushState(null, '', to)
    setPath(new URL(to, window.location.origin).pathname)
  }, [])

  const value = useMemo(() => ({ path, navigate }), [path, navigate])
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
