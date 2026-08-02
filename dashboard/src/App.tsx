import { useEffect, useState } from 'react'
import { Link, Router } from '@/lib/router'
import { useRouter } from '@/hooks/useRouter'
import { isActive, matchPath } from '@/lib/paths'
import { useQuery } from '@tanstack/react-query'
import { LogOut, Moon, Sun } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Overview } from '@/pages/Overview'
import { Services } from '@/pages/Services'
import { ServiceDetail } from '@/pages/ServiceDetail'
import { Login } from '@/pages/Login'
import { fetchHealth } from '@/lib/api'
import { SessionProvider } from '@/lib/session-provider'
import { useSession } from '@/hooks/useSession'
import { cn } from '@/lib/utils'

const nav = [
  { to: '/', label: 'Overview', exact: true },
  { to: '/services', label: 'Services', exact: false },
]

export function App() {
  return (
    <SessionProvider>
      <Router>
        <Gate />
      </Router>
    </SessionProvider>
  )
}

/**
 * Gate decides between the app and the login screen.
 *
 * The daemon is the authority — every route behind this is deny-by-default —
 * so this is presentation, not enforcement. Skipping it would not expose data;
 * it would show an operator a screen full of 401s instead of a password field.
 */
function Gate() {
  const { session, loading } = useSession()

  if (loading) {
    // Deliberately blank rather than a spinner: the answer usually arrives in
    // a few milliseconds, and a flashed skeleton is worse than a still page.
    return <div className="min-h-screen bg-background" />
  }
  if (!session) return <Login />
  return <Shell />
}

function Shell() {
  const { path } = useRouter()
  const [theme, setTheme] = useTheme()
  const { session, signOut } = useSession()

  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 10_000,
  })

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="flex items-baseline gap-4">
            <span className="text-lg font-semibold tracking-tight">Kanea</span>
            <nav className="flex gap-3">
              {nav.map((item) => (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    'text-sm hover:text-foreground',
                    isActive(path, item.to, item.exact)
                      ? 'text-foreground'
                      : 'text-muted-foreground',
                  )}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            {health.data ? (
              <span className="font-mono text-xs text-muted-foreground">{health.data.version}</span>
            ) : null}
            <Badge variant={health.isSuccess ? 'ok' : 'error'}>
              {health.isSuccess ? 'connected' : 'unreachable'}
            </Badge>
            <button
              type="button"
              aria-label="Toggle theme"
              className="rounded-md border p-1.5 hover:bg-muted"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            {session ? (
              <div className="flex items-center gap-2 border-l pl-3">
                {/* Who you are and what you may do, always visible: a viewer
                    who does not know they are a viewer reads every missing
                    button as a broken dashboard. */}
                <span className="text-xs text-muted-foreground">
                  {session.subject}
                  <span className="ml-1 opacity-70">({session.role})</span>
                </span>
                <button
                  type="button"
                  aria-label="Sign out"
                  title="Sign out"
                  className="rounded-md border p-1.5 hover:bg-muted"
                  onClick={() => void signOut()}
                >
                  <LogOut size={16} />
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">
        <Page path={path} />
      </main>
    </div>
  )
}

/** Page resolves the current path to a view. */
function Page({ path }: { path: string }) {
  if (matchPath('/', path)) return <Overview />
  if (matchPath('/services', path)) return <Services />

  const detail = matchPath('/services/:project/:service', path)
  if (detail?.project && detail.service) {
    return <ServiceDetail project={detail.project} service={detail.service} />
  }

  // A deep link the server handed to the app but the app does not know: say so
  // rather than render a blank page.
  return <p className="text-sm text-muted-foreground">No such page.</p>
}

type Theme = 'dark' | 'light'

/** useTheme keeps the shadcn dark class in step with the stored preference. */
function useTheme(): [Theme, (next: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = window.localStorage.getItem('kanea-theme')
    if (stored === 'light' || stored === 'dark') return stored
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    window.localStorage.setItem('kanea-theme', theme)
  }, [theme])

  return [theme, setTheme]
}
