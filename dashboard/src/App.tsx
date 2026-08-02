import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Moon, Sun } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Services } from '@/pages/Services'
import { fetchHealth } from '@/lib/api'

export function App() {
  const [theme, setTheme] = useTheme()

  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 10_000,
  })

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
          <div className="flex items-baseline gap-3">
            <span className="text-lg font-semibold tracking-tight">Kanea</span>
            {health.data ? (
              <span className="font-mono text-xs text-muted-foreground">
                {health.data.version}
              </span>
            ) : null}
          </div>
          <div className="flex items-center gap-3">
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
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">
        <Services />
      </main>
    </div>
  )
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
