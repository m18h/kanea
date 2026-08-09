import { useEffect, useState } from 'react'

export type Theme = 'dark' | 'light'

/** useTheme keeps the shadcn dark class in step with the stored preference. */
export function useTheme(): [Theme, (next: Theme) => void] {
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
