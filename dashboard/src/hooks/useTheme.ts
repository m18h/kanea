import { useEffect, useState } from 'react'

export type Theme = 'dark' | 'light'

/** useTheme keeps the shadcn dark class in step with the stored preference. */
export function useTheme(): [Theme, (next: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = window.localStorage.getItem('kanea-theme')
    if (stored === 'light' || stored === 'dark') return stored
    // Dark by default, whatever the OS says — an ops dashboard is a thing
    // left open on a monitor. The toggle persists an explicit choice.
    return 'dark'
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    window.localStorage.setItem('kanea-theme', theme)
  }, [theme])

  return [theme, setTheme]
}
