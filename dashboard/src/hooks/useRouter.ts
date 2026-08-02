import { useContext } from 'react'
import { RouterContext, type RouterState } from '@/lib/router-context'

/** useRouter exposes the current path and a way to navigate. */
export function useRouter(): RouterState {
  const ctx = useContext(RouterContext)
  if (!ctx) throw new Error('useRouter must be used inside a Router')
  return ctx
}
