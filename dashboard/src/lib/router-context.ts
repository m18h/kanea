import { createContext } from 'react'

export interface RouterState {
  /** The current pathname, without origin or query. */
  path: string
  navigate: (to: string) => void
}

/**
 * The router's context, in its own module.
 *
 * Not a style choice: a file exporting both a context and components breaks
 * fast refresh, because the context identity changes on every hot update and
 * every consumer remounts.
 */
export const RouterContext = createContext<RouterState | null>(null)
