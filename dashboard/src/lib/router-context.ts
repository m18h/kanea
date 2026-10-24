import { createContext } from 'react'

export interface RouterState {
  /** The current pathname, without origin or query. */
  path: string
  /**
   * The query string with its leading '?', or '' when there is none.
   *
   * Beside `path` rather than part of it: matchPath counts '/' segments, so a
   * path carrying a query would match no route at all, and AppShell closes the
   * mobile drawer on a changed path - which a filter typed character by
   * character must not do.
   */
  search: string
  /** navigate pushes a history entry, or replaces the current one: a filter
   * writing itself into the URL must not leave an entry per keystroke. */
  navigate: (to: string, opts?: { replace?: boolean }) => void
}

/**
 * The router's context, in its own module.
 *
 * Not a style choice: a file exporting both a context and components breaks
 * fast refresh, because the context identity changes on every hot update and
 * every consumer remounts.
 */
export const RouterContext = createContext<RouterState | null>(null)
