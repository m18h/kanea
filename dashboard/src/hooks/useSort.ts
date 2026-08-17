import { useState } from 'react'

export type SortDir = 'asc' | 'desc'

export interface Sort<K extends string> {
  /** key is null while the list is in its own order: the order the server
   * chose, which every page treats as the default. */
  key: K | null
  dir: SortDir
  toggle: (key: K) => void
}

/**
 * useSort holds which column a table is sorted by.
 *
 * Clicking a header cycles asc → desc → back to the list's own order. The
 * third state matters: a services list arrives named-ordered and a run list
 * arrives newest-first, and once a reader has sorted by allocs there must be a
 * way back to that order that is not "reload the page".
 */
export function useSort<K extends string>(): Sort<K> {
  const [state, setState] = useState<{ key: K | null; dir: SortDir }>({ key: null, dir: 'asc' })
  return {
    ...state,
    toggle: (key) =>
      setState((s) => {
        if (s.key !== key) return { key, dir: 'asc' }
        if (s.dir === 'asc') return { key, dir: 'desc' }
        return { key: null, dir: 'asc' }
      }),
  }
}

/** SortValue is what a column can order by. undefined means "no data". */
export type SortValue = string | number | undefined

/**
 * sortItems orders a list by the active column, stably, without mutating it.
 *
 * "No data" sorts last in *both* directions: the dashboard's dashes are not
 * small numbers ("no data is never zero"), and a reader sorting P95 descending
 * is looking for the slowest service, not for the ones nothing has measured.
 */
export function sortItems<T, K extends string>(
  items: T[],
  sort: { key: K | null; dir: SortDir },
  accessors: Record<K, (item: T) => SortValue>,
): T[] {
  if (sort.key === null) return items
  const get = accessors[sort.key]
  const sign = sort.dir === 'asc' ? 1 : -1
  return [...items].sort((a, b) => {
    const va = get(a)
    const vb = get(b)
    if (va === undefined && vb === undefined) return 0
    if (va === undefined) return 1
    if (vb === undefined) return -1
    if (typeof va === 'string' && typeof vb === 'string') return sign * va.localeCompare(vb)
    if (va < vb) return -sign
    if (va > vb) return sign
    return 0
  })
}
