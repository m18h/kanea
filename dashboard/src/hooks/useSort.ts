import { useQueryParam } from '@/hooks/useQueryParam'

export type SortDir = 'asc' | 'desc'

export interface Sort<K extends string> {
  /** key is null while the list is in its own order: the order the server
   * chose, which every page treats as the default. */
  key: K | null
  dir: SortDir
  toggle: (key: K) => void
}

/**
 * useSort holds which column a table is sorted by, in the URL.
 *
 * Clicking a header cycles asc → desc → back to the list's own order. The
 * third state matters: a services list arrives named-ordered and a run list
 * arrives newest-first, and once a reader has sorted by allocs there must be a
 * way back to that order that is not "reload the page". It is also why the
 * param is absent rather than empty for that state.
 *
 * `keys` is required because parseSort validates against it, and an unchecked
 * key out of the URL is a crash rather than a wrong order: sortItems looks the
 * accessor up by name and calls it.
 */
export function useSort<K extends string>(keys: readonly K[]): Sort<K> {
  const [raw, set] = useQueryParam('sort', '')
  const state = parseSort(raw, keys)
  return { ...state, toggle: (key) => set(formatSort(nextSort(state, key))) }
}

/** nextSort is the asc → desc → list-order cycle, as a value. */
export function nextSort<K extends string>(
  current: { key: K | null; dir: SortDir },
  key: K,
): { key: K | null; dir: SortDir } {
  if (current.key !== key) return { key, dir: 'asc' }
  if (current.dir === 'asc') return { key, dir: 'desc' }
  return { key: null, dir: 'asc' }
}

/** formatSort renders a sort as `key:dir`, or '' for the list's own order. */
export function formatSort<K extends string>(sort: { key: K | null; dir: SortDir }): string {
  return sort.key === null ? '' : `${sort.key}:${sort.dir}`
}

/**
 * parseSort reads `key:dir` back, validated against the columns this table
 * actually has.
 *
 * A URL naming a column that does not exist - hand-edited, or a link from a
 * release where it did - sorts by nothing rather than reaching sortItems with
 * a key it has no accessor for.
 */
export function parseSort<K extends string>(
  raw: string,
  keys: readonly K[],
): { key: K | null; dir: SortDir } {
  const none = { key: null, dir: 'asc' as SortDir }
  const at = raw.lastIndexOf(':')
  if (at < 1) return none
  const key = raw.slice(0, at)
  const dir = raw.slice(at + 1)
  if (!(keys as readonly string[]).includes(key)) return none
  if (dir !== 'asc' && dir !== 'desc') return none
  return { key: key as K, dir }
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
