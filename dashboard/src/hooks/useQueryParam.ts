import { useRouter } from '@/hooks/useRouter'

/**
 * A filter that lives in the URL.
 *
 * The URL is the state rather than a copy of it: the value is read during
 * render and written in the event that changed it, so going back restores the
 * filters that history entry carried with no effect in the loop and no second
 * copy to disagree with the address bar. Reading during render also means the
 * first paint is already filtered, which is what keeps usePagination's
 * reset-on-change from discarding anything on mount.
 *
 * Writes replace rather than push: a history entry per keystroke would turn
 * Back into a letter-by-letter undo instead of the way out of the page.
 */
export function useQueryParam(key: string, fallback: string): [string, (next: string) => void] {
  const { path, search, navigate } = useRouter()
  const value = new URLSearchParams(search).get(key) ?? fallback

  const set = (next: string) => {
    // Built from the current query, never from scratch: starting empty is how
    // setting one filter silently drops the others.
    const params = new URLSearchParams(search)
    // The default is omitted, so an unfiltered list is `/services` rather than
    // `/services?q=&status=all`.
    if (next === fallback) params.delete(key)
    else params.set(key, next)
    const qs = params.toString()
    navigate(qs === '' ? path : `${path}?${qs}`, { replace: true })
  }

  return [value, set]
}

/**
 * useQueryEnum is a filter whose values are a fixed set.
 *
 * An unreadable filter reads as no filter: a hand-edited or stale URL naming a
 * value this page does not have falls back rather than crashing or filtering
 * the list to nothing it can explain. Reading never rewrites the URL - two
 * mounted readers of one key would race each other over it.
 */
export function useQueryEnum<T extends string>(
  key: string,
  options: readonly T[],
  fallback: T,
): [T, (next: T) => void] {
  const [raw, set] = useQueryParam(key, fallback)
  return [isOneOf(options, raw) ? raw : fallback, set]
}

function isOneOf<T extends string>(options: readonly T[], value: string): value is T {
  return (options as readonly string[]).includes(value)
}
