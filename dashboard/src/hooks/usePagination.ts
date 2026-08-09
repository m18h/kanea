import { useState } from 'react'

/** One page of a list. 25 rows reads without scrolling on a laptop screen. */
export const DefaultPageSize = 25

export interface Pagination<T> {
  /** The window of items the current page shows. */
  pageItems: T[]
  /** page is zero-based and always clamped to the list that exists now. */
  page: number
  pages: number
  total: number
  /** start is the index of the first shown item, for "26–50 of 132". */
  start: number
  setPage: (page: number) => void
}

/**
 * usePagination windows a list the caller already has.
 *
 * Client-side on purpose: every list in this dashboard is either a live
 * websocket snapshot (services, allocs) or a bounded fetch (events, runs,
 * backups), so the full list is in memory already and a server round-trip per
 * page would add latency to buy nothing.
 *
 * The clamp matters for live data: a list that shrinks under the reader — a
 * scale to zero, a pruned run — must not leave the page pointing past the end.
 * Clamping (rather than resetting) keeps the reader where they were for the
 * ordinary case of rows merely updating in place.
 */
export function usePagination<T>(
  items: T[],
  opts: { pageSize?: number; resetKey?: unknown } = {},
): Pagination<T> {
  const pageSize = opts.pageSize ?? DefaultPageSize
  const [page, setPage] = useState(0)

  // A changed filter is a different list, and page 3 of the old one points
  // nowhere meaningful in the new one. Reset during render rather than in an
  // effect, so the new list never flashes at the old page for one frame.
  const resetKey = opts.resetKey
  const [prevKey, setPrevKey] = useState(resetKey)
  if (prevKey !== resetKey) {
    setPrevKey(resetKey)
    setPage(0)
  }

  const pages = Math.max(1, Math.ceil(items.length / pageSize))
  const current = Math.min(page, pages - 1)
  const start = current * pageSize

  return {
    pageItems: items.slice(start, start + pageSize),
    page: current,
    pages,
    total: items.length,
    start,
    setPage,
  }
}
