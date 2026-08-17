import { useState } from 'react'

/** One page of a list. Ten rows keeps a card-height table scannable; the
 * selector offers more for whoever wants a wall of data. */
export const DefaultPageSize = 10

/** The sizes the pager offers. */
export const PageSizes = [10, 20, 50, 100] as const

export interface Pagination<T> {
  /** The window of items the current page shows. */
  pageItems: T[]
  /** page is zero-based and always clamped to the list that exists now. */
  page: number
  pages: number
  total: number
  /** start is the index of the first shown item, for "26-50 of 132". */
  start: number
  setPage: (page: number) => void
  pageSize: number
  /** setPageSize re-windows around the first visible item, so growing the
   * page does not teleport the reader back to the top of the list. */
  setPageSize: (size: number) => void
}

/**
 * usePagination windows a list the caller already has.
 *
 * Client-side on purpose: every list in this dashboard is either a live
 * websocket snapshot (services, allocs) or a bounded fetch (events, runs,
 * backups), so the full list is in memory already and a server round-trip per
 * page would add latency to buy nothing.
 *
 * The clamp matters for live data: a list that shrinks under the reader (a
 * scale to zero, a pruned run) must not leave the page pointing past the end.
 * Clamping (rather than resetting) keeps the reader where they were for the
 * ordinary case of rows merely updating in place.
 */
export function usePagination<T>(
  items: T[],
  opts: { pageSize?: number; resetKey?: unknown } = {},
): Pagination<T> {
  const [page, setPage] = useState(0)
  const [pageSize, setSize] = useState(opts.pageSize ?? DefaultPageSize)

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
    pageSize,
    setPageSize: (size: number) => {
      setSize(size)
      setPage(Math.floor(start / size))
    },
  }
}
