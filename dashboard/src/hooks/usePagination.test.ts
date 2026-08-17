import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { DefaultPageSize, PageSizes, usePagination } from '@/hooks/usePagination'

const list = (n: number) => Array.from({ length: n }, (_, i) => i)

describe('usePagination', () => {
  it('windows the list to one page', () => {
    const { result } = renderHook(() => usePagination(list(60), { pageSize: 25 }))
    expect(result.current.pageItems).toHaveLength(25)
    expect(result.current.pages).toBe(3)
    expect(result.current.total).toBe(60)
  })

  it('defaults to ten rows with the larger sizes on offer', () => {
    expect(DefaultPageSize).toBe(10)
    expect(PageSizes).toEqual([10, 20, 50, 100])
    const { result } = renderHook(() => usePagination(list(35)))
    expect(result.current.pageItems).toHaveLength(10)
    expect(result.current.pages).toBe(4)
  })

  it('re-windows around the first visible item when the size changes', () => {
    // Reading rows 21-30 and choosing 50 must keep those rows in view, not
    // teleport the reader back to the top of the list.
    const { result } = renderHook(() => usePagination(list(100)))
    act(() => result.current.setPage(2))
    expect(result.current.start).toBe(20)

    act(() => result.current.setPageSize(50))
    expect(result.current.pageSize).toBe(50)
    expect(result.current.page).toBe(0)
    expect(result.current.pageItems).toContain(20)

    // And shrinking again from a deep page keeps the window anchored too.
    act(() => result.current.setPage(1))
    expect(result.current.start).toBe(50)
    act(() => result.current.setPageSize(10))
    expect(result.current.page).toBe(5)
    expect(result.current.pageItems[0]).toBe(50)
  })

  it('reports a single page for a list that fits', () => {
    const { result } = renderHook(() => usePagination(list(10), { pageSize: 25 }))
    expect(result.current.pages).toBe(1)
    expect(result.current.pageItems).toHaveLength(10)
  })

  it('clamps the page when a live list shrinks under the reader', () => {
    // A scale to zero or a pruned run must not leave the page pointing past
    // the end of what now exists.
    const { result, rerender } = renderHook(({ items }) => usePagination(items, { pageSize: 25 }), {
      initialProps: { items: list(100) },
    })
    act(() => result.current.setPage(3))
    expect(result.current.page).toBe(3)

    rerender({ items: list(30) })
    expect(result.current.page).toBe(1)
    expect(result.current.pageItems).toHaveLength(5)
  })

  it('returns to the first page when the filter changes', () => {
    // Page 3 of "all" and page 3 of "error" are unrelated places.
    const { result, rerender } = renderHook(
      ({ key }) => usePagination(list(100), { pageSize: 25, resetKey: key }),
      { initialProps: { key: 'all' } },
    )
    act(() => result.current.setPage(2))
    expect(result.current.page).toBe(2)

    rerender({ key: 'error' })
    expect(result.current.page).toBe(0)
  })

  it('stays on page zero for an empty list', () => {
    const { result } = renderHook(() => usePagination([], { pageSize: 25 }))
    expect(result.current.page).toBe(0)
    expect(result.current.pages).toBe(1)
    expect(result.current.pageItems).toHaveLength(0)
  })
})
