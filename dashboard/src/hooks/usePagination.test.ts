import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { usePagination } from '@/hooks/usePagination'

const list = (n: number) => Array.from({ length: n }, (_, i) => i)

describe('usePagination', () => {
  it('windows the list to one page', () => {
    const { result } = renderHook(() => usePagination(list(60), { pageSize: 25 }))
    expect(result.current.pageItems).toHaveLength(25)
    expect(result.current.pages).toBe(3)
    expect(result.current.total).toBe(60)
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
