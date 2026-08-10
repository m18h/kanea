import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { sortItems, useSort } from '@/hooks/useSort'

describe('useSort', () => {
  it('cycles a header asc → desc → back to the list order', () => {
    const { result } = renderHook(() => useSort<'name'>())
    expect(result.current.key).toBeNull()

    act(() => result.current.toggle('name'))
    expect(result.current).toMatchObject({ key: 'name', dir: 'asc' })

    act(() => result.current.toggle('name'))
    expect(result.current).toMatchObject({ key: 'name', dir: 'desc' })

    // The third click restores the order the server chose — the only way back
    // that is not "reload the page".
    act(() => result.current.toggle('name'))
    expect(result.current.key).toBeNull()
  })

  it('starts a different column ascending, whatever the previous one was', () => {
    const { result } = renderHook(() => useSort<'name' | 'allocs'>())
    act(() => result.current.toggle('name'))
    act(() => result.current.toggle('name'))
    expect(result.current.dir).toBe('desc')

    act(() => result.current.toggle('allocs'))
    expect(result.current).toMatchObject({ key: 'allocs', dir: 'asc' })
  })
})

describe('sortItems', () => {
  const byValue = { value: (item: { value: number | undefined }) => item.value }

  it('returns the list itself while no column is active', () => {
    const items = [{ value: 2 }, { value: 1 }]
    expect(sortItems(items, { key: null, dir: 'asc' }, byValue)).toBe(items)
  })

  it('orders numbers both ways without mutating the input', () => {
    const items = [{ value: 2 }, { value: 3 }, { value: 1 }]
    expect(sortItems(items, { key: 'value', dir: 'asc' }, byValue).map((i) => i.value)).toEqual([
      1, 2, 3,
    ])
    expect(sortItems(items, { key: 'value', dir: 'desc' }, byValue).map((i) => i.value)).toEqual([
      3, 2, 1,
    ])
    expect(items.map((i) => i.value)).toEqual([2, 3, 1])
  })

  it('orders strings with localeCompare', () => {
    const items = [{ name: 'web/api' }, { name: 'blog/site' }]
    const sorted = sortItems(items, { key: 'name', dir: 'asc' }, { name: (i) => i.name })
    expect(sorted.map((i) => i.name)).toEqual(['blog/site', 'web/api'])
  })

  it('sorts "no data" last in both directions', () => {
    // A dash is not a small number: descending P95 means "slowest first", and
    // an unmeasured service belongs at the bottom either way.
    const items = [{ value: undefined }, { value: 5 }, { value: undefined }, { value: 1 }]
    expect(sortItems(items, { key: 'value', dir: 'asc' }, byValue).map((i) => i.value)).toEqual([
      1, 5, undefined, undefined,
    ])
    expect(sortItems(items, { key: 'value', dir: 'desc' }, byValue).map((i) => i.value)).toEqual([
      5, 1, undefined, undefined,
    ])
  })

  it('keeps equal rows in their incoming order', () => {
    const items = [
      { id: 'a', rank: 1 },
      { id: 'b', rank: 0 },
      { id: 'c', rank: 1 },
    ]
    const sorted = sortItems(items, { key: 'rank', dir: 'asc' }, { rank: (i) => i.rank })
    expect(sorted.map((i) => i.id)).toEqual(['b', 'a', 'c'])
  })
})
