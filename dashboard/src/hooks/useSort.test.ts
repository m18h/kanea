import { beforeEach, describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { formatSort, parseSort, sortItems, useSort } from '@/hooks/useSort'
import { Router } from '@/lib/router'

describe('useSort', () => {
  // The sort lives in the URL now, which is global state vitest shares across
  // the tests in a file.
  beforeEach(() => window.history.pushState({}, '', '/'))

  it('cycles a header asc → desc → back to the list order', () => {
    const { result } = renderHook(() => useSort<'name'>(['name']), { wrapper: Router })
    expect(result.current.key).toBeNull()

    act(() => result.current.toggle('name'))
    expect(result.current).toMatchObject({ key: 'name', dir: 'asc' })

    act(() => result.current.toggle('name'))
    expect(result.current).toMatchObject({ key: 'name', dir: 'desc' })

    // The third click restores the order the server chose: the only way back
    // that is not "reload the page". The param goes rather than going empty,
    // so an unsorted list has a clean URL.
    act(() => result.current.toggle('name'))
    expect(result.current.key).toBeNull()
    expect(window.location.search).toBe('')
  })

  it('starts a different column ascending, whatever the previous one was', () => {
    const { result } = renderHook(() => useSort<'name' | 'allocs'>(['name', 'allocs']), {
      wrapper: Router,
    })
    act(() => result.current.toggle('name'))
    act(() => result.current.toggle('name'))
    expect(result.current.dir).toBe('desc')

    act(() => result.current.toggle('allocs'))
    expect(result.current).toMatchObject({ key: 'allocs', dir: 'asc' })
    expect(window.location.search).toBe('?sort=allocs%3Aasc')
  })

  it('reads a sort seeded on the URL before anything is clicked', () => {
    window.history.pushState({}, '', '/services?sort=allocs:desc')
    const { result } = renderHook(() => useSort<'name' | 'allocs'>(['name', 'allocs']), {
      wrapper: Router,
    })
    expect(result.current).toMatchObject({ key: 'allocs', dir: 'desc' })
  })
})

// sortItems looks an accessor up by name and calls it, so a key out of the URL
// that the table has no column for is a crash rather than a wrong order.
describe('parseSort', () => {
  const keys = ['name', 'allocs'] as const

  it('reads a column this table has', () => {
    expect(parseSort('allocs:desc', keys)).toEqual({ key: 'allocs', dir: 'desc' })
  })

  it('falls back to the list order for anything it cannot trust', () => {
    for (const raw of ['', 'allocs', 'nope:asc', 'allocs:sideways', ':asc', 'allocs:']) {
      expect(parseSort(raw, keys)).toEqual({ key: null, dir: 'asc' })
    }
  })

  it('round-trips through formatSort', () => {
    expect(formatSort({ key: 'name' as const, dir: 'asc' as const })).toBe('name:asc')
    expect(parseSort(formatSort({ key: 'name' as const, dir: 'asc' as const }), keys)).toEqual({
      key: 'name',
      dir: 'asc',
    })
    expect(formatSort({ key: null, dir: 'asc' })).toBe('')
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
