import { beforeEach, describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useQueryEnum, useQueryParam } from '@/hooks/useQueryParam'
import { Router } from '@/lib/router'

const statuses = ['all', 'running', 'degraded'] as const

describe('useQueryParam', () => {
  // The URL is global state, and vitest isolates per file rather than per test.
  beforeEach(() => window.history.pushState({}, '', '/'))

  it('reads a seeded URL on the first render, before any effect', () => {
    window.history.pushState({}, '', '/services?q=api')
    const { result } = renderHook(() => useQueryParam('q', ''), { wrapper: Router })

    // No waitFor: a value that arrived a render late would flash the
    // unfiltered list and throw away the pager's reset key.
    expect(result.current[0]).toBe('api')
  })

  it('drops the param when the value returns to its default', () => {
    window.history.pushState({}, '', '/services')
    const { result } = renderHook(() => useQueryParam('q', ''), { wrapper: Router })

    act(() => result.current[1]('api'))
    expect(window.location.search).toBe('?q=api')

    act(() => result.current[1](''))
    expect(window.location.search).toBe('')
    expect(window.location.pathname).toBe('/services')
  })

  // The likeliest bug in the whole feature: building the next query from
  // scratch instead of from the current one silently drops its siblings.
  it('preserves the other params when one is written', () => {
    window.history.pushState({}, '', '/services')
    const { result } = renderHook(
      () => ({
        q: useQueryParam('q', ''),
        status: useQueryEnum<(typeof statuses)[number]>('status', statuses, 'all'),
      }),
      { wrapper: Router },
    )

    act(() => result.current.q[1]('api'))
    act(() => result.current.status[1]('degraded'))

    const params = new URLSearchParams(window.location.search)
    expect(params.get('q')).toBe('api')
    expect(params.get('status')).toBe('degraded')
  })

  it('round-trips a value with URL metacharacters exactly once', () => {
    window.history.pushState({}, '', '/events')
    const { result } = renderHook(() => useQueryParam('glob', ''), { wrapper: Router })

    act(() => result.current[1]('payments/*'))

    expect(result.current[0]).toBe('payments/*')
    // Encoded by the serializer alone: a hand-rolled encodeURIComponent on top
    // of it is how a value becomes %2520.
    expect(window.location.search).toContain('glob=payments%2F*')
  })
})

describe('useQueryEnum', () => {
  beforeEach(() => window.history.pushState({}, '', '/'))

  it('falls back for a value this page does not have, and leaves the URL alone', () => {
    window.history.pushState({}, '', '/services?status=banana')
    const { result } = renderHook(
      () => useQueryEnum<(typeof statuses)[number]>('status', statuses, 'all'),
      { wrapper: Router },
    )

    expect(result.current[0]).toBe('all')
    // A read is not a write: two mounted readers of one key would otherwise
    // race each other over it.
    expect(window.location.search).toBe('?status=banana')
  })

  it('accepts a value it does have', () => {
    window.history.pushState({}, '', '/services?status=degraded')
    const { result } = renderHook(
      () => useQueryEnum<(typeof statuses)[number]>('status', statuses, 'all'),
      { wrapper: Router },
    )

    expect(result.current[0]).toBe('degraded')
  })
})
