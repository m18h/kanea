import { useSyncExternalStore } from 'react'

import { type DateStyle, dateStyle, subscribeDateStyle } from '@/lib/datetime'

/**
 * useDateStyle subscribes a component to the date-format preference.
 *
 * It returns the style rather than a bound formatter so the call sites read as
 * `formatDateTime(iso, style)`: the dependency is visible in the render, which
 * is what stops a component from formatting against a module global it never
 * declared and then failing to re-render when that global moves.
 */
export function useDateStyle(): DateStyle {
  return useSyncExternalStore(subscribeDateStyle, dateStyle, dateStyle)
}
