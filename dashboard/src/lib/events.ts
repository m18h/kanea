import type { KaneaEvent } from './api'

/**
 * Presentation helpers for the event feed. Pure and tested, in lib for the
 * same fast-refresh reason as state.ts.
 */

export interface ScaleDecision {
  service: string
  from?: number | undefined
  to?: number | undefined
  direction: 'up' | 'down'
  reason: string
  at: string
}

/**
 * parseScaleDecision reads an autoscaler event back into a decision row.
 *
 * There is no decisions endpoint: the evaluator's choices surface only as
 * `scale.up` / `scale.down` events (PRD §9.2), so the "3 → 5" the mockup shows
 * is extracted from the message when it is there and omitted when it is not.
 * Nothing is fabricated: a message without counts renders as its own text.
 */
export function parseScaleDecision(event: KaneaEvent): ScaleDecision | null {
  if (event.name !== 'scale.up' && event.name !== 'scale.down') return null

  const scope = [event.project, event.service].filter(Boolean).join('/')
  const text = `${event.message} ${event.detail ?? ''}`
  const counts = /(\d+)\s*(?:→|->)\s*(\d+)/.exec(text)

  return {
    service: scope || event.message,
    from: counts ? Number(counts[1]) : undefined,
    to: counts ? Number(counts[2]) : undefined,
    direction: event.name === 'scale.up' ? 'up' : 'down',
    reason: event.message,
    at: event.at,
  }
}

/**
 * matchGlob matches a `project/service` scope against a shell-style pattern
 * ("svc/*", "*billing*"). Only `*` is special; everything else is literal.
 */
export function matchGlob(pattern: string, scope: string): boolean {
  const trimmed = pattern.trim()
  if (trimmed === '' || trimmed === '*') return true
  const escaped = trimmed.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`, 'i').test(scope)
}

/** eventScope is the `project/service` string an event belongs to. */
export function eventScope(event: KaneaEvent): string {
  return [event.project, event.service].filter(Boolean).join('/')
}

/** eventSource is the feed's SOURCE column: the vocabulary prefix of the
 * event name ("scale.up" → "scale", "backup.snapshot" → "backup"). */
export function eventSource(event: KaneaEvent): string {
  const dot = event.name.indexOf('.')
  return dot > 0 ? event.name.slice(0, dot) : event.name
}
