import { describe, expect, it } from 'vitest'
import { eventScope, eventSource, matchGlob, parseScaleDecision } from '@/lib/events'
import type { KaneaEvent } from '@/lib/api'

function event(overrides: Partial<KaneaEvent>): KaneaEvent {
  return {
    id: 'e1',
    name: 'scale.up',
    severity: 'info',
    message: 'scaled',
    at: '2026-08-09T14:32:08Z',
    ...overrides,
  }
}

describe('parseScaleDecision', () => {
  it('extracts the from/to counts when the message carries them', () => {
    const decision = parseScaleDecision(
      event({
        name: 'scale.up',
        project: 'shop',
        service: 'api-gateway',
        message: 'api-gateway scaled 3 → 5 (p95 84ms > 80ms target)',
      }),
    )
    expect(decision).toMatchObject({ service: 'shop/api-gateway', from: 3, to: 5, direction: 'up' })
  })

  it('accepts an ASCII arrow too', () => {
    const decision = parseScaleDecision(event({ message: 'scaled 4 -> 2', name: 'scale.down' }))
    expect(decision).toMatchObject({ from: 4, to: 2, direction: 'down' })
  })

  // Fabricating numbers a message does not carry would be worse than showing
  // the message itself.
  it('leaves the counts undefined when the message has none', () => {
    const decision = parseScaleDecision(event({ message: 'scaled up' }))
    expect(decision?.from).toBeUndefined()
    expect(decision?.to).toBeUndefined()
  })

  it('ignores every other event name', () => {
    expect(parseScaleDecision(event({ name: 'deploy.finished' }))).toBeNull()
  })
})

describe('matchGlob', () => {
  it('matches everything for empty or bare-star patterns', () => {
    expect(matchGlob('', 'shop/web')).toBe(true)
    expect(matchGlob('*', 'shop/web')).toBe(true)
  })

  it('expands * and keeps everything else literal', () => {
    expect(matchGlob('shop/*', 'shop/web')).toBe(true)
    expect(matchGlob('shop/*', 'other/web')).toBe(false)
    expect(matchGlob('*billing*', 'shop/billing')).toBe(true)
  })

  // Regex metacharacters in a pattern are text, not syntax — a filter that
  // throws on "(" is a filter nobody can type into.
  it('treats regex metacharacters as literals', () => {
    expect(matchGlob('shop/web(1)', 'shop/web(1)')).toBe(true)
    expect(matchGlob('shop/web(1)', 'shop/web1')).toBe(false)
  })
})

describe('eventScope and eventSource', () => {
  it('joins project and service, tolerating either being absent', () => {
    expect(eventScope(event({ project: 'shop', service: 'web' }))).toBe('shop/web')
    expect(eventScope(event({ project: 'shop' }))).toBe('shop')
    expect(eventScope(event({}))).toBe('')
  })

  it('takes the vocabulary prefix as the source', () => {
    expect(eventSource(event({ name: 'backup.snapshot' }))).toBe('backup')
    expect(eventSource(event({ name: 'weird' }))).toBe('weird')
  })
})
