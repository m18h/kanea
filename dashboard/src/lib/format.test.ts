import { describe, expect, it } from 'vitest'
import { formatUptime, relativeAge, serviceStatusTone } from '@/lib/state'
import { replicationLag } from '@/lib/backups'

describe('formatUptime', () => {
  it('renders the two largest non-zero units', () => {
    expect(formatUptime(41 * 86_400 + 6 * 3_600 + 12 * 60)).toBe('41d 6h')
    expect(formatUptime(6 * 3_600 + 12 * 60)).toBe('6h 12m')
    expect(formatUptime(12 * 60 + 30)).toBe('12m')
    expect(formatUptime(45)).toBe('45s')
  })

  it('refuses to render a nonsense value', () => {
    expect(formatUptime(-1)).toBe('-')
    expect(formatUptime(Number.NaN)).toBe('-')
  })
})

describe('relativeAge', () => {
  const now = Date.parse('2026-08-09T14:32:00Z')

  it('renders the single largest unit', () => {
    expect(relativeAge('2026-06-29T14:32:00Z', now)).toBe('41d')
    expect(relativeAge('2026-08-09T08:32:00Z', now)).toBe('6h')
    expect(relativeAge('2026-08-09T14:29:00Z', now)).toBe('3m')
    expect(relativeAge('2026-08-09T14:31:59Z', now)).toBe('1s')
  })

  it('is a dash for a missing or unparsable timestamp', () => {
    expect(relativeAge(undefined, now)).toBe('-')
    expect(relativeAge('garbage', now)).toBe('-')
  })
})

describe('serviceStatusTone', () => {
  it('maps the health vocabulary onto the four words', () => {
    expect(serviceStatusTone({ label: 'ok', settled: true })).toEqual({
      tone: 'ok',
      word: 'running',
    })
    expect(serviceStatusTone({ label: 'starting', settled: false })).toEqual({
      tone: 'warn',
      word: 'scaling',
    })
    expect(serviceStatusTone({ label: '1 failed', settled: false })).toEqual({
      tone: 'error',
      word: 'degraded',
    })
    expect(serviceStatusTone({ label: '2 restarting', settled: false })).toEqual({
      tone: 'error',
      word: 'degraded',
    })
    expect(serviceStatusTone({ label: 'stopped', settled: true })).toEqual({
      tone: 'muted',
      word: 'stopped',
    })
  })
})

describe('replicationLag', () => {
  const now = Date.parse('2026-08-09T14:32:00Z')

  it('derives the lag from the last shipped segment', () => {
    expect(replicationLag('2026-08-09T14:31:18Z', now)).toBe('42s')
    expect(replicationLag('2026-08-09T14:20:00Z', now)).toBe('12m')
    expect(replicationLag('2026-08-09T09:32:00Z', now)).toBe('5h')
  })

  // "never" is an empty state, not a zero lag: a destination nothing has
  // reached is the opposite of a destination that is caught up.
  it('says never when nothing has shipped', () => {
    expect(replicationLag(undefined, now)).toBe('never')
    expect(replicationLag('garbage', now)).toBe('never')
  })
})
