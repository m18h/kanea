import { describe, expect, it } from 'vitest'
import { humanDuration, runDuration, runStateVariant, shortID, shortSHA } from './pipelines'
import type { Run } from './api'

function run(over: Partial<Run> = {}): Run {
  return {
    id: '01JABCDEFGHIJK',
    project: 'shop',
    service: 'web',
    state: 'running',
    trigger: 'push',
    started_at: '2026-08-05T10:00:00Z',
    ...over,
  }
}

describe('runStateVariant', () => {
  it('separates finished from in-flight from broken', () => {
    expect(runStateVariant('succeeded')).toBe('ok')
    expect(runStateVariant('running')).toBe('accent')
    expect(runStateVariant('queued')).toBe('warn')
    expect(runStateVariant('failed')).toBe('error')
    expect(runStateVariant('cancelled')).toBe('muted')
  })
})

describe('runDuration', () => {
  it('measures a finished run against its own end', () => {
    // Not against now. A duration that kept climbing after a build ended would
    // be a lie about a finished thing, and the page re-renders every 15s.
    const finished = run({
      state: 'succeeded',
      finished_at: '2026-08-05T10:02:30Z',
    })
    const later = Date.parse('2026-08-05T18:00:00Z')
    expect(runDuration(finished, later)).toBe('2m30s')
  })

  it('measures a running build against now', () => {
    const now = Date.parse('2026-08-05T10:00:45Z')
    expect(runDuration(run(), now)).toBe('45.0s')
  })

  it('does not render a negative duration from a clock skew', () => {
    const before = Date.parse('2026-08-05T09:59:00Z')
    expect(runDuration(run(), before)).toBe('0ms')
  })

  it('reports a dash rather than NaN for an unparseable time', () => {
    expect(runDuration(run({ started_at: 'not a time' }))).toBe('—')
  })
})

describe('humanDuration', () => {
  it('changes unit with magnitude', () => {
    expect(humanDuration(546)).toBe('546ms')
    expect(humanDuration(2_200)).toBe('2.2s')
    expect(humanDuration(90_000)).toBe('1m30s')
    expect(humanDuration(3_900_000)).toBe('1h05m')
  })
})

describe('short forms', () => {
  it('abbreviates ids and shas the way the CLI does', () => {
    expect(shortID('01JABCDEFGHIJK')).toBe('01JABCDE')
    expect(shortID('short')).toBe('short')
    expect(shortSHA('abc123def456789')).toBe('abc123d')
    expect(shortSHA(undefined)).toBe('—')
  })
})
