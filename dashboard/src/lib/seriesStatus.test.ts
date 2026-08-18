import { describe, expect, it } from 'vitest'
import { seriesStatus } from '@/lib/seriesStatus'

const base = { points: 0, seeded: true, connected: true, error: null }

describe('seriesStatus', () => {
  it('is live whenever there is anything to draw', () => {
    // Whatever else is true, a real measurement is on screen. This is what
    // stops a reconnect blink from replacing a populated chart with a message.
    expect(seriesStatus({ ...base, points: 1, seeded: false, connected: false })).toBe('live')
  })

  it('is loading while the seed has not settled', () => {
    expect(seriesStatus({ ...base, seeded: false })).toBe('loading')
  })

  it('is loading while no frame has arrived', () => {
    expect(seriesStatus({ ...base, connected: false })).toBe('loading')
  })

  it('is empty only once the daemon has spoken and had nothing to say', () => {
    // Both flags together are the whole grace period: before the first frame
    // `connected` is false, and after it an empty series really is empty.
    expect(seriesStatus(base)).toBe('empty')
  })

  it('is an error before anything else', () => {
    // A panel showing no error is worse than one showing a gap.
    expect(seriesStatus({ ...base, error: 'the daemon said no', seeded: false })).toBe('error')
  })
})
