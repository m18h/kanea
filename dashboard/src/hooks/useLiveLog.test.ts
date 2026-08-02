import { describe, expect, it } from 'vitest'
import { MaxLogLines } from './useLiveLog'

describe('MaxLogLines', () => {
  // A tab left open on a chatty service would otherwise grow without limit:
  // the daemon streams as fast as the workload writes.
  it('is a bound a browser can actually hold', () => {
    expect(MaxLogLines).toBeGreaterThan(100)
    expect(MaxLogLines).toBeLessThanOrEqual(10_000)
  })
})
