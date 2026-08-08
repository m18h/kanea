import { describe, expect, it } from 'vitest'
import { describeArchive, isStale } from '@/lib/backups'
import type { Backup } from '@/lib/api'

function archive(over: Partial<Backup> = {}): Backup {
  return {
    id: '20260808T120000Z',
    created_at: '2026-08-08T12:00:00Z',
    index: 42,
    snapshot: { name: 'snapshots/20260808T120000Z.snap', size: 1024, sha256: 'abc' },
    ...over,
  }
}

describe('isStale', () => {
  const now = new Date('2026-08-08T12:00:00Z').getTime()

  it('accepts a single missed interval', () => {
    // Segments ship every minute against a five-minute RPO, so one missed
    // interval is normal and must not paint the page red.
    const recent = new Date(now - 3 * 60 * 1000).toISOString()
    expect(isStale(recent, now)).toBe(false)
  })

  it('flags replication that has fallen behind the RPO', () => {
    const old = new Date(now - 30 * 60 * 1000).toISOString()
    expect(isStale(old, now)).toBe(true)
  })

  it('does not call a node that has never shipped stale', () => {
    // Nothing has shipped yet: that is the empty state, and it has its own
    // message. Reporting it as staleness would describe a fresh install as a
    // failing one.
    expect(isStale(undefined, now)).toBe(false)
  })

  it('ignores a timestamp it cannot read', () => {
    expect(isStale('not a date', now)).toBe(false)
  })
})

describe('describeArchive', () => {
  it('renders counts in a fixed order', () => {
    // Object order is not guaranteed to survive a JSON round trip, and a table
    // whose cells reshuffle between renders looks broken.
    const summary = describeArchive(
      archive({ counts: { allocs: 12, services: 4, secrets: 2 } }),
    )
    expect(summary).toBe('4 services, 12 allocs, 2 secrets')
  })

  it('says nothing rather than nothing-shaped when there are no counts', () => {
    expect(describeArchive(archive())).toBe('—')
  })

  it('omits a count the manifest does not carry', () => {
    // Counts are best effort on the daemon side: one that could not be read is
    // omitted rather than reported as zero.
    expect(describeArchive(archive({ counts: { services: 1 } }))).toBe('1 services')
  })
})
