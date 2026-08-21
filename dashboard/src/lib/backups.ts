import type { Backup } from './api'

/**
 * Presentation helpers for the archive list.
 *
 * In lib rather than beside the page because they are pure, they are tested,
 * and a component file that also exports functions breaks fast refresh: the
 * page reloads instead of updating, which makes the dashboard tedious to work
 * on for no benefit.
 */

import { type DateStyle, formatDateTime } from '@/lib/datetime'

export { formatDateTime as formatTime } from '@/lib/datetime'

/** describeArchive summarises an archive's contents without decrypting it. */
export function describeArchive(archive: Backup): string {
  const counts = archive.counts ?? {}
  // A fixed order rather than object order, so two renders of the same page
  // produce the same string.
  const parts = ['services', 'allocs', 'secrets', 'certs', 'projects']
    .filter((key) => counts[key] !== undefined)
    .map((key) => `${counts[key]} ${key}`)
  return parts.length > 0 ? parts.join(', ') : '-'
}

/**
 * isStale reports replication that has fallen behind its RPO.
 *
 * Ten minutes, not five: the target is a five-minute RPO and segments ship
 * every minute, so a single missed interval is normal and should not paint the
 * page red. Two missed intervals plus the target is a real signal.
 */
export function isStale(last: string | undefined, now: number = Date.now()): boolean {
  if (!last) return false // nothing has shipped yet; that is the empty state, not staleness
  const at = new Date(last).getTime()
  if (Number.isNaN(at)) return false
  return now - at > 10 * 60 * 1000
}

/** describeReplication renders "never" for a destination nothing has reached. */
export function when(iso: string | undefined, style?: DateStyle): string {
  if (!iso) return 'never'
  return formatDateTime(iso, style)
}

/**
 * replicationLag renders how far behind the sink is, derived from the last
 * shipped segment: there is no lag field on the wire, and pretending to
 * sub-second precision would be inventing a number. Segments ship about once
 * a minute, so a healthy node reads in seconds-to-minutes.
 */
export function replicationLag(last: string | undefined, now: number = Date.now()): string {
  if (!last) return 'never'
  const at = new Date(last).getTime()
  if (Number.isNaN(at)) return 'never'
  const seconds = Math.max(0, Math.floor((now - at) / 1000))
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m`
  return `${Math.floor(seconds / 3_600)}h`
}
