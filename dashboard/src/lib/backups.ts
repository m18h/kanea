import type { Backup } from './api'

/**
 * Presentation helpers for the archive list.
 *
 * In lib rather than beside the page because they are pure, they are tested,
 * and a component file that also exports functions breaks fast refresh — the
 * page reloads instead of updating, which makes the dashboard tedious to work
 * on for no benefit.
 */

/** formatTime renders a timestamp in the reader's locale, or passes it through. */
export function formatTime(iso: string): string {
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return iso
  return at.toLocaleString()
}

/** describeArchive summarises an archive's contents without decrypting it. */
export function describeArchive(archive: Backup): string {
  const counts = archive.counts ?? {}
  // A fixed order rather than object order, so two renders of the same page
  // produce the same string.
  const parts = ['services', 'allocs', 'secrets', 'certs', 'projects']
    .filter((key) => counts[key] !== undefined)
    .map((key) => `${counts[key]} ${key}`)
  return parts.length > 0 ? parts.join(', ') : '—'
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
export function when(iso: string | undefined): string {
  if (!iso) return 'never'
  return formatTime(iso)
}
