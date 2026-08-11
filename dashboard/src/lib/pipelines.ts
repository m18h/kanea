import type { BadgeProps } from '@/components/ui/badge'
import type { Run, RunStep } from '@/lib/api'

/** runStateVariant maps a run state onto a badge colour. */
export function runStateVariant(state: string): NonNullable<BadgeProps['variant']> {
  switch (state) {
    case 'succeeded':
      return 'ok'
    case 'running':
      return 'accent'
    case 'queued':
      return 'warn'
    case 'failed':
      return 'error'
    default:
      return 'muted'
  }
}

/** runStateLabel renders a state the way the pipeline table reads: a running
 * run is "building", a succeeded one is "ok". The state names stay on the
 * wire; only the pill's word changes. */
export function runStateLabel(state: string): string {
  switch (state) {
    case 'running':
      return 'building'
    case 'succeeded':
      return 'ok'
    default:
      return state
  }
}

/**
 * runDuration is how long a run took, or has been going.
 *
 * A running build is measured against now, so the number moves while you watch
 * it. A finished one is measured against its own end, so it stops — a duration
 * that kept climbing after a build ended would be a lie about a finished thing.
 */
export function runDuration(run: Run, now: number = Date.now()): string {
  const ms = runDurationMs(run, now)
  return ms === undefined ? '—' : humanDuration(ms)
}

/** runDurationMs is the same number before rendering — what a sorted Duration
 * column compares, where "unparseable" must stay distinct from "instant". */
export function runDurationMs(run: Run, now: number = Date.now()): number | undefined {
  const started = Date.parse(run.started_at)
  if (!Number.isFinite(started)) return undefined

  const ended = run.finished_at ? Date.parse(run.finished_at) : now
  if (!Number.isFinite(ended)) return undefined
  return Math.max(0, ended - started)
}

/** stepDuration is the same for one step. */
export function stepDuration(step: RunStep, now: number = Date.now()): string {
  const started = Date.parse(step.started_at)
  if (!Number.isFinite(started)) return '—'

  const ended = step.finished_at ? Date.parse(step.finished_at) : now
  if (!Number.isFinite(ended)) return '—'
  return humanDuration(Math.max(0, ended - started))
}

/** humanDuration renders milliseconds the way a build log reads. */
export function humanDuration(ms: number): string {
  if (ms < 1_000) return `${Math.round(ms)}ms`
  const seconds = ms / 1_000
  if (seconds < 60) return `${seconds.toFixed(1)}s`

  const minutes = Math.floor(seconds / 60)
  const rest = Math.round(seconds % 60)
  if (minutes < 60) return `${minutes}m${rest.toString().padStart(2, '0')}s`
  return `${Math.floor(minutes / 60)}h${(minutes % 60).toString().padStart(2, '0')}m`
}

/** shortID abbreviates a run id, matching what the CLI prints. */
export function shortID(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id
}

/** shortSHA abbreviates a commit. */
export function shortSHA(sha: string | undefined): string {
  if (!sha) return '—'
  return sha.length > 7 ? sha.slice(0, 7) : sha
}
