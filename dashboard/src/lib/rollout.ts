import type { Alloc, Service } from './api'

export interface RolloutStatus {
  /** deploying is true while any alloc still runs a different spec. */
  deploying: boolean
  /** updated counts allocs running at the desired hash. */
  updated: number
  /** total is the declared count. */
  total: number
}

/**
 * rolloutStatus derives deploy progress from the served spec_hash (v1.64)
 * and the allocs' own hashes; the planner's staleness rule, applied
 * client-side (internal/reconciler/plan.go): an alloc with a non-empty hash
 * differing from the desired one is being replaced; an empty hash is an
 * adopted record and never counts as stale.
 *
 * Works for a deploy from any source: restart, apply, GitOps, auto-update;
 * because all of them are exactly a spec-hash mismatch. Against an older
 * daemon that serves no hash, the answer is "not deploying", never a guess.
 */
export function rolloutStatus(desired: Service, allocs: Alloc[]): RolloutStatus {
  const total = desired.Count
  const hash = desired.spec_hash
  if (!hash || total <= 0) {
    return { deploying: false, updated: allocs.length, total }
  }

  const stale = allocs.filter(
    (a) => a.spec_hash !== undefined && a.spec_hash !== '' && a.spec_hash !== hash,
  )
  const updatedRunning = allocs.filter(
    (a) =>
      a.state === 'running' &&
      (a.spec_hash === hash || a.spec_hash === '' || a.spec_hash === undefined),
  )
  // A replacement that exists at the new hash but has not started yet: the
  // window between an old alloc's teardown and its successor coming up.
  // Deliberately only 'pending': a 'backoff' alloc at the new hash is a crash
  // loop, and calling that "deploying" would disable the restart button that
  // clears it (R29).
  const pendingNew = allocs.filter((a) => a.state === 'pending' && a.spec_hash === hash)

  const deploying = stale.length > 0 || pendingNew.length > 0
  return { deploying, updated: Math.min(updatedRunning.length, total), total }
}
