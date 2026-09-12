import { fetchHealth, runUpgrade, type UpgradeResponse } from './api'

/**
 * The upgrade state machine, module-level on purpose (PRD v1.108): the
 * install-restart-reload arc must survive navigation, because the reload at
 * its end is what swaps in the new embedded dashboard, and a state machine
 * mounted inside the Updates page would lose it the moment the reader
 * clicked elsewhere. The v1.107 dialog held still to protect this; a page
 * cannot, so the machine lives above the router instead - the datetime
 * store's pattern, subscribed via useSyncExternalStore.
 */

/** `waiting` is the stretch between the daemon's answer and the new version
 * answering health, which ends in a full page reload. */
export type UpgradePhase = 'idle' | 'installing' | 'waiting'

export type UpgradeState = {
  phase: UpgradePhase
  result: UpgradeResponse | null
  error: string | null
}

let state: UpgradeState = { phase: 'idle', result: null, error: null }
const subscribers = new Set<() => void>()

function set(next: UpgradeState) {
  state = next
  subscribers.forEach((fn) => fn())
}

export function subscribeUpgrade(fn: () => void): () => void {
  subscribers.add(fn)
  return () => subscribers.delete(fn)
}

export function upgradeState(): UpgradeState {
  return state
}

/** How long to wait for the restarted daemon before giving up. The edge
 * drains, kanead runs a schema migration at startup; minutes, not seconds. */
const restartWaitMs = 3 * 60 * 1000
const healthPollMs = 2000

let pollTimer: ReturnType<typeof setInterval> | undefined

/** startUpgrade kicks off the install; a second call while one runs is a
 * no-op, matching the daemon's own 409. */
export function startUpgrade(csrf?: string) {
  if (state.phase !== 'idle') return
  set({ phase: 'installing', result: null, error: null })
  runUpgrade(undefined, csrf)
    .then((resp) => {
      if (resp.restarting) {
        set({ phase: 'waiting', result: resp, error: null })
        waitForRestart(resp)
      } else {
        set({ phase: 'idle', result: resp, error: null })
      }
    })
    .catch((err: unknown) => {
      set({ phase: 'idle', result: null, error: err instanceof Error ? err.message : String(err) })
    })
}

// Poll health until the installed version answers, then reload the whole
// page. fetchHealth failing here is expected (the daemon is down
// mid-restart) and just means "not yet".
function waitForRestart(result: UpgradeResponse) {
  const deadline = Date.now() + restartWaitMs
  clearInterval(pollTimer)
  pollTimer = setInterval(() => {
    if (Date.now() > deadline) {
      clearInterval(pollTimer)
      set({
        phase: 'idle',
        result: null,
        error:
          'kanead did not come back in time; check `journalctl -u kanead` on the node. ' +
          'If a schema migration failed, its pre-migration copy is named in the log.',
      })
      return
    }
    fetchHealth()
      .then((health) => {
        if (health.version === result.installed) window.location.reload()
      })
      .catch(() => {})
  }, healthPollMs)
}
