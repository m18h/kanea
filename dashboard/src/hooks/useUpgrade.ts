import { useSyncExternalStore } from 'react'
import { subscribeUpgrade, upgradeState, type UpgradeState } from '@/lib/upgrade'

/** The module-level upgrade machine (PRD v1.108), as React state. */
export function useUpgrade(): UpgradeState {
  return useSyncExternalStore(subscribeUpgrade, upgradeState)
}
