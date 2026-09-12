import { useQuery } from '@tanstack/react-query'
import { fetchUpdates, fetchUpgradeCheck } from '@/lib/api'
import { useSession } from './useSession'

/**
 * The two update queries (PRD v1.107/v1.108), shared by the sidebar badge
 * and the Updates page through their query keys so neither costs a second
 * probe. Both run only for an admin with a dashboard open: that cadence,
 * against the daemon's caches, is the outer bound of how often a node checks
 * anything at all.
 */

export function useUpgradeCheckQuery(enabled: boolean) {
  return useQuery({
    queryKey: ['upgrade-check'],
    queryFn: ({ signal }) => fetchUpgradeCheck(signal),
    enabled,
    refetchInterval: 6 * 60 * 60 * 1000,
    staleTime: 60 * 60 * 1000,
  })
}

export function useUpdatesQuery(enabled: boolean) {
  return useQuery({
    queryKey: ['updates'],
    queryFn: ({ signal }) => fetchUpdates(signal),
    enabled,
    refetchInterval: 30 * 60 * 1000,
    staleTime: 5 * 60 * 1000,
  })
}

/**
 * How many things on the Updates page need attention: a newer release, a
 * pending reboot. The sidebar badge's number; 0 for a non-admin, whose page
 * holds no controls anyway.
 */
export function useUpdateAttention(): number {
  const { session } = useSession()
  const admin = session?.role === 'admin'
  const check = useUpgradeCheckQuery(admin)
  const updates = useUpdatesQuery(admin)
  return (check.data?.update_available ? 1 : 0) + (updates.data?.os.reboot_required ? 1 : 0)
}
