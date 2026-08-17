import { useQuery } from '@tanstack/react-query'
import {
  fetchEvents,
  fetchRuns,
  servicesResponseSchema,
  Topic,
} from '@/lib/api'
import { useLiveTopic } from '@/hooks/useLiveTopic'

export interface NavCounts {
  services?: number | undefined
  /** functions is derived from the same services topic (a function IS a
   * service, marked); no extra request or subscription. */
  functions?: number | undefined
  buildsRunning?: number | undefined
  /** alerts is warnings + errors in the last 24 h, not a raw event total; an
   * unbounded count is noise where "something needs looking at" is the ask. */
  alerts?: number | undefined
}

/**
 * useNavCounts feeds the sidebar badges. Every source is shared with the page
 * that owns it: the services WS key and the ['runs'] / ['events', ''] query
 * keys are the same ones Pipelines and Events use, so the sidebar costs no
 * extra subscription or request when those pages are open.
 */
export function useNavCounts(): NavCounts {
  const services = useLiveTopic({ topic: Topic.Services }, servicesResponseSchema)

  const runs = useQuery({
    queryKey: ['runs'],
    queryFn: ({ signal }) => fetchRuns({ limit: 200 }, signal),
    refetchInterval: 15_000,
  })

  const alerts = useQuery({
    queryKey: ['events', ''],
    queryFn: ({ signal }) => fetchEvents({ limit: 200 }, signal),
    refetchInterval: 15_000,
    // Counted in select rather than in render: the clock read is impure, and
    // here it runs when data (or a refetch) arrives instead of on every render.
    select: (data) => {
      const dayAgo = Date.now() - 24 * 60 * 60 * 1000
      return data.events.filter((e) => e.severity !== 'info' && Date.parse(e.at) >= dayAgo).length
    },
  })

  const all = services.data?.services ?? undefined
  const fns = all?.filter((s) => s.function != null)
  return {
    services: all === undefined || fns === undefined ? undefined : all.length - fns.length,
    functions: fns?.length,
    buildsRunning: runs.data?.filter((r) => r.state === 'running' || r.state === 'queued').length,
    alerts: alerts.data,
  }
}
