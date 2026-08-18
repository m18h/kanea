/**
 * Why a chart has nothing to draw.
 *
 * The panels used to render the words "no data" the moment their buffer was
 * empty, which included the whole time the seed request was in flight. That
 * reads as *broken* where the truth was *coming*, and it was the single largest
 * contributor to the dashboard feeling slow: the fetch was fast, the message
 * was wrong.
 *
 * Pure, and in `lib/` so both a hook and a component may import it without the
 * fast-refresh hazard a module exporting a hook beside a component creates.
 */
export type SeriesStatus = 'loading' | 'empty' | 'live' | 'error'

export interface SeriesStatusInput {
  /** How many points the series holds. */
  points: number
  /**
   * The seed request has settled: succeeded, returned nothing, or failed. An
   * unsettled seed is the commonest reason a chart is briefly blank.
   */
  seeded: boolean
  /**
   * A frame has arrived on the current connection. Together with `seeded` this
   * is the whole grace period: the daemon has spoken and had nothing to say,
   * which is a different fact from not having spoken yet.
   *
   * A wall-clock grace window was tried instead and dropped. It needed the
   * clock read during render, which is impure, and it bought nothing these two
   * flags do not: before the first frame `connected` is false, and after it an
   * empty series really is empty.
   */
  connected: boolean
  /** An error to show instead of an empty state. */
  error?: string | null | undefined
}

/**
 * seriesStatus explains an empty series.
 *
 * Consulted only when there is nothing to draw: a series with points is always
 * 'live', because whatever else is true, there is a real measurement on screen.
 */
export function seriesStatus(input: SeriesStatusInput): SeriesStatus {
  if (input.error) return 'error'
  if (input.points > 0) return 'live'
  if (!input.seeded || !input.connected) return 'loading'
  return 'empty'
}
