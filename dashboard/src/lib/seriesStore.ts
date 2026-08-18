/**
 * The page's accumulated metric series, above the components that draw them.
 *
 * Every buffer used to be a `useRef` inside the panel that showed it, so
 * leaving a page and coming back threw away minutes of samples and rebuilt from
 * a fresh seed request. The samples outlive the components now; the components
 * retain a key while they are mounted and read a snapshot of it.
 *
 * It lives in `lib/` and exports only functions, types and consts, which is the
 * same rule `lib/live.ts` follows and the reason the hooks are next door: a
 * module that exports both a hook and a component breaks fast refresh, and
 * every consumer remounts on each edit.
 *
 * Memory: an entry is two arrays of at most `maxTimedPoints`, a slot grid of
 * `SparklineLength`, and one snapshot copy of the first two, so roughly 20 KB.
 * A session that has visited the Overview and one service with a dozen allocs
 * holds about 33 keys, so under a megabyte; `maxSeriesKeys` bounds the worst
 * case at about five.
 */

/** TimedSeries is a series over real time: aligned unix-seconds and values,
 * null marking a gap; uPlot's native vocabulary. */
export interface TimedSeries {
  times: number[]
  values: (number | null)[]
}

/**
 * How many samples a sparkline keeps.
 *
 * At the daemon's five-second cadence this is five minutes: enough to see a
 * spike arrive and settle, short enough that the shape stays readable at the
 * width a table cell allows.
 */
export const SparklineLength = 60

/** How many timed points a chart keeps: the 15 m history window at the 5 s
 * cadence, with headroom for a long-open page. */
export const maxTimedPoints = 400

/** A silence longer than this breaks the line: the samples on either side are
 * real, the time between them was never measured. */
export const gapSeconds = 30

/**
 * How long an unreferenced entry survives. Matched to TanStack's default
 * `gcTime`, because the same navigation that drops a query's last observer
 * drops this key's last reader.
 */
export const retainMs = 5 * 60_000

/**
 * The hard cap. A bound on memory, not on correctness: a referenced entry is
 * never evicted, because a visible chart going blank is worse than the bytes.
 */
export const maxSeriesKeys = 256

/** A key is a subject and a metric. Subjects are 'node', 'project/service', or
 * 'project/service#alloc' for a per-alloc series. */
export type SeriesKey = string & { readonly __series: unique symbol }

export function seriesKey(subject: string, metric: string): SeriesKey {
  return `${subject}|${metric}` as SeriesKey
}

/** allocSubject names one alloc's series, distinct from its service's. */
export function allocSubject(service: string, allocID: string): string {
  return `${service}#${allocID}`
}

interface Entry {
  times: number[]
  values: (number | null)[]
  /** The fixed-slot grid a sparkline draws, sharing this entry's dedupe guard
   * so the two representations cannot disagree about what has been seen. */
  slots: (number | undefined)[]
  /** The newest sample's timestamp: the idempotence key. */
  lastAt: string
  snapshot: TimedSeries
  slotSnapshot: (number | undefined)[]
  refs: number
  releasedAt: number
  listeners: Set<() => void>
}

const entries = new Map<SeriesKey, Entry>()

const emptySnapshot: TimedSeries = { times: [], values: [] }
const emptySlots: (number | undefined)[] = []

function newEntry(): Entry {
  return {
    times: [],
    values: [],
    slots: [],
    lastAt: '',
    snapshot: emptySnapshot,
    slotSnapshot: emptySlots,
    refs: 0,
    // Stamped as if just released, so an entry created by a write that no
    // component ever retains is still swept after retainMs rather than held
    // for the life of the tab.
    releasedAt: Date.now(),
    listeners: new Set(),
  }
}

/**
 * Fetch an entry, creating it if a write arrived first.
 *
 * Writes genuinely do arrive first: a hook records during render and retains in
 * an effect, so the very first sample of a mount reaches the store before the
 * reference does. Requiring retain() to have run would silently drop it, which
 * is a point missing from the left edge of every freshly opened chart.
 */
function ensure(key: SeriesKey): Entry {
  let entry = entries.get(key)
  if (!entry) {
    entry = newEntry()
    entries.set(key, entry)
  }
  return entry
}

/**
 * Drop what nobody is reading and nothing recent has touched.
 *
 * Swept on access rather than on a timer, deliberately: a `setInterval` in a
 * module keeps a hidden tab awake for housekeeping nobody is waiting on.
 */
function sweep(now: number): void {
  for (const [key, entry] of entries) {
    if (entry.refs === 0 && now - entry.releasedAt > retainMs) entries.delete(key)
  }
  if (entries.size < maxSeriesKeys) return

  // Past the cap, evict the coldest unreferenced entries. A referenced one is
  // never taken: the cap is a memory guard, and a chart somebody is looking at
  // must not go blank to satisfy it.
  const cold = [...entries.entries()]
    .filter(([, entry]) => entry.refs === 0)
    .sort((a, b) => a[1].releasedAt - b[1].releasedAt)
  for (const [key] of cold) {
    if (entries.size < maxSeriesKeys) break
    entries.delete(key)
  }
}

/**
 * Take a reference to a key, returning the release.
 *
 * There is deliberately no "this data is too old to reuse" check here. The two
 * bounds that already exist cover it exactly: an entry nobody has referenced
 * for `retainMs` is swept, so coming back much later starts clean, and coming
 * back sooner keeps a tail whose age the gap break and the real time axis both
 * show honestly. A staleness rule on top of those turned out to delete entries
 * that had just been written, because a hook records during render and retains
 * in the effect after it.
 */
export function retain(key: SeriesKey, now = Date.now()): () => void {
  sweep(now)

  const entry = ensure(key)
  entry.refs++
  entry.releasedAt = 0

  let released = false
  return () => {
    if (released) return
    released = true
    const current = entries.get(key)
    if (!current) return
    current.refs = Math.max(0, current.refs - 1)
    if (current.refs === 0) current.releasedAt = Date.now()
  }
}

/** subscribe is retain plus a change notification, for a reader that is not
 * already re-rendered by whatever produced the sample. */
export function subscribe(key: SeriesKey, onChange: () => void): () => void {
  const release = retain(key)
  entries.get(key)?.listeners.add(onChange)
  return () => {
    entries.get(key)?.listeners.delete(onChange)
    release()
  }
}

function notify(entry: Entry): void {
  if (entry.listeners.size === 0) return
  // Deferred: a record during one component's render must not synchronously
  // schedule a state update in another.
  queueMicrotask(() => {
    for (const listener of entry.listeners) listener()
  })
}

/**
 * Record one live sample.
 *
 * Idempotent and monotonic, which is what makes it safe to call during render:
 * a sample is keyed on its timestamp, one at or behind the newest is refused,
 * and the snapshot's identity changes only when a point actually lands. A
 * StrictMode double render therefore records nothing twice, a discarded
 * concurrent render records exactly what its retry would have, and two
 * components sharing a key record once between them.
 *
 * That last property is also the `UPlotChart` contract: it calls `setData` on
 * the snapshot's identity, so a no-op record must not change it.
 *
 * `undefined` is stored as a gap rather than skipped or zeroed: the daemon
 * omits a metric it has nothing recent for, and a chart that closes over the
 * hole draws a line through data nobody measured.
 */
export function record(key: SeriesKey, value: number | undefined, at: string): void {
  if (at === '') return
  const entry = ensure(key)
  if (at === entry.lastAt) return
  if (entry.lastAt !== '' && at < entry.lastAt) return

  const t = Date.parse(at) / 1000
  if (!Number.isFinite(t)) return
  const previous = entry.times.at(-1)
  if (previous !== undefined && t <= previous) return

  entry.lastAt = at
  if (previous !== undefined && t - previous > gapSeconds) {
    entry.times.push(previous + 1)
    entry.values.push(null)
  }
  entry.times.push(t)
  entry.values.push(value ?? null)
  if (entry.times.length > maxTimedPoints) {
    entry.times = entry.times.slice(-maxTimedPoints)
    entry.values = entry.values.slice(-maxTimedPoints)
  }
  entry.slots = [...entry.slots, value].slice(-SparklineLength)

  entry.snapshot = { times: [...entry.times], values: [...entry.values] }
  entry.slotSnapshot = [...entry.slots]
  notify(entry)
}

/** A seed: a window of history and the timestamp of its newest point. */
export interface Seed {
  times: number[]
  values: (number | null)[]
  asOf: string
}

/**
 * Prepend a history window under whatever has already accumulated.
 *
 * Only the portion older than the oldest held point is taken, which does three
 * jobs at once. It stops the overlap between "history up to T" and the first
 * live frames from being counted twice. It makes the call **idempotent**: after
 * the first seed the oldest held point is the seed's own first point, so
 * repeating it prepends nothing, which is what lets a hook call this on every
 * render without a "have I seeded yet" flag. And it makes a stale cached seed
 * harmless rather than something to detect: whatever part of it predates the
 * live tail is true history and belongs on the left, and the rest is discarded.
 */
export function seed(key: SeriesKey, s: Seed): void {
  if (s.times.length === 0) return
  const entry = ensure(key)

  const oldest = entry.times.at(0)
  const times: number[] = []
  const values: (number | null)[] = []
  for (let i = 0; i < s.times.length; i++) {
    const t = s.times[i]
    if (t === undefined) continue
    if (oldest !== undefined && t >= oldest) break
    times.push(t)
    values.push(s.values[i] ?? null)
  }
  if (times.length === 0) return

  entry.times = [...times, ...entry.times].slice(-maxTimedPoints)
  entry.values = [...values, ...entry.values].slice(-maxTimedPoints)
  if (entry.lastAt === '') entry.lastAt = s.asOf

  entry.snapshot = { times: [...entry.times], values: [...entry.values] }
  notify(entry)
}

/** seedSlots prepends a slot-grid seed, for the sparkline representation. */
export function seedSlots(key: SeriesKey, points: (number | undefined)[], asOf: string): void {
  if (points.length === 0) return
  const entry = ensure(key)
  if (entry.lastAt !== '' && asOf <= entry.lastAt) return

  entry.slots = [...points, ...entry.slots].slice(-SparklineLength)
  if (entry.lastAt === '') entry.lastAt = asOf
  entry.slotSnapshot = [...entry.slots]
  notify(entry)
}

/** The newest sample's timestamp, or '' when nothing has been recorded. */
export function lastAtOf(key: SeriesKey): string {
  return entries.get(key)?.lastAt ?? ''
}

/** snapshotOf is the timed series a chart draws. Its identity changes exactly
 * when a point lands, which is what lets uPlot call setData only then. */
export function snapshotOf(key: SeriesKey): TimedSeries {
  return entries.get(key)?.snapshot ?? emptySnapshot
}

/** slotsOf is the fixed-slot grid a sparkline draws. */
export function slotsOf(key: SeriesKey): (number | undefined)[] {
  return entries.get(key)?.slotSnapshot ?? emptySlots
}

/** clearAll drops everything. For tests, and for a sign-out: the series belong
 * to the session that collected them. */
export function clearAll(): void {
  entries.clear()
}

/** size reports how many keys are held. For tests and diagnostics. */
export function size(): number {
  return entries.size
}
