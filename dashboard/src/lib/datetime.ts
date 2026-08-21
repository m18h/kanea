/**
 * How the dashboard renders a moment in time.
 *
 * Every timestamp on every page goes through here, which is the point: before
 * this, three formatters disagreed. `formatClock` rendered the *time alone*, so
 * the events feed, the audit log and the scaling decisions all showed
 * `14:32:07` with no way to tell today's entry from last Tuesday's, while
 * backups and the settings view used `toLocaleString()` and showed a date in
 * whatever order the browser's locale preferred.
 *
 * The order is now a stated preference rather than a guess. `toLocaleDateString`
 * is deliberately not used for the date half: it answers with the *browser's*
 * idea of the format, which is exactly the thing this setting exists to
 * override. The time half stays 24-hour everywhere, because an ops dashboard
 * reading `2:07:33` is a dashboard you have to think about.
 *
 * The preference lives in localStorage beside the theme (`kanea-theme`), for
 * the same reason: it is a property of whoever is looking, not of the node, so
 * it belongs to the browser and not to the Store. It is also why the control
 * sits in the sidebar rather than on the Settings page, which is admin-only -
 * a viewer has just as much right to read dates in their own order.
 */

/** DateStyle is the order the date half is written in. */
export type DateStyle = 'dd/MM/yyyy' | 'MM/dd/yyyy' | 'yyyy-MM-dd'

/** DateStyles is every offered style, in the order the control cycles them. */
export const DateStyles: readonly DateStyle[] = ['dd/MM/yyyy', 'MM/dd/yyyy', 'yyyy-MM-dd']

/** DefaultDateStyle is day-first. */
export const DefaultDateStyle: DateStyle = 'dd/MM/yyyy'

/** ShortDateStyle labels a style for a control with no room for the full form. */
export const ShortDateStyle: Record<DateStyle, string> = {
  'dd/MM/yyyy': 'dd/mm',
  'MM/dd/yyyy': 'mm/dd',
  'yyyy-MM-dd': 'iso',
}

const storageKey = 'kanea-date-style'

function isDateStyle(value: unknown): value is DateStyle {
  return DateStyles.includes(value as DateStyle)
}

function load(): DateStyle {
  // Guarded because a browser can refuse storage entirely (private mode, a
  // locked-down profile), and a dashboard that will not render because it
  // could not read a display preference is a worse outcome than a default.
  try {
    const stored = window.localStorage.getItem(storageKey)
    if (isDateStyle(stored)) return stored
  } catch {
    /* fall through to the default */
  }
  return DefaultDateStyle
}

let current: DateStyle = load()
const listeners = new Set<() => void>()

/** dateStyle is the style in force right now. */
export function dateStyle(): DateStyle {
  return current
}

/** setDateStyle persists a choice and tells every subscriber. */
export function setDateStyle(next: DateStyle): void {
  if (next === current) return
  current = next
  try {
    window.localStorage.setItem(storageKey, next)
  } catch {
    // The choice still applies to this session; it just will not outlive it.
  }
  for (const notify of listeners) notify()
}

/** subscribeDateStyle registers a listener and returns its unsubscribe. */
export function subscribeDateStyle(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** nextDateStyle is the style after this one, wrapping: the control cycles. */
export function nextDateStyle(style: DateStyle): DateStyle {
  const at = DateStyles.indexOf(style)
  return DateStyles[(at + 1) % DateStyles.length] as DateStyle
}

function pad(n: number): string {
  return String(n).padStart(2, '0')
}

/** formatDate renders the date half in the given style, in local time. */
export function formatDate(at: Date, style: DateStyle = current): string {
  const year = String(at.getFullYear()).padStart(4, '0')
  const month = pad(at.getMonth() + 1)
  const day = pad(at.getDate())
  switch (style) {
    case 'MM/dd/yyyy':
      return `${month}/${day}/${year}`
    case 'yyyy-MM-dd':
      return `${year}-${month}-${day}`
    default:
      return `${day}/${month}/${year}`
  }
}

/** formatTimeOfDay renders the time half: 24-hour, always, seconds included. */
export function formatTimeOfDay(at: Date): string {
  return `${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`
}

/**
 * formatDateTime renders a timestamp as date and time.
 *
 * An unparseable value passes through rather than becoming "Invalid Date": the
 * input is a daemon-supplied string, and showing what arrived is more useful
 * than showing that JavaScript could not read it.
 */
export function formatDateTime(iso: string, style: DateStyle = current): string {
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return iso
  return `${formatDate(at, style)} ${formatTimeOfDay(at)}`
}

/** isZeroTime reports Go's zero time, which the API sends for "never". */
export function isZeroTime(iso: string | undefined): boolean {
  if (!iso) return true
  return iso.startsWith('0001-01-01')
}

/** timeOrNever renders a timestamp, or "never" for absence and the zero time. */
export function timeOrNever(iso: string | undefined, style: DateStyle = current): string {
  if (isZeroTime(iso)) return 'never'
  return formatDateTime(iso as string, style)
}
