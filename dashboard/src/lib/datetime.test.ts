import { afterEach, describe, expect, it } from 'vitest'

import {
  DateStyles,
  DefaultDateStyle,
  dateStyle,
  formatDate,
  formatDateTime,
  formatTimeOfDay,
  isZeroTime,
  setDateStyle,
  subscribeDateStyle,
  timeOrNever,
} from '@/lib/datetime'

// A fixed local moment: the 2nd of a month, so a day-first and a month-first
// rendering are different strings rather than accidentally equal.
const at = new Date(2026, 7, 2, 9, 5, 7) // 2 August 2026, 09:05:07 local
const iso = at.toISOString()

afterEach(() => {
  setDateStyle(DefaultDateStyle)
  window.localStorage.clear()
})

describe('formatDate', () => {
  it('writes each style in its own order', () => {
    expect(formatDate(at, 'dd/MM/yyyy')).toBe('02/08/2026')
    expect(formatDate(at, 'MM/dd/yyyy')).toBe('08/02/2026')
    expect(formatDate(at, 'yyyy-MM-dd')).toBe('2026-08-02')
  })

  it('pads every field, so the columns line up', () => {
    // The tables these land in are mono and nowrap; a one-digit day would make
    // every row a different width.
    expect(formatDate(new Date(2026, 0, 1, 0, 0, 0), 'dd/MM/yyyy')).toBe('01/01/2026')
  })
})

describe('formatTimeOfDay', () => {
  it('is 24-hour with seconds, always', () => {
    // Not the locale's choice: an ops dashboard reading "9:05:07 PM" is one you
    // have to think about, and the seconds are what make two events orderable.
    expect(formatTimeOfDay(at)).toBe('09:05:07')
    expect(formatTimeOfDay(new Date(2026, 7, 2, 21, 5, 7))).toBe('21:05:07')
  })
})

describe('formatDateTime', () => {
  it('renders the date and the time, which is the whole point', () => {
    // Before this the dashboard showed the time alone, so there was no way to
    // tell today's event from last Tuesday's.
    expect(formatDateTime(iso, 'dd/MM/yyyy')).toBe('02/08/2026 09:05:07')
  })

  it('passes an unparseable value through rather than saying Invalid Date', () => {
    // The input is a daemon-supplied string; showing what arrived is more use
    // than showing that JavaScript could not read it.
    expect(formatDateTime('not a timestamp')).toBe('not a timestamp')
  })

  it('follows the current style when none is given', () => {
    setDateStyle('dd/MM/yyyy')
    expect(formatDateTime(iso)).toBe('02/08/2026 09:05:07')
  })
})

describe('timeOrNever', () => {
  it('renders Go\'s zero time and absence as never', () => {
    expect(timeOrNever(undefined)).toBe('never')
    expect(timeOrNever('0001-01-01T00:00:00Z')).toBe('never')
    expect(isZeroTime('0001-01-01T00:00:00Z')).toBe(true)
  })

  it('renders a real timestamp in the chosen style', () => {
    expect(timeOrNever(iso, 'MM/dd/yyyy')).toBe('08/02/2026 09:05:07')
  })
})

describe('the preference', () => {
  it('defaults to ISO 8601', () => {
    // Big-endian is the one order unambiguous to every reader: 03/04 is two
    // different days depending on where you learned to write dates.
    expect(DefaultDateStyle).toBe('yyyy-MM-dd')
    expect(dateStyle()).toBe('yyyy-MM-dd')
  })

  it('persists a choice and notifies subscribers', () => {
    let notified = 0
    const stop = subscribeDateStyle(() => {
      notified++
    })

    // Deliberately not the default, or the first call would be the no-op the
    // idempotence check below is testing for.
    setDateStyle('dd/MM/yyyy')
    expect(dateStyle()).toBe('dd/MM/yyyy')
    expect(notified).toBe(1)
    expect(window.localStorage.getItem('kanea-date-style')).toBe('dd/MM/yyyy')

    // Idempotent: setting the style it already has notifies nobody, or every
    // render that re-asserted the current value would be a re-render storm.
    setDateStyle('dd/MM/yyyy')
    expect(notified).toBe(1)

    stop()
    setDateStyle('MM/dd/yyyy')
    expect(notified).toBe(1)
  })

  it('offers the default among the styles the picker lists', () => {
    // The picker renders DateStyles; a default outside that list would show as
    // a select with nothing selected.
    expect(DateStyles).toContain(DefaultDateStyle)
    expect(new Set(DateStyles).size).toBe(DateStyles.length)
  })
})
