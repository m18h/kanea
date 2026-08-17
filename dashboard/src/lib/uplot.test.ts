import { describe, expect, it } from 'vitest'
import { buildOptions, chartColors, paddedRange, percentRange, smoothValues, timeLabel } from './uplot'

describe('smoothValues', () => {
  it('averages a centered window', () => {
    expect(smoothValues([0, 10, 20], 3)).toEqual([5, 10, 15])
  })

  it('a gap stays a gap and never borrows across one', () => {
    const out = smoothValues([10, 10, null, 90, 90], 3)
    expect(out[2]).toBeNull()
    // The neighbours of the gap only average their own side.
    expect(out[1]).toBe(10)
    expect(out[3]).toBe(90)
  })

  it('a wide window still stops at the gap, not merely skips it', () => {
    // The regression: window 5 reaches two steps out, and a walk that skipped
    // the null would pick up the 90s beyond it.
    const out = smoothValues([10, 10, null, 90, 90], 5)
    expect(out[0]).toBe(10)
    expect(out[1]).toBe(10)
    expect(out[3]).toBe(90)
  })

  it('window 1 is the identity', () => {
    const values = [1, null, 3]
    expect(smoothValues(values, 1)).toBe(values)
  })
})

describe('timeLabel', () => {
  it('renders one HH:MM line', () => {
    expect(timeLabel(Date.UTC(2026, 7, 13, 0, 0, 0) / 1000)).toMatch(/^\d{2}:\d{2}$/)
  })
})

describe('ranges', () => {
  it('percent is pinned 0-100', () => {
    expect(percentRange()).toEqual([0, 100])
  })

  it('auto pads 10% over the max with a zero floor', () => {
    expect(paddedRange(200)).toEqual([0, 220.00000000000003])
    expect(paddedRange(200)[1]).toBeCloseTo(220)
  })

  it('an empty or zero series gets a sane scale, not a degenerate one', () => {
    expect(paddedRange(0)).toEqual([0, 1])
    expect(paddedRange(-5)).toEqual([0, 1])
    expect(paddedRange(Number.NaN)).toEqual([0, 1])
  })
})

describe('buildOptions', () => {
  const theme = {
    stroke: { 1: 's1', 2: 's2', 3: 's3', 4: 's4' },
    fill: { 1: 'f1', 2: 'f2', 3: 'f3', 4: 'f4' },
    grid: 'g',
    axis: 'a',
  } as const

  const opts = (scale: 'percent' | 'auto', tone: 1 | 2 | 3 | 4 = 1) =>
    buildOptions({
      width: 300,
      height: 96,
      tone,
      scale,
      theme,
      formatValue: (v) => `${v}%`,
    })

  it('the series never spans gaps: absent is never a drawn line', () => {
    const series = opts('percent').series[1]
    expect(series?.spanGaps).toBe(false)
  })

  it('the x scale is time', () => {
    expect(opts('percent').scales?.x?.time).toBe(true)
  })

  it('percent pins the y range and auto pads it', () => {
    expect(opts('percent').scales?.y?.range).toEqual([0, 100])
    const range = opts('auto').scales?.y?.range
    expect(typeof range).toBe('function')
  })

  it('tone selects the stroke and fill', () => {
    const series = opts('auto', 3).series[1]
    expect(series?.stroke).toBe('s3')
    expect(series?.fill).toBe('f3')
  })

  it('the legend is off: the panel readout is the legend', () => {
    expect(opts('percent').legend?.show).toBe(false)
  })
})

describe('chartColors', () => {
  it('reads hsl triplets off the document root', () => {
    document.documentElement.style.setProperty('--chart-1', '40 100% 39%')
    document.documentElement.style.setProperty('--border', '40 10% 88%')
    document.documentElement.style.setProperty('--muted-foreground', '240 5% 42%')
    const theme = chartColors()
    expect(theme.stroke[1]).toBe('hsl(40 100% 39%)')
    expect(theme.fill[1]).toBe('hsl(40 100% 39% / 0.12)')
    expect(theme.grid).toBe('hsl(40 10% 88% / 0.6)')
    expect(theme.axis).toBe('hsl(240 5% 42%)')
  })
})
