import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Sparkline } from '@/components/Sparkline'

/**
 * The property everything upstream rests on: the daemon omits a metric it has
 * nothing recent for, and a chart that closes over the hole draws a line
 * through data nobody measured.
 */
describe('Sparkline', () => {
  it('breaks the line at a gap rather than joining across it', () => {
    render(<Sparkline points={[10, 20, undefined, 30, 40]} max={100} label="cpu" />)

    // Two segments: one before the gap and one after. A single polyline would
    // mean the chart invented a value for the missing sample.
    const chart = screen.getByLabelText('cpu')
    expect(chart.querySelectorAll('polyline')).toHaveLength(2)
  })

  it('draws one line when there are no gaps', () => {
    render(<Sparkline points={[1, 2, 3]} max={100} label="cpu" />)
    expect(screen.getByLabelText('cpu').querySelectorAll('polyline')).toHaveLength(1)
  })

  it('says so when there is nothing to draw', () => {
    // Not an empty chart: a blank rectangle reads as "measured zero", and this
    // is "measured nothing".
    render(<Sparkline points={[undefined, undefined]} label="cpu" />)
    expect(screen.getByLabelText('cpu').textContent).toBe('no data')
  })

  it('scales against the given maximum, not its own range', () => {
    // Two flat lines at very different levels must not look identical, which
    // is what self-scaling would do to a percentage.
    render(<Sparkline points={[2, 2, 2]} max={100} label="quiet" />)
    render(<Sparkline points={[90, 90, 90]} max={100} label="busy" />)

    const quiet = screen.getByLabelText('quiet').querySelector('polyline')?.getAttribute('points')
    const busy = screen.getByLabelText('busy').querySelector('polyline')?.getAttribute('points')
    expect(quiet).not.toEqual(busy)
  })

  it('clamps a value past the maximum instead of drawing outside the chart', () => {
    render(<Sparkline points={[500]} max={100} label="cpu" />)
    const points = screen.getByLabelText('cpu').querySelector('polyline')?.getAttribute('points')
    // y is measured downward from the top, so a clamped value sits at the top
    // padding, never above it, which is where 5× the ceiling would land.
    const y = Number(points?.split(',')[1])
    expect(y).toBeGreaterThanOrEqual(0)
    expect(y).toBeLessThanOrEqual(8)
  })
})
