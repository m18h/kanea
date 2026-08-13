import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import { Skeleton } from './ui/skeleton'
import { CardSkeleton, ChartSkeleton, KeyValueSkeleton, TableSkeleton } from './Skeletons'

describe('skeletons', () => {
  it('the primitive is hidden from assistive tech and pulses', () => {
    const { container } = render(<Skeleton className="h-4 w-24" />)
    const el = container.firstElementChild
    expect(el?.getAttribute('aria-hidden')).toBe('true')
    expect(el?.className).toContain('animate-pulse')
  })

  it('KeyValueSkeleton renders the requested number of rows', () => {
    const { container } = render(<KeyValueSkeleton rows={6} />)
    expect(container.querySelectorAll(':scope > div > div')).toHaveLength(6)
  })

  it('TableSkeleton renders a header row plus the requested body rows', () => {
    const { container } = render(<TableSkeleton rows={5} cols={3} />)
    const rows = container.querySelectorAll('.flex.gap-4')
    expect(rows).toHaveLength(6) // header + 5
    expect(rows[0]?.children).toHaveLength(3)
  })

  it('CardSkeleton can drop its title line', () => {
    const withTitle = render(<CardSkeleton lines={2} />)
    const without = render(<CardSkeleton lines={2} title={false} />)
    expect(withTitle.container.firstElementChild?.children).toHaveLength(3)
    expect(without.container.firstElementChild?.children).toHaveLength(2)
  })

  it('ChartSkeleton sizes its chart area by variant', () => {
    const big = render(<ChartSkeleton big />)
    expect(big.container.innerHTML).toContain('h-24')
    const compact = render(<ChartSkeleton />)
    expect(compact.container.innerHTML).toContain('h-16')
  })
})
