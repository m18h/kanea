import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { PaginationControls } from '@/components/Pagination'
import { DefaultPageSize, PageSizes, type Pagination } from '@/hooks/usePagination'

/**
 * The pager the lists share.
 *
 * Two properties are worth pinning. The sizes it offers are the ones the hook
 * declares, so the selector cannot drift from `PageSizes`; and it renders
 * nothing for a list that fits at the default, which is what keeps a pager
 * from appearing under a seven-row table.
 */

function state<T>(over: Partial<Pagination<T>> = {}): Pagination<T> {
  return {
    pageItems: [],
    page: 0,
    pages: 1,
    total: 0,
    start: 0,
    setPage: vi.fn(),
    pageSize: DefaultPageSize,
    setPageSize: vi.fn(),
    ...over,
  }
}

describe('PaginationControls', () => {
  it('offers exactly the sizes the hook declares', () => {
    render(
      <PaginationControls
        state={state({ total: 120, pages: 6, pageItems: Array.from({ length: 20 }, (_, i) => i) })}
      />,
    )
    const select = screen.getByRole('combobox', { name: 'Rows per page' })
    const offered = Array.from(select.querySelectorAll('option')).map((o) => Number(o.value))
    expect(offered).toEqual([...PageSizes])
    expect(offered).toEqual([20, 50, 100])
  })

  it('renders nothing for a list that fits at the default size', () => {
    const { container } = render(<PaginationControls state={state({ total: DefaultPageSize })} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders for a list one row past the default', () => {
    render(
      <PaginationControls
        state={state({
          total: DefaultPageSize + 1,
          pages: 2,
          pageItems: Array.from({ length: DefaultPageSize }, (_, i) => i),
        })}
      />,
    )
    expect(screen.getByRole('combobox', { name: 'Rows per page' })).toBeTruthy()
  })

  // The threshold is the *default* size, not the current one: choosing 100 on
  // a fifty-row list must not make the selector vanish under the reader.
  it('stays visible once a larger size has been chosen', () => {
    render(
      <PaginationControls
        state={state({
          total: 50,
          pages: 1,
          pageSize: 100,
          pageItems: Array.from({ length: 50 }, (_, i) => i),
        })}
      />,
    )
    expect(screen.getByRole('combobox', { name: 'Rows per page' })).toBeTruthy()
  })

  it('reports the window and steps through pages', () => {
    const setPage = vi.fn()
    render(
      <PaginationControls
        state={state({
          total: 120,
          pages: 6,
          page: 1,
          start: 20,
          setPage,
          pageItems: Array.from({ length: 20 }, (_, i) => i),
        })}
      />,
    )
    expect(screen.getByText('21: 40 of 120')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(setPage).toHaveBeenCalledWith(2)
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(setPage).toHaveBeenCalledWith(0)
  })
})
