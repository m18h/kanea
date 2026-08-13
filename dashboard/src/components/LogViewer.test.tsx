import { describe, expect, it, vi, afterEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { LogViewer, lineSeverity, type LogViewerLine } from './LogViewer'

function makeLines(n: number): LogViewerLine[] {
  return Array.from({ length: n }, (_, i) => ({ key: `k${i}`, text: `line ${i}` }))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('LogViewer', () => {
  it('renders the empty text when there is nothing', () => {
    render(<LogViewer lines={[]} live emptyText="Waiting for output…" />)
    expect(screen.getByText('Waiting for output…')).toBeTruthy()
  })

  it('virtualizes: a huge buffer does not land in the DOM wholesale', () => {
    const { container } = render(<LogViewer lines={makeLines(10_000)} live emptyText="—" />)
    // jsdom has no layout, so the virtualizer renders its estimate + overscan
    // — the point is the order of magnitude, not the exact count.
    const rows = container.querySelectorAll('[data-index]')
    expect(rows.length).toBeGreaterThan(0)
    expect(rows.length).toBeLessThan(500)
  })

  it('renders prefixes as their own column', () => {
    render(
      <LogViewer
        lines={[{ key: 'a', prefix: '·0', text: 'hello' }]}
        live
        emptyText="—"
      />,
    )
    expect(screen.getByText('·0')).toBeTruthy()
    expect(screen.getByText('hello')).toBeTruthy()
  })

  it('tints severity lines without touching their content', () => {
    const { container } = render(
      <LogViewer
        lines={[
          { key: 'a', text: 'ERROR: disk full' },
          { key: 'b', text: 'warning: soon' },
          { key: 'c', text: 'all fine' },
        ]}
        live={false}
        tintSeverity
        emptyText="—"
      />,
    )
    expect(container.querySelectorAll('.text-status-error')).toHaveLength(1)
    expect(container.querySelectorAll('.text-status-warn')).toHaveLength(1)
    // Content is still a text node, verbatim.
    expect(screen.getByText('ERROR: disk full')).toBeTruthy()
  })

  it('copies the whole buffer, prefixes included', () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })

    render(
      <LogViewer
        lines={[
          { key: 'a', prefix: '·0', text: 'one' },
          { key: 'b', text: 'two' },
        ]}
        live
        toolbar={{ copy: true }}
        emptyText="—"
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Copy log' }))
    expect(writeText).toHaveBeenCalledWith('·0 one\ntwo')
    vi.unstubAllGlobals()
  })

  it('downloads under the given filename', () => {
    const clicks: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clicks.push(this.download)
    })
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn().mockReturnValue('blob:x'),
      revokeObjectURL: vi.fn(),
    })

    render(
      <LogViewer
        lines={makeLines(2)}
        live
        toolbar={{ download: { filename: 'shop-web.log' } }}
        emptyText="—"
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Download log' }))
    expect(clicks).toEqual(['shop-web.log'])
    vi.unstubAllGlobals()
  })

  it('hides the toolbar while the buffer is empty', () => {
    render(<LogViewer lines={[]} live toolbar={{ copy: true }} emptyText="—" />)
    expect(screen.queryByRole('button', { name: 'Copy log' })).toBeNull()
  })
})

describe('lineSeverity', () => {
  it.each([
    ['ERROR: it broke', 'error'],
    ['request failed with 500', 'error'],
    ['panic: nil pointer', 'error'],
    ['warning: low disk', 'warn'],
    ['WARN something', 'warn'],
    ['errors are counted here', null], // word-boundary: "errors" is not "error"
    ['ordinary line', null],
  ])('%s → %s', (text, want) => {
    expect(lineSeverity(text)).toBe(want)
  })
})
