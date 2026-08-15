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

  describe('expand', () => {
    it('is absent unless the caller asks for it', () => {
      render(<LogViewer lines={makeLines(3)} live emptyText="—" toolbar={{ copy: true }} />)
      expect(screen.queryByRole('button', { name: 'Expand log' })).toBeNull()
    })

    it('opens the buffer in a dialog and closes again', () => {
      render(
        <LogViewer lines={makeLines(3)} live emptyText="—" toolbar={{ expand: true }} title="shop/web — logs" />,
      )
      expect(screen.queryByRole('dialog')).toBeNull()

      fireEvent.click(screen.getByRole('button', { name: 'Expand log' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog).toBeTruthy()
      expect(screen.getByText('shop/web — logs')).toBeTruthy()
      // The lines moved into the dialog rather than being rendered twice.
      expect(dialog.querySelectorAll('[data-index]').length).toBeGreaterThan(0)

      fireEvent.click(screen.getByRole('button', { name: 'Close' }))
      expect(screen.queryByRole('dialog')).toBeNull()
      expect(screen.getByText('line 0')).toBeTruthy()
    })

    it('closes on Escape', () => {
      render(<LogViewer lines={makeLines(3)} live emptyText="—" toolbar={{ expand: true }} />)
      fireEvent.click(screen.getByRole('button', { name: 'Expand log' }))
      fireEvent.keyDown(document, { key: 'Escape' })
      expect(screen.queryByRole('dialog')).toBeNull()
    })

    // Copy and Download have nothing to act on with an empty buffer, but
    // "waiting for output" is a thing people sit and watch.
    it('is offered on an empty buffer, unlike the other actions', () => {
      render(
        <LogViewer lines={[]} live emptyText="Waiting for output…" toolbar={{ copy: true, expand: true }} />,
      )
      expect(screen.getByRole('button', { name: 'Expand log' })).toBeTruthy()
      expect(screen.queryByRole('button', { name: 'Copy log' })).toBeNull()
    })

    it('renders the caller controls inside the dialog so they stay reachable', () => {
      render(
        <LogViewer
          lines={makeLines(3)}
          live
          emptyText="—"
          toolbar={{ expand: true }}
          controls={<button type="button">Follow</button>}
        />,
      )
      fireEvent.click(screen.getByRole('button', { name: 'Expand log' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog.querySelector('button')).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Follow' })).toBeTruthy()
    })

    it('holds the card space while the viewer is in the dialog', () => {
      const { container } = render(
        <LogViewer lines={makeLines(3)} live emptyText="—" toolbar={{ expand: true }} />,
      )
      fireEvent.click(screen.getByRole('button', { name: 'Expand log' }))
      // The placeholder keeps the layout from collapsing behind the backdrop,
      // which would show as a jump the moment it closes.
      expect(container.querySelector('[aria-hidden]')).toBeTruthy()
    })
  })

  // The snap-back regression (PRD v1.70): follow used to short-circuit the
  // pinned check entirely, so scrolling up on the service page was ignored.
  describe('scroll drives follow', () => {
    // jsdom has no layout, so the scroll container's metrics are stubbed
    // directly — the component reads exactly these three numbers.
    function scrollTo(el: Element, { top, height, client }: Record<string, number>) {
      Object.defineProperty(el, 'scrollTop', { value: top, configurable: true })
      Object.defineProperty(el, 'scrollHeight', { value: height, configurable: true })
      Object.defineProperty(el, 'clientHeight', { value: client, configurable: true })
      fireEvent.scroll(el)
    }

    function scroller(container: HTMLElement): Element {
      const el = container.querySelector('.overflow-auto')
      if (!el) throw new Error('no scroll container')
      return el
    }

    it('reports false when the reader scrolls away from the tail', () => {
      const onFollowChange = vi.fn()
      const { container } = render(
        <LogViewer lines={makeLines(50)} live follow onFollowChange={onFollowChange} emptyText="—" />,
      )
      scrollTo(scroller(container), { top: 0, height: 1000, client: 200 })
      expect(onFollowChange).toHaveBeenCalledWith(false)
    })

    it('reports true again when the reader returns to within the slack', () => {
      const onFollowChange = vi.fn()
      const { container } = render(
        <LogViewer
          lines={makeLines(50)}
          live
          follow={false}
          onFollowChange={onFollowChange}
          emptyText="—"
        />,
      )
      const el = scroller(container)
      scrollTo(el, { top: 0, height: 1000, client: 200 })
      onFollowChange.mockClear()
      // 1000 - 790 - 200 = 10, inside the 24px slack.
      scrollTo(el, { top: 790, height: 1000, client: 200 })
      expect(onFollowChange).toHaveBeenCalledWith(true)
    })

    it('does not report a position it has not moved away from', () => {
      const onFollowChange = vi.fn()
      const { container } = render(
        <LogViewer lines={makeLines(50)} live follow onFollowChange={onFollowChange} emptyText="—" />,
      )
      const el = scroller(container)
      // Already at the tail, which is where it starts: nothing changed.
      scrollTo(el, { top: 800, height: 1000, client: 200 })
      expect(onFollowChange).not.toHaveBeenCalled()
    })

    it('leaves the view alone once follow is off', () => {
      const onFollowChange = vi.fn()
      const { container, rerender } = render(
        <LogViewer
          lines={makeLines(50)}
          live
          follow={false}
          onFollowChange={onFollowChange}
          emptyText="—"
        />,
      )
      const el = scroller(container)
      scrollTo(el, { top: 0, height: 1000, client: 200 })
      onFollowChange.mockClear()
      // New lines arrive; a reader who scrolled up must not be yanked back.
      rerender(
        <LogViewer
          lines={makeLines(80)}
          live
          follow={false}
          onFollowChange={onFollowChange}
          emptyText="—"
        />,
      )
      expect(onFollowChange).not.toHaveBeenCalled()
    })
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
