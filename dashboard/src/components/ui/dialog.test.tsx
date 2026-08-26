import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { Dialog } from './dialog'

describe('Dialog', () => {
  it('renders nothing while closed', () => {
    render(
      <Dialog open={false} onClose={() => {}} title="T">
        <p>body</p>
      </Dialog>,
    )
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('opens with the title, closes on Escape and the X', () => {
    const onClose = vi.fn()
    render(
      <Dialog open onClose={onClose} title="Shell">
        <p>body</p>
      </Dialog>,
    )
    expect(screen.getByRole('dialog')).toBeTruthy()
    expect(screen.getByText('Shell')).toBeTruthy()

    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalledTimes(2)
  })

  it('dismissable={false} ignores Escape and the backdrop, keeps the X', () => {
    const onClose = vi.fn()
    render(
      <Dialog open onClose={onClose} title="Shell" dismissable={false}>
        <p>body</p>
      </Dialog>,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    fireEvent.mouseDown(screen.getByRole('presentation'))
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('locks body scroll while open and releases it after', () => {
    const { unmount } = render(
      <Dialog open onClose={() => {}} title="T">
        <p>body</p>
      </Dialog>,
    )
    expect(document.body.style.overflow).toBe('hidden')
    unmount()
    expect(document.body.style.overflow).toBe('')
  })

  it('keeps focus on the content when handler identity changes across re-renders', () => {
    // The exec-terminal regression: every live-stats frame re-rendered the
    // parent with a fresh inline onClose, and the capture effect's re-run
    // pulled focus off the terminal and back onto the panel.
    const { rerender } = render(
      <Dialog open onClose={() => {}} title="Shell">
        <input aria-label="field" />
      </Dialog>,
    )
    const field = screen.getByLabelText('field')
    field.focus()
    expect(document.activeElement).toBe(field)

    const latest = vi.fn()
    rerender(
      <Dialog open onClose={latest} title="Shell">
        <input aria-label="field" />
      </Dialog>,
    )
    expect(document.activeElement).toBe(field)

    // and Escape still reaches the latest handler, not the first one
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(latest).toHaveBeenCalledTimes(1)
  })

  it('moves focus into the panel and returns it on close', () => {
    const outside = document.createElement('button')
    document.body.appendChild(outside)
    outside.focus()

    const { unmount } = render(
      <Dialog open onClose={() => {}} title="T">
        <p>body</p>
      </Dialog>,
    )
    expect(document.activeElement).toBe(screen.getByRole('dialog'))
    unmount()
    expect(document.activeElement).toBe(outside)
    outside.remove()
  })
})
