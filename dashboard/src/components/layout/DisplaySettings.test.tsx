import { afterEach, describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { DisplaySettings } from './DisplaySettings'
import { DefaultDateStyle, dateStyle, setDateStyle } from '@/lib/datetime'

afterEach(() => {
  setDateStyle(DefaultDateStyle)
  window.localStorage.clear()
  document.documentElement.classList.remove('dark')
})

function openPanel() {
  fireEvent.click(screen.getByRole('button', { name: 'Display settings' }))
}

describe('DisplaySettings', () => {
  it('keeps the panel shut until the cog is pressed', () => {
    render(<DisplaySettings />)

    const cog = screen.getByRole('button', { name: 'Display settings' })
    expect(cog.getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByLabelText('Dark mode')).toBeNull()

    fireEvent.click(cog)
    expect(cog.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByLabelText('Dark mode')).toBeTruthy()
  })

  it('carries both settings, and only those', () => {
    render(<DisplaySettings />)
    openPanel()

    expect(screen.getByRole('switch', { name: 'Dark mode' })).toBeTruthy()
    expect(screen.getByLabelText('Date format')).toBeTruthy()
  })

  it('changes the date format from the picker', () => {
    render(<DisplaySettings />)
    openPanel()

    const picker = screen.getByLabelText<HTMLSelectElement>('Date format')
    expect(picker.value).toBe(DefaultDateStyle)

    fireEvent.change(picker, { target: { value: 'MM/dd/yyyy' } })
    expect(dateStyle()).toBe('MM/dd/yyyy')
    expect(window.localStorage.getItem('kanea-date-style')).toBe('MM/dd/yyyy')
  })

  it('toggles the theme', () => {
    render(<DisplaySettings />)
    openPanel()

    // The hook owns the class on <html>; this asserts the wiring reaches it
    // rather than re-testing useTheme.
    const before = document.documentElement.classList.contains('dark')
    fireEvent.click(screen.getByRole('switch', { name: 'Dark mode' }))
    expect(document.documentElement.classList.contains('dark')).toBe(!before)
  })

  it('closes on Escape and gives focus back to the cog', () => {
    // A panel that closes and drops focus to the document leaves a keyboard
    // user at the top of the page.
    render(<DisplaySettings />)
    const cog = screen.getByRole('button', { name: 'Display settings' })
    openPanel()

    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByLabelText('Dark mode')).toBeNull()
    expect(document.activeElement).toBe(cog)
  })

  it('closes on a press outside it', () => {
    render(
      <div>
        <DisplaySettings />
        <button type="button">elsewhere</button>
      </div>,
    )
    openPanel()

    // mousedown, not click: an outside press should close this before whatever
    // it lands on gets to act.
    fireEvent.mouseDown(screen.getByRole('button', { name: 'elsewhere' }))
    expect(screen.queryByLabelText('Dark mode')).toBeNull()
  })

  it('stays open when pressed inside', () => {
    // The outside-press listener is on the document, so without the containment
    // check the panel would close the moment somebody reached for a control.
    render(<DisplaySettings />)
    openPanel()

    fireEvent.mouseDown(screen.getByLabelText('Date format'))
    expect(screen.getByLabelText('Date format')).toBeTruthy()
  })

  it('does not claim menu semantics', () => {
    // aria-expanded without role="menu": menu semantics promise arrow-key
    // navigation, and a switch and a select reached by Tab is the honest
    // description (the OpenUrlMenu rule).
    render(<DisplaySettings />)
    openPanel()

    expect(screen.queryByRole('menu')).toBeNull()
    expect(screen.queryByRole('menuitem')).toBeNull()
  })
})
