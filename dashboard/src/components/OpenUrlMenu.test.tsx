import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { OpenUrlMenu } from '@/components/OpenUrlMenu'

/**
 * The Open control.
 *
 * Its shape depends on how many addresses there are, and each of the three
 * cases is a deliberate choice: nothing for none (a disabled button would
 * imply a permission or a state you could change, and neither applies), a
 * plain link for one (a menu holding exactly one item is chrome between the
 * reader and what they wanted), and a dropdown only once there is a choice to
 * make.
 */
describe('OpenUrlMenu', () => {
  it('renders nothing when there is nothing to open', () => {
    const { container } = render(<OpenUrlMenu urls={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('is a plain link for a single address, with no menu to open', () => {
    render(<OpenUrlMenu urls={['https://shop.example.com']} />)
    const link = screen.getByRole('link', { name: /Open/ })
    expect(link.getAttribute('href')).toBe('https://shop.example.com')
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')
    // No disclosure: there is no choice to make. (The link wraps a Button,
    // the same shape `Edit spec` uses, so a button element legitimately
    // exists; what must not exist is the expanded state of a menu.)
    expect(screen.getByRole('button', { name: /Open/ }).hasAttribute('aria-expanded')).toBe(false)
  })

  it('opens a menu of every address when there is a choice', () => {
    const first = 'https://shop.example.com'
    const urls = [first, 'https://www.shop.example.com']
    render(<OpenUrlMenu urls={urls} />)

    const trigger = screen.getByRole('button', { name: /Open/ })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
    // Closed: the addresses are not in the document at all, rather than hidden.
    expect(screen.queryByRole('link', { name: first })).toBeNull()

    fireEvent.click(trigger)
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
    for (const url of urls) {
      const link = screen.getByRole('link', { name: url })
      expect(link.getAttribute('href')).toBe(url)
      expect(link.getAttribute('target')).toBe('_blank')
      // Every item, not just the first: the attribute that keeps the opened
      // page from getting a handle on this one has to be on all of them.
      expect(link.getAttribute('rel')).toBe('noopener noreferrer')
    }
  })

  it('closes on Escape', () => {
    render(<OpenUrlMenu urls={['https://a.example.com', 'https://b.example.com']} />)
    const trigger = screen.getByRole('button', { name: /Open/ })
    fireEvent.click(trigger)
    expect(trigger.getAttribute('aria-expanded')).toBe('true')

    fireEvent.keyDown(document, { key: 'Escape' })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })

  it('closes on a press outside it', () => {
    render(
      <div>
        <button type="button">elsewhere</button>
        <OpenUrlMenu urls={['https://a.example.com', 'https://b.example.com']} />
      </div>,
    )
    const trigger = screen.getByRole('button', { name: /Open/ })
    fireEvent.click(trigger)
    expect(trigger.getAttribute('aria-expanded')).toBe('true')

    fireEvent.mouseDown(screen.getByRole('button', { name: 'elsewhere' }))
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })

  it('stays open for a press inside it', () => {
    render(<OpenUrlMenu urls={['https://a.example.com', 'https://b.example.com']} />)
    const trigger = screen.getByRole('button', { name: /Open/ })
    fireEvent.click(trigger)
    fireEvent.mouseDown(screen.getByRole('link', { name: 'https://a.example.com' }))
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
  })

  it('closes once an address is chosen', () => {
    render(<OpenUrlMenu urls={['https://a.example.com', 'https://b.example.com']} />)
    const trigger = screen.getByRole('button', { name: /Open/ })
    fireEvent.click(trigger)
    fireEvent.click(screen.getByRole('link', { name: 'https://a.example.com' }))
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })
})
