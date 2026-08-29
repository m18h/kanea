import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { DiagnosticList, jumpToLine } from '@/components/SpecDiagnostics'

/**
 * The diagnostics card both spec editors share. Extracted from
 * SpecEditorPage (v1.103), which is what finally put it under test.
 */

describe('DiagnosticList', () => {
  it('badges severity and renders the daemon text as text', () => {
    render(
      <DiagnosticList
        diagnostics={[
          { severity: 'error', summary: 'Missing task', detail: 'a service needs one' },
          { severity: 'warning', summary: '<b>not markup</b>' },
        ]}
        onJump={vi.fn()}
      />,
    )
    expect(screen.getByText('error')).toBeTruthy()
    expect(screen.getByText('warning')).toBeTruthy()
    expect(screen.getByText('a service needs one')).toBeTruthy()
    // Operator/daemon text renders as a text node, never markup (§14 A03).
    expect(screen.getByText('<b>not markup</b>')).toBeTruthy()
  })

  it('offers a jump only for positioned findings and fires with the line', () => {
    const onJump = vi.fn()
    render(
      <DiagnosticList
        diagnostics={[
          { severity: 'error', summary: 'positioned', line: 3, column: 7 },
          { severity: 'error', summary: 'unpositioned' },
        ]}
        onJump={onJump}
      />,
    )
    const jumps = screen.getAllByRole('button')
    expect(jumps).toHaveLength(1)
    expect(jumps[0]?.textContent).toContain('line 3:7')
    fireEvent.click(jumps[0] as HTMLElement)
    expect(onJump).toHaveBeenCalledWith(3)
  })
})

describe('jumpToLine', () => {
  it('moves the caret to the start of the named line', () => {
    const el = document.createElement('textarea')
    const text = 'one\ntwo\nthree'
    el.value = text
    document.body.appendChild(el)
    jumpToLine(el, text, 3)
    expect(el.selectionStart).toBe('one\ntwo\n'.length)
    el.remove()
  })

  it('tolerates a null element and an out-of-range line', () => {
    expect(() => jumpToLine(null, 'x', 5)).not.toThrow()
    const el = document.createElement('textarea')
    el.value = 'one'
    document.body.appendChild(el)
    jumpToLine(el, 'one', 99)
    // The browser clamps the caret to the end of the value.
    expect(el.selectionStart).toBe('one'.length)
    el.remove()
  })
})
