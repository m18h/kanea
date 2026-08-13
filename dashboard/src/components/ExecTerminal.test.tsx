import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { ExecTerminal } from './ExecTerminal'
import { SessionContext, type SessionState } from '@/lib/session-context'

/** Recording fakes for the lazily imported xterm modules. */
const terminals: FakeTerminal[] = []
class FakeTerminal {
  cols = 80
  rows = 24
  opened: HTMLElement | null = null
  disposed = false
  written: unknown[] = []
  constructor(public opts: unknown) {
    terminals.push(this)
  }
  loadAddon() {}
  open(el: HTMLElement) {
    this.opened = el
  }
  onData() {
    return { dispose: () => {} }
  }
  write(data: unknown) {
    this.written.push(data)
  }
  focus() {}
  dispose() {
    this.disposed = true
  }
}

vi.mock('@xterm/xterm', () => ({ Terminal: FakeTerminal }))
vi.mock('@xterm/addon-fit', () => ({ FitAddon: class { fit() {} } }))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

class fakeWebSocket {
  static instances: fakeWebSocket[] = []
  static readonly OPEN = 1
  readyState = 0
  binaryType = 'blob'
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: { data: ArrayBuffer | string }) => void) | null = null
  constructor(
    public url: string,
    public protocols?: string[],
  ) {
    fakeWebSocket.instances.push(this)
  }
  send() {}
  close() {
    this.readyState = 3
    this.onclose?.()
  }
}

const session: SessionState = {
  session: { subject: 'ada', role: 'admin', via: 'session' },
  loading: false,
  csrf: 'tok',
  signIn: vi.fn(),
  signOut: vi.fn(),
}

beforeEach(() => {
  terminals.length = 0
  fakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', fakeWebSocket)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ExecTerminal', () => {
  it('opens a terminal, dials with the CSRF subprotocol, and tears down on unmount', async () => {
    const { unmount } = render(
      <SessionContext.Provider value={session}>
        <ExecTerminal project="shop" alloc="shop-web-0" />
      </SessionContext.Provider>,
    )

    await waitFor(() => expect(terminals.some((t) => t.opened !== null)).toBe(true))
    await waitFor(() => expect(fakeWebSocket.instances.length).toBeGreaterThan(0))
    const ws = fakeWebSocket.instances.at(-1)
    expect(ws?.url).toContain('/v1/exec?')
    expect(ws?.protocols).toEqual(['kanea.exec.v1', 'kanea-csrf.tok'])

    unmount()
    expect(terminals.every((t) => t.disposed || t.opened === null)).toBe(true)
    expect(fakeWebSocket.instances.every((w) => w.readyState === 3)).toBe(true)
  })
})
