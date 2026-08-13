import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { z } from 'zod'
import { useLiveTopic } from './useLiveTopic'
import { resetLiveSocket } from '@/lib/live'

/** The same shape socket.test.ts drives; enough of a WebSocket for the hook. */
class fakeWebSocket {
  static instances: fakeWebSocket[] = []
  static readonly CONNECTING = 0
  static readonly OPEN = 1

  readyState = fakeWebSocket.CONNECTING
  sent: string[] = []
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null

  constructor(public url: string) {
    fakeWebSocket.instances.push(this)
  }

  send(data: string) {
    this.sent.push(data)
  }

  close() {
    this.readyState = 3
    this.onclose?.()
  }

  open() {
    this.readyState = fakeWebSocket.OPEN
    this.onopen?.()
  }
}

const schema = z.object({ value: z.number() })

beforeEach(() => {
  fakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', fakeWebSocket)
  resetLiveSocket()
})

afterEach(() => {
  resetLiveSocket()
  vi.unstubAllGlobals()
})

function socket(): fakeWebSocket {
  const ws = fakeWebSocket.instances.at(-1)
  if (!ws) throw new Error('no socket was opened')
  return ws
}

describe('useLiveTopic', () => {
  it('connected means a frame arrived on the current connection', () => {
    const { result } = renderHook(() => useLiveTopic({ topic: 'services' }, schema))
    expect(result.current.connected).toBe(false)

    const ws = socket()
    act(() => ws.open())
    expect(result.current.up).toBe(true)
    expect(result.current.connected).toBe(false) // the transport alone is not data

    act(() =>
      ws.onmessage?.({
        data: JSON.stringify({ type: 'data', topic: 'services', key: 'services', data: { value: 3 } }),
      }),
    )
    expect(result.current.connected).toBe(true)
    expect(result.current.data).toEqual({ value: 3 })
  })

  it('a disconnect resets connected but keeps the data', () => {
    const { result } = renderHook(() => useLiveTopic({ topic: 'services' }, schema))
    const ws = socket()
    act(() => ws.open())
    act(() =>
      ws.onmessage?.({
        data: JSON.stringify({ type: 'data', topic: 'services', key: 'services', data: { value: 3 } }),
      }),
    )

    act(() => ws.close())
    // Stale beats blank: the page keeps rendering what it has, but nothing may
    // treat it as a current answer — that is what un-set connected means.
    expect(result.current.up).toBe(false)
    expect(result.current.connected).toBe(false)
    expect(result.current.data).toEqual({ value: 3 })
  })
})
