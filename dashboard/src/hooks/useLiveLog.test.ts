import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import { MaxLogLines, useLiveLog } from './useLiveLog'
import { resetLiveSocket } from '@/lib/live'

describe('MaxLogLines', () => {
  // A tab left open on a chatty service would otherwise grow without limit:
  // the daemon streams as fast as the workload writes.
  it('is a bound a browser can actually hold', () => {
    expect(MaxLogLines).toBeGreaterThan(100)
    expect(MaxLogLines).toBeLessThanOrEqual(10_000)
  })
})

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

function deliver(ws: fakeWebSocket, data: unknown) {
  act(() => {
    ws.onmessage?.({
      data: JSON.stringify({
        type: 'data',
        topic: 'logs',
        key: 'logs:shop/web',
        data,
      }),
    })
  })
}

describe('useLiveLog', () => {
  it('appends every line a batch carries', async () => {
    const { result } = renderHook(() => useLiveLog('shop', 'web'))
    const ws = socket()
    act(() => ws.open())

    deliver(ws, {
      lines: [
        { alloc_id: 'shop-web-0', line: 'first' },
        { alloc_id: 'shop-web-0', line: 'second' },
      ],
    })

    await waitFor(() => expect(result.current.lines).toHaveLength(2))
    expect(result.current.lines.map((l) => l.line)).toEqual(['first', 'second'])
  })

  // Two gaps with two causes. Collapsing them would report a node under
  // pressure as a browser running out of buffer, and send whoever is debugging
  // to the wrong end of the pipe.
  it('keeps a daemon-side drop apart from its own trim', async () => {
    const { result } = renderHook(() => useLiveLog('shop', 'web'))
    const ws = socket()
    act(() => ws.open())

    deliver(ws, { lines: [{ alloc_id: 'shop-web-0', line: 'kept' }], dropped: 91 })

    await waitFor(() => expect(result.current.droppedByDaemon).toBe(91))
    expect(result.current.dropped).toBe(0)
    expect(result.current.lines).toHaveLength(1)
  })

  it('reports a drop even when the frame that carried it had few lines', async () => {
    const { result } = renderHook(() => useLiveLog('shop', 'web'))
    const ws = socket()
    act(() => ws.open())

    deliver(ws, { lines: [{ alloc_id: 'shop-web-0', line: 'a' }], dropped: 4 })
    deliver(ws, { lines: [{ alloc_id: 'shop-web-0', line: 'b' }], dropped: 6 })

    await waitFor(() => expect(result.current.droppedByDaemon).toBe(10))
  })

  it('ignores a frame that is not a batch', async () => {
    const { result } = renderHook(() => useLiveLog('shop', 'web'))
    const ws = socket()
    act(() => ws.open())

    // The pre-v1.70 single-line shape.
    deliver(ws, { alloc_id: 'shop-web-0', line: 'lonely' })
    deliver(ws, { lines: [{ alloc_id: 'shop-web-0', line: 'batched' }] })

    await waitFor(() => expect(result.current.lines).toHaveLength(1))
    expect(result.current.lines[0]?.line).toBe('batched')
  })
})
