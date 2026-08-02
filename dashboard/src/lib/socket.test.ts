import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { LiveSocket } from './socket'

/** fakeWebSocket records what a LiveSocket sends and lets a test drive it. */
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
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function latest(): fakeWebSocket {
  const ws = fakeWebSocket.instances.at(-1)
  if (!ws) throw new Error('no socket was opened')
  return ws
}

describe('LiveSocket', () => {
  it('opens one connection for several subscriptions', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    live.subscribe({ topic: 'allocs' }, () => {})

    expect(fakeWebSocket.instances).toHaveLength(1)
    live.close()
  })

  // After a daemon restart the server knows nothing about this client, so a
  // subscription that is not re-sent is a view that silently stops updating.
  it('replays subscriptions when the socket reopens', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    live.subscribe({ topic: 'logs', project: 'shop', service: 'web' }, () => {})

    const ws = latest()
    ws.open()

    const topics = ws.sent.map((raw) => (JSON.parse(raw) as { topic: string }).topic)
    expect(topics).toContain('services')
    expect(topics).toContain('logs')
    live.close()
  })

  it('routes frames to the subscriber that asked for them', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    const services: unknown[] = []
    const logs: unknown[] = []

    live.subscribe({ topic: 'services' }, (f) => services.push(f))
    live.subscribe({ topic: 'logs', project: 'shop', service: 'web' }, (f) => logs.push(f))

    const ws = latest()
    ws.open()
    ws.onmessage?.({ data: JSON.stringify({ type: 'data', topic: 'services', key: 'services' }) })
    ws.onmessage?.({
      data: JSON.stringify({ type: 'data', topic: 'logs', key: 'logs:shop/web' }),
    })

    expect(services).toHaveLength(1)
    expect(logs).toHaveLength(1)
    live.close()
  })

  it('ignores a frame that is not valid JSON rather than throwing', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()

    expect(() => ws.onmessage?.({ data: 'not json' })).not.toThrow()
    live.close()
  })

  it('stops sending to a listener after it unsubscribes', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    const seen: unknown[] = []
    const stop = live.subscribe({ topic: 'services' }, (f) => seen.push(f))

    const ws = latest()
    ws.open()
    stop()
    ws.onmessage?.({ data: JSON.stringify({ type: 'data', topic: 'services', key: 'services' }) })

    expect(seen).toHaveLength(0)
    live.close()
  })
})
