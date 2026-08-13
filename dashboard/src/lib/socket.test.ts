import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { LiveSocket, lingerMs, pingInterval, staleAfter } from './socket'

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

describe('LiveSocket keepalive', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  const sentTypes = (ws: fakeWebSocket) =>
    ws.sent.map((raw) => (JSON.parse(raw) as { type: string }).type)

  it('pings an idle socket before the server would give up on it', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()
    ws.onmessage?.({ data: JSON.stringify({ type: 'data', topic: 'services', key: 'services' }) })

    vi.advanceTimersByTime(pingInterval)
    expect(sentTypes(ws)).toContain('ping')
    live.close()
  })

  it('closes a socket that has been silent past the stale window', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    const first = latest()
    first.open()

    // Nothing ever arrives: after two silent ping rounds the socket is
    // half-open and must be replaced rather than trusted.
    vi.advanceTimersByTime(staleAfter + pingInterval)
    expect(first.readyState).toBe(3)

    // The close handler owns reconnection; a new socket appears on schedule.
    vi.advanceTimersByTime(1_000)
    expect(fakeWebSocket.instances.length).toBeGreaterThan(1)
    live.close()
  })

  it('a frame resets the silence clock', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()

    // Keep feeding frames just inside the window; the socket must stay up.
    for (let i = 0; i < 4; i++) {
      vi.advanceTimersByTime(pingInterval)
      ws.onmessage?.({ data: JSON.stringify({ type: 'pong', topic: 'services' }) })
    }
    expect(ws.readyState).toBe(fakeWebSocket.OPEN)
    live.close()
  })
})

describe('LiveSocket reconnection', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('backs off with jitter inside [0.5x, 1x] of the nominal delay', () => {
    const random = vi.spyOn(Math, 'random').mockReturnValue(0)
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()
    ws.close()

    // With random = 0 the jittered delay is exactly half the nominal 500 ms.
    vi.advanceTimersByTime(249)
    expect(fakeWebSocket.instances).toHaveLength(1)
    vi.advanceTimersByTime(1)
    expect(fakeWebSocket.instances).toHaveLength(2)

    random.mockRestore()
    live.close()
  })

  it('reconnects immediately when connectivity returns', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()
    ws.close()

    // The backoff timer is pending; the online event preempts it.
    window.dispatchEvent(new Event('online'))
    expect(fakeWebSocket.instances).toHaveLength(2)

    // And the replaced subscription replays when the new socket opens.
    const next = latest()
    next.open()
    const topics = next.sent.map((raw) => (JSON.parse(raw) as { topic: string }).topic)
    expect(topics).toContain('services')
    live.close()
  })

  it('close removes the connectivity listeners', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    live.subscribe({ topic: 'services' }, () => {})
    live.close()

    const before = fakeWebSocket.instances.length
    window.dispatchEvent(new Event('online'))
    document.dispatchEvent(new Event('visibilitychange'))
    expect(fakeWebSocket.instances.length).toBe(before)
  })
})

describe('LiveSocket linger', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('holds a subscription through a quick unsubscribe/resubscribe', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    const stop = live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()
    ws.sent = []

    // A route change: the old page unsubscribes, the new one resubscribes
    // moments later. The server must never see the teardown.
    stop()
    vi.advanceTimersByTime(lingerMs / 2)
    live.subscribe({ topic: 'services' }, () => {})
    vi.advanceTimersByTime(lingerMs * 2)

    const types = ws.sent.map((raw) => (JSON.parse(raw) as { type: string }).type)
    expect(types).not.toContain('unsubscribe')
    live.close()
  })

  it('tells the server once the linger window passes unclaimed', () => {
    const live = new LiveSocket('ws://test/v1/ws')
    const stop = live.subscribe({ topic: 'services' }, () => {})
    const ws = latest()
    ws.open()
    ws.sent = []

    stop()
    expect(ws.sent).toHaveLength(0) // not yet
    vi.advanceTimersByTime(lingerMs)

    const types = ws.sent.map((raw) => (JSON.parse(raw) as { type: string }).type)
    expect(types).toContain('unsubscribe')
    live.close()
  })
})
