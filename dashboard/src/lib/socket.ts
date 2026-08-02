import {
  serverFrameSchema,
  subscriptionKey,
  type ServerFrame,
  type SubscribeRequest,
} from './api'

type Listener = (frame: ServerFrame) => void

/**
 * One socket for the whole page.
 *
 * The daemon caps concurrent connections (PRD §14, A07) and multiplexes topics
 * on purpose, so a component opening its own socket would spend a slot the
 * whole dashboard shares. Components subscribe through this instead; the
 * connection is opened on first use and reused.
 */
export class LiveSocket {
  private ws: WebSocket | null = null
  private readonly listeners = new Map<string, Set<Listener>>()
  /** Subscriptions to replay after a reconnect. */
  private readonly active = new Map<string, SubscribeRequest>()
  private reconnectDelay = initialReconnectDelay
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private closed = false

  constructor(private readonly url: string) {}

  /** Subscribe to a topic; returns an unsubscribe function. */
  subscribe(req: SubscribeRequest, listener: Listener): () => void {
    const key = subscriptionKey(req)

    let set = this.listeners.get(key)
    if (!set) {
      set = new Set()
      this.listeners.set(key, set)
    }
    set.add(listener)

    // Recorded before sending so a socket that is still connecting picks it up
    // when it opens, rather than the subscription being silently lost.
    this.active.set(key, req)
    this.connect()
    this.send({ type: 'subscribe', ...req })

    return () => {
      const current = this.listeners.get(key)
      current?.delete(listener)
      if (current && current.size === 0) {
        this.listeners.delete(key)
        this.active.delete(key)
        this.send({ type: 'unsubscribe', ...req })
      }
    }
  }

  /** Close permanently. */
  close(): void {
    this.closed = true
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer)
    this.ws?.close()
    this.ws = null
  }

  private connect(): void {
    if (this.closed) return
    if (this.ws && this.ws.readyState <= WebSocket.OPEN) return

    const ws = new WebSocket(this.url)
    this.ws = ws

    ws.onopen = () => {
      this.reconnectDelay = initialReconnectDelay
      // Replay everything: after a daemon restart the server knows nothing
      // about this client, so anything not re-sent is a view that silently
      // stops updating.
      for (const req of this.active.values()) {
        this.send({ type: 'subscribe', ...req })
      }
    }

    ws.onmessage = (event: MessageEvent<string>) => {
      let parsed: unknown
      try {
        parsed = JSON.parse(event.data)
      } catch {
        return
      }
      const frame = serverFrameSchema.safeParse(parsed)
      if (!frame.success) return

      const key = frame.data.key ?? frame.data.topic
      if (!key) return
      for (const listener of this.listeners.get(key) ?? []) {
        listener(frame.data)
      }
    }

    ws.onclose = () => {
      this.ws = null
      this.scheduleReconnect()
    }
    // An error is always followed by a close, so reconnection is handled there.
    ws.onerror = () => {}
  }

  private scheduleReconnect(): void {
    if (this.closed || this.listeners.size === 0) return
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer)

    const delay = this.reconnectDelay
    // Backing off matters more than usual here: a daemon that is down is
    // exactly when every open tab would otherwise retry in a tight loop, and
    // the connection cap means those retries also lock each other out.
    this.reconnectDelay = Math.min(delay * 2, maxReconnectDelay)
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, delay)
  }

  private send(frame: Record<string, unknown>): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(frame))
  }
}

const initialReconnectDelay = 500
const maxReconnectDelay = 15_000

/** socketURL derives the websocket address from the page's own origin. */
export function socketURL(): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${window.location.host}/v1/ws`
}
