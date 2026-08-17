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
  /** Keys whose last listener just left, waiting out the linger window. */
  private readonly lingering = new Map<string, ReturnType<typeof setTimeout>>()
  private readonly statusListeners = new Set<(up: boolean) => void>()
  private reconnectDelay = initialReconnectDelay
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private pingTimer: ReturnType<typeof setInterval> | null = null
  private lastFrameAt = 0
  private closed = false

  constructor(private readonly url: string) {
    // A laptop lid or a dropped wifi association ends in one of two ways: the
    // OS delivers a close (handled below), or the connection is half-open and
    // nothing fires at all. These two signals cover the moments the machine
    // knows connectivity just returned, so waiting out a 15 s backoff there
    // would be latency with no purpose.
    window.addEventListener('online', this.wake)
    document.addEventListener('visibilitychange', this.onVisibility)
  }

  /** connected reports whether the socket is open right now. */
  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  /** onStatus is notified on open and close; returns an unsubscribe. */
  onStatus(fn: (up: boolean) => void): () => void {
    this.statusListeners.add(fn)
    return () => {
      this.statusListeners.delete(fn)
    }
  }

  /** Subscribe to a topic; returns an unsubscribe function. */
  subscribe(req: SubscribeRequest, listener: Listener): () => void {
    const key = subscriptionKey(req)

    // A re-subscribe inside the linger window keeps the server-side
    // subscription alive instead of tearing it down and rebuilding it.
    const pending = this.lingering.get(key)
    if (pending !== undefined) {
      clearTimeout(pending)
      this.lingering.delete(key)
    }

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
    // Sent even when the key was already subscribed: the server treats a
    // repeat subscribe as a replace and re-sends the current snapshot, which
    // is exactly what a listener that just mounted needs.
    this.send({ type: 'subscribe', ...req })

    return () => {
      const current = this.listeners.get(key)
      current?.delete(listener)
      if (!current || current.size > 0) return
      this.listeners.delete(key)

      // Linger before telling the server. Route changes churn the same shared
      // topics (services, allocs, a page of per-row stats): an immediate
      // unsubscribe would tear each one down on navigation only to rebuild it
      // milliseconds later, and every rebuild costs a snapshot re-send.
      const timer = setTimeout(() => {
        this.lingering.delete(key)
        this.active.delete(key)
        this.send({ type: 'unsubscribe', ...req })
      }, lingerMs)
      this.lingering.set(key, timer)
    }
  }

  /** Close permanently. */
  close(): void {
    this.closed = true
    window.removeEventListener('online', this.wake)
    document.removeEventListener('visibilitychange', this.onVisibility)
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer)
    this.stopPing()
    for (const timer of this.lingering.values()) clearTimeout(timer)
    this.lingering.clear()
    this.ws?.close()
    this.ws = null
  }

  private readonly wake = (): void => {
    if (this.closed || this.listeners.size === 0) return
    if (this.ws && this.ws.readyState <= WebSocket.OPEN) return
    // Connectivity just came back; the pending backoff was sized for a world
    // that no longer exists.
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.reconnectDelay = initialReconnectDelay
    this.connect()
  }

  private readonly onVisibility = (): void => {
    if (!document.hidden) this.wake()
  }

  private connect(): void {
    if (this.closed) return
    if (this.ws && this.ws.readyState <= WebSocket.OPEN) return

    const ws = new WebSocket(this.url)
    this.ws = ws

    ws.onopen = () => {
      this.reconnectDelay = initialReconnectDelay
      this.startPing()
      for (const fn of this.statusListeners) fn(true)
      // Replay everything: after a daemon restart the server knows nothing
      // about this client, so anything not re-sent is a view that silently
      // stops updating.
      for (const req of this.active.values()) {
        this.send({ type: 'subscribe', ...req })
      }
    }

    ws.onmessage = (event: MessageEvent<string>) => {
      // Any frame proves the path is alive; the ping loop reads this.
      this.lastFrameAt = Date.now()

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
      this.stopPing()
      for (const fn of this.statusListeners) fn(false)
      this.scheduleReconnect()
    }
    // An error is always followed by a close, so reconnection is handled there.
    ws.onerror = () => {}
  }

  /**
   * The application-level keepalive. The server pings every 30 s and closes on
   * a failed write, but nothing guards the other direction: a half-open
   * connection after a sleep or a NAT timeout looks open to this client while
   * delivering nothing. Sending our own ping makes the server answer (any
   * frame counts), and a socket that has been silent past staleAfter is closed
   * so the ordinary reconnect path can replace it.
   */
  private startPing(): void {
    this.stopPing()
    this.lastFrameAt = Date.now()
    this.pingTimer = setInterval(() => {
      if (this.ws?.readyState !== WebSocket.OPEN) return
      if (Date.now() - this.lastFrameAt > staleAfter) {
        this.ws.close()
        return
      }
      this.send({ type: 'ping' })
    }, pingInterval)
  }

  private stopPing(): void {
    if (this.pingTimer !== null) clearInterval(this.pingTimer)
    this.pingTimer = null
  }

  private scheduleReconnect(): void {
    if (this.closed || this.listeners.size === 0) return
    if (this.reconnectTimer !== null) clearTimeout(this.reconnectTimer)

    // Backing off matters more than usual here: a daemon that is down is
    // exactly when every open tab would otherwise retry in a tight loop, and
    // the connection cap means those retries also lock each other out. The
    // jitter (equal-jitter: [0.5×, 1×] of the nominal delay) keeps those tabs
    // from thundering back in lockstep when it returns.
    const delay = this.reconnectDelay * (0.5 + Math.random() * 0.5)
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, maxReconnectDelay)
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, delay)
  }

  // A frame sent while the socket is not OPEN is dropped, deliberately. For
  // subscribes that is safe because `active` replays on open; for
  // unsubscribes it is safe because server-side subscription state is
  // per-connection: whatever the unsubscribe would have cleared either died
  // with the old connection or was never sent to the new one.
  private send(frame: Record<string, unknown>): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(frame))
  }
}

const initialReconnectDelay = 500
const maxReconnectDelay = 15_000
/** Under the server's own 30 s ping, so each side sees traffic in time. */
export const pingInterval = 25_000
/** A socket silent past two ping rounds is half-open; close and reconnect. */
export const staleAfter = 2 * pingInterval
/** How long an unwatched subscription survives a route change. */
export const lingerMs = 3_000

/** socketURL derives the websocket address from the page's own origin. */
export function socketURL(): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${window.location.host}/v1/ws`
}
