import { z } from 'zod'

/**
 * The exec websocket client (GET /v1/exec, internal/api/exec.go).
 *
 * Wire protocol:
 *   client → server   binary: raw stdin bytes (no prefix)
 *                     text:   {"type":"resize","width":N,"height":N}
 *                             {"type":"eof"}
 *   server → client   binary: [stream byte][data], 1 = stdout, 2 = stderr
 *                     text:   {"type":"exit","code":N}
 *                             {"type":"error","message":"…"}
 *
 * Auth handshake (PRD v1.64): the browser cannot set X-Kanea-CSRF on an
 * upgrade, so the token rides Sec-WebSocket-Protocol as "kanea-csrf.<token>"
 * beside the negotiable "kanea.exec.v1". Both live in one place here so a
 * protocol change is a one-line adaptation.
 *
 * Deliberately no auto-reconnect: an exec is a session, and a shell that
 * silently became a different shell is worse than one that says it ended.
 */

export const execSubprotocol = 'kanea.exec.v1'
export const csrfProtocolPrefix = 'kanea-csrf.'

/** The server refuses stdin frames above 1 MiB (maxExecStdinFrame). */
export const maxStdinFrame = 1024 * 1024

export interface ExecOptions {
  project: string
  alloc: string
  command: string[]
  tty?: boolean
}

export type ExecEvent =
  | { kind: 'open' }
  | { kind: 'data'; stream: 1 | 2; bytes: Uint8Array }
  | { kind: 'exit'; code: number }
  | { kind: 'error'; message: string }
  | { kind: 'close' }

const controlFrameSchema = z.object({
  type: z.string(),
  code: z.number().optional(),
  message: z.string().optional(),
})

/** execURL builds the exec endpoint address from the page's own origin. */
export function execURL(opts: ExecOptions): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const query = new URLSearchParams()
  query.set('project', opts.project)
  query.set('alloc', opts.alloc)
  for (const arg of opts.command) query.append('command', arg)
  if (opts.tty) query.set('tty', 'true')
  return `${scheme}//${window.location.host}/v1/exec?${query.toString()}`
}

export class ExecSession {
  private ws: WebSocket
  private readonly handlers = new Set<(e: ExecEvent) => void>()
  private closed = false

  constructor(opts: ExecOptions, csrf: string | undefined) {
    const protocols = csrf !== undefined ? [execSubprotocol, csrfProtocolPrefix + csrf] : undefined
    this.ws = new WebSocket(execURL(opts), protocols)
    this.ws.binaryType = 'arraybuffer'

    this.ws.onopen = () => this.emit({ kind: 'open' })
    this.ws.onmessage = (event: MessageEvent<ArrayBuffer | string>) => {
      if (typeof event.data === 'string') {
        this.handleControl(event.data)
        return
      }
      const bytes = new Uint8Array(event.data)
      if (bytes.length === 0) return
      const stream = bytes[0]
      if (stream !== 1 && stream !== 2) return
      this.emit({ kind: 'data', stream, bytes: bytes.subarray(1) })
    }
    this.ws.onclose = () => {
      if (!this.closed) {
        this.closed = true
        this.emit({ kind: 'close' })
      }
    }
    this.ws.onerror = () => {} // a close always follows
  }

  onEvent(fn: (e: ExecEvent) => void): () => void {
    this.handlers.add(fn)
    return () => {
      this.handlers.delete(fn)
    }
  }

  /** sendInput forwards stdin bytes, split under the server's frame cap. */
  sendInput(bytes: Uint8Array): void {
    if (this.ws.readyState !== WebSocket.OPEN) return
    for (let off = 0; off < bytes.length; off += maxStdinFrame) {
      this.ws.send(bytes.subarray(off, off + maxStdinFrame))
    }
  }

  resize(width: number, height: number): void {
    this.sendControl({ type: 'resize', width, height })
  }

  sendEOF(): void {
    this.sendControl({ type: 'eof' })
  }

  close(): void {
    this.ws.close()
  }

  private sendControl(frame: Record<string, unknown>): void {
    if (this.ws.readyState !== WebSocket.OPEN) return
    this.ws.send(JSON.stringify(frame))
  }

  private handleControl(raw: string): void {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      return
    }
    const frame = controlFrameSchema.safeParse(parsed)
    if (!frame.success) return
    if (frame.data.type === 'exit') {
      this.emit({ kind: 'exit', code: frame.data.code ?? 0 })
    } else if (frame.data.type === 'error') {
      this.emit({ kind: 'error', message: frame.data.message ?? 'exec failed' })
    }
  }

  private emit(event: ExecEvent): void {
    for (const fn of this.handlers) fn(event)
  }
}
