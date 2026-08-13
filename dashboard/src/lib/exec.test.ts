import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import {
  ExecSession,
  execURL,
  maxStdinFrame,
  execSubprotocol,
  csrfProtocolPrefix,
  type ExecEvent,
} from './exec'

/** A fake exec socket: binary-aware, protocol-recording. */
class fakeWebSocket {
  static instances: fakeWebSocket[] = []
  static readonly CONNECTING = 0
  static readonly OPEN = 1

  readyState = fakeWebSocket.CONNECTING
  binaryType = 'blob'
  sent: (string | Uint8Array)[] = []
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

  send(data: string | Uint8Array) {
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

function connect(csrf?: string) {
  const events: ExecEvent[] = []
  const session = new ExecSession(
    { project: 'shop', alloc: 'shop-web-0', command: ['sh'], tty: true },
    csrf,
  )
  session.onEvent((e) => events.push(e))
  const ws = fakeWebSocket.instances.at(-1)
  if (!ws) throw new Error('no socket')
  return { session, ws, events }
}

function frame(stream: number, text: string): ArrayBuffer {
  const body = new TextEncoder().encode(text)
  const bytes = new Uint8Array(body.length + 1)
  bytes[0] = stream
  bytes.set(body, 1)
  return bytes.buffer
}

describe('execURL', () => {
  it('carries project, alloc, every command argument and the tty flag', () => {
    const url = execURL({ project: 'shop', alloc: 'a-0', command: ['sh', '-c', 'ls'], tty: true })
    expect(url).toContain('/v1/exec?')
    const q = new URL(url.replace(/^ws/, 'http')).searchParams
    expect(q.get('project')).toBe('shop')
    expect(q.get('alloc')).toBe('a-0')
    expect(q.getAll('command')).toEqual(['sh', '-c', 'ls'])
    expect(q.get('tty')).toBe('true')
  })
})

describe('ExecSession', () => {
  it('offers the negotiable subprotocol beside the CSRF entry', () => {
    const { ws } = connect('tok123')
    expect(ws.protocols).toEqual([execSubprotocol, csrfProtocolPrefix + 'tok123'])
    expect(ws.binaryType).toBe('arraybuffer')
  })

  it('decodes the stream prefix byte on server data', () => {
    const { ws, events } = connect()
    ws.open()
    ws.onmessage?.({ data: frame(1, 'out') })
    ws.onmessage?.({ data: frame(2, 'err') })

    const data = events.filter((e): e is ExecEvent & { kind: 'data' } => e.kind === 'data')
    expect(data).toHaveLength(2)
    expect(data[0]?.stream).toBe(1)
    expect(new TextDecoder().decode(data[0]?.bytes)).toBe('out')
    expect(data[1]?.stream).toBe(2)
  })

  it('surfaces exit and error control frames', () => {
    const { ws, events } = connect()
    ws.open()
    ws.onmessage?.({ data: JSON.stringify({ type: 'exit', code: 7 }) })
    ws.onmessage?.({ data: JSON.stringify({ type: 'error', message: 'gone' }) })
    expect(events).toContainEqual({ kind: 'exit', code: 7 })
    expect(events).toContainEqual({ kind: 'error', message: 'gone' })
  })

  it('splits stdin at the server frame cap', () => {
    const { session, ws } = connect()
    ws.open()
    session.sendInput(new Uint8Array(maxStdinFrame + 5))
    const binary = ws.sent.filter((s): s is Uint8Array => typeof s !== 'string')
    expect(binary).toHaveLength(2)
    expect(binary[0]).toHaveLength(maxStdinFrame)
    expect(binary[1]).toHaveLength(5)
  })

  it('encodes resize and eof as JSON control frames', () => {
    const { session, ws } = connect()
    ws.open()
    session.resize(120, 40)
    session.sendEOF()
    const texts = ws.sent.filter((s): s is string => typeof s === 'string').map((s) => JSON.parse(s) as unknown)
    expect(texts).toContainEqual({ type: 'resize', width: 120, height: 40 })
    expect(texts).toContainEqual({ type: 'eof' })
  })

  it('never reconnects: a close is a close', () => {
    const { ws, events } = connect()
    ws.open()
    ws.close()
    expect(events).toContainEqual({ kind: 'close' })
    expect(fakeWebSocket.instances).toHaveLength(1)
  })
})
