import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { ExecSession } from '@/lib/exec'
import { useSession } from '@/hooks/useSession'

export interface ExecTerminalProps {
  project: string
  alloc: string
  /** command defaults to a plain sh with a TTY. */
  command?: string[]
}

type Ended = { code: number | null; message?: string }

/**
 * ExecTerminal is a shell inside an alloc: xterm.js wired to the exec
 * websocket. xterm (~75 KB) loads through a dynamic import so nobody pays
 * for it until a shell is actually opened: verify the build keeps it as a
 * separate chunk.
 *
 * There is no reconnect: when the process exits or the socket drops, the
 * session is over and says so. "New session" remounts via the parent's key.
 */
export function ExecTerminal({ project, alloc, command }: ExecTerminalProps) {
  const hostRef = useRef<HTMLDivElement>(null)
  const [ended, setEnded] = useState<Ended | null>(null)
  const [epoch, setEpoch] = useState(0)
  const { csrf } = useSession()

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    // StrictMode runs this effect twice: the guard stops the first, already
    // cleaned-up run from wiring a dead terminal after the async import.
    let disposed = false
    let cleanup: (() => void) | null = null

    void Promise.all([import('@xterm/xterm'), import('@xterm/addon-fit'), import('@xterm/xterm/css/xterm.css')]).then(
      ([{ Terminal }, { FitAddon }]) => {
        if (disposed) return

        const styles = getComputedStyle(document.documentElement)
        const hsl = (name: string) => `hsl(${styles.getPropertyValue(name).trim()})`
        const term = new Terminal({
          fontSize: 13,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
          cursorBlink: true,
          theme: {
            background: hsl('--card'),
            foreground: hsl('--foreground'),
            cursor: hsl('--primary'),
            selectionBackground: hsl('--muted'),
          },
        })
        const fit = new FitAddon()
        term.loadAddon(fit)
        term.open(host)
        fit.fit()

        const session = new ExecSession(
          { project, alloc, command: command ?? ['sh'], tty: true },
          csrf,
        )
        const encoder = new TextEncoder()
        const onData = term.onData((data) => session.sendInput(encoder.encode(data)))
        const offEvents = session.onEvent((event) => {
          switch (event.kind) {
            case 'open':
              session.resize(term.cols, term.rows)
              term.focus()
              break
            case 'data':
              term.write(event.bytes)
              break
            case 'exit':
              setEnded({ code: event.code })
              break
            case 'error':
              setEnded((prev) => prev ?? { code: null, message: event.message })
              break
            case 'close':
              setEnded((prev) => prev ?? { code: null })
              break
          }
        })

        const observer =
          typeof ResizeObserver !== 'undefined'
            ? new ResizeObserver(() => {
                fit.fit()
                session.resize(term.cols, term.rows)
              })
            : null
        observer?.observe(host)

        cleanup = () => {
          observer?.disconnect()
          onData.dispose()
          offEvents()
          session.close()
          term.dispose()
        }
      },
    )

    return () => {
      disposed = true
      cleanup?.()
      cleanup = null
    }
    // epoch remounts the whole session for "New session".
  }, [project, alloc, command, csrf, epoch])

  return (
    <div className="flex h-full flex-col gap-2">
      <div ref={hostRef} className="min-h-0 flex-1 overflow-hidden rounded-md" />
      <div className="flex h-8 items-center gap-3 font-mono text-xs text-muted-foreground">
        {ended === null ? (
          <span>
            {alloc} · {(command ?? ['sh']).join(' ')}
          </span>
        ) : (
          <>
            <span className={ended.message !== undefined ? 'text-destructive' : ''}>
              {ended.message ?? (ended.code !== null ? `exited · code ${ended.code}` : 'session ended')}
            </span>
            <Button
              size="sm"
              variant="outline"
              className="h-6 px-2 text-xs"
              onClick={() => {
                setEnded(null)
                setEpoch((n) => n + 1)
              }}
            >
              New session
            </Button>
          </>
        )}
      </div>
    </div>
  )
}
