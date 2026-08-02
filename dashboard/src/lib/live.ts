import { LiveSocket, socketURL } from '@/lib/socket'

/**
 * The page's single live socket (PRD §12.1).
 *
 * It lives in its own module so every hook reaches it the same way. The daemon
 * caps concurrent connections (§14, A07), so "one socket per page" is a real
 * constraint rather than a tidiness preference — two accessors in two modules
 * is how that quietly becomes two connections.
 *
 * Created lazily so importing a hook in a test does not open one.
 */
let shared: LiveSocket | null = null

export function liveSocket(): LiveSocket {
  shared ??= new LiveSocket(socketURL())
  return shared
}

/** resetLiveSocket drops the shared connection. For tests. */
export function resetLiveSocket(): void {
  shared?.close()
  shared = null
}
