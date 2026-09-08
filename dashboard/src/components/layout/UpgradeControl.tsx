import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import {
  fetchHealth,
  fetchUpgradeCheck,
  runUpgrade,
  type UpgradeCheck,
  type UpgradeResponse,
} from '@/lib/api'
import { formatDateTime } from '@/lib/datetime'
import { useSession } from '@/hooks/useSession'

/**
 * UpgradeControl is the sidebar's version, and for an admin it is a control
 * (PRD v1.107): a dot when a newer release exists, a click for the dialog
 * that checks or upgrades. A non-admin gets the plain text, and so does a
 * daemon that cannot upgrade itself (the check answers 503 there).
 *
 * The check query runs only while a dashboard is open, on purpose: the
 * daemon caches its answer for an hour and never contacts the release host
 * unprompted, so this refetch cadence is the outer bound of how often any
 * node phones GitHub at all.
 */
export function UpgradeControl({ version }: { version: string }) {
  const { session } = useSession()
  const admin = session?.role === 'admin'
  const [open, setOpen] = useState(false)

  const check = useQuery({
    queryKey: ['upgrade-check'],
    queryFn: ({ signal }) => fetchUpgradeCheck(signal),
    enabled: admin,
    refetchInterval: 6 * 60 * 60 * 1000,
    staleTime: 60 * 60 * 1000,
  })

  const label = `v${version.replace(/^v/, '')}`
  if (!admin || check.data === null) {
    return <span className="ml-auto font-mono text-[11px] text-muted-foreground">{label}</span>
  }

  const newRelease = check.data?.update_available ? check.data.latest : null
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title={newRelease ? `New release ${newRelease} available` : 'Check for updates'}
        className="ml-auto flex items-center gap-1.5 rounded-md px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
      >
        {label}
        {newRelease ? (
          <span
            aria-label={`new release ${newRelease} available`}
            className="size-1.5 rounded-full bg-status-warn"
          />
        ) : null}
      </button>
      <UpgradeDialog
        open={open}
        onClose={() => setOpen(false)}
        check={check.data}
        checkError={check.isError ? String(check.error) : null}
        checking={check.isFetching}
        onCheck={() => void check.refetch()}
      />
    </>
  )
}

/** What the dialog is doing right now. `waiting` is the stretch between the
 * daemon's answer and the new version answering health, which ends in a full
 * page reload: that reload is what swaps in the new embedded dashboard. */
type Phase = 'idle' | 'installing' | 'waiting'

/** How long to wait for the restarted daemon before giving up. The edge
 * drains, kanead runs a schema migration at startup; minutes, not seconds. */
const restartWaitMs = 3 * 60 * 1000
const healthPollMs = 2000

function UpgradeDialog({
  open,
  onClose,
  check,
  checkError,
  checking,
  onCheck,
}: {
  open: boolean
  onClose: () => void
  check: UpgradeCheck | null | undefined
  checkError: string | null
  checking: boolean
  onCheck: () => void
}) {
  const { csrf } = useSession()
  const [phase, setPhase] = useState<Phase>('idle')
  const [armed, setArmed] = useState(false)
  const [result, setResult] = useState<UpgradeResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  // An armed upgrade disarms itself: a button left reading "confirm?" for
  // minutes is a trap for the next person at the keyboard.
  useEffect(() => {
    if (!armed) return
    const timer = setTimeout(() => setArmed(false), 4000)
    return () => clearTimeout(timer)
  }, [armed])

  // The wait for the restarted daemon: poll health until the installed
  // version answers, then reload the whole page. fetchHealth failing here is
  // expected (the daemon is down mid-restart) and just means "not yet".
  useEffect(() => {
    if (phase !== 'waiting' || !result) return
    const deadline = Date.now() + restartWaitMs
    const timer = setInterval(() => {
      if (Date.now() > deadline) {
        clearInterval(timer)
        setPhase('idle')
        setError(
          'kanead did not come back in time; check `journalctl -u kanead` on the node. ' +
            'If a schema migration failed, its pre-migration copy is named in the log.',
        )
        return
      }
      fetchHealth()
        .then((health) => {
          if (health.version === result.installed) window.location.reload()
        })
        .catch(() => {})
    }, healthPollMs)
    return () => clearInterval(timer)
  }, [phase, result])

  const upgrade = () => {
    setArmed(false)
    setPhase('installing')
    setError(null)
    setResult(null)
    runUpgrade(undefined, csrf)
      .then((resp) => {
        setResult(resp)
        setPhase(resp.restarting ? 'waiting' : 'idle')
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err))
        setPhase('idle')
      })
  }

  const busy = phase !== 'idle'
  return (
    <Dialog
      open={open}
      // Closing mid-restart would silently drop the reload that finishes the
      // upgrade, so the dialog holds still until the daemon answers.
      dismissable={!busy}
      onClose={() => {
        if (!busy) onClose()
      }}
      title="Software update"
      className="w-[92vw] max-w-md"
    >
      <div className="flex flex-col gap-3 text-sm">
        <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
          <span className="text-muted-foreground">Running</span>
          <span className="font-mono">{check?.running ?? '…'}</span>
          <span className="text-muted-foreground">Latest release</span>
          <span className="font-mono">{check?.latest ?? '…'}</span>
        </div>
        {check ? (
          <p className="text-xs text-muted-foreground">
            {check.update_available
              ? `A new release is available.`
              : 'This node is on the latest release.'}
            {check.checked_at ? ` Checked ${formatDateTime(check.checked_at)}.` : ''}
          </p>
        ) : null}
        {checkError ? <p className="text-xs text-destructive">{checkError}</p> : null}

        {result ? (
          <ul className="flex flex-col gap-0.5 rounded-md bg-muted p-2 font-mono text-xs">
            {result.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        ) : null}
        {phase === 'installing' ? (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 size={14} className="animate-spin" aria-hidden />
            Downloading and verifying… the pre-upgrade backup runs first.
          </p>
        ) : null}
        {phase === 'waiting' ? (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 size={14} className="animate-spin" aria-hidden />
            Restarting the daemons… this page reloads when {result?.installed} answers.
          </p>
        ) : null}
        {result?.restart_required ? (
          <p className="text-xs text-muted-foreground">
            The new binary is installed, but this daemon is not running under systemd, so nothing
            restarts by itself: run <code>systemctl restart kanea-edge kanead</code> on the node
            (or restart the processes however this node runs them) to finish.
          </p>
        ) : null}
        {error ? <p className="text-xs text-destructive">{error}</p> : null}

        <div className="mt-1 flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={busy || checking} onClick={onCheck}>
            {checking ? <Loader2 size={14} className="animate-spin" aria-hidden /> : null}
            Check for updates
          </Button>
          {check?.update_available ? (
            <Button
              size="sm"
              disabled={busy}
              onClick={() => {
                if (armed) upgrade()
                else setArmed(true)
              }}
            >
              {armed ? 'Confirm upgrade?' : `Upgrade to ${check.latest}`}
            </Button>
          ) : null}
        </div>
      </div>
    </Dialog>
  )
}
