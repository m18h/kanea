import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { KeyValue } from '@/components/KeyValue'
import { CardSkeleton } from '@/components/Skeletons'
import { PageHeader } from '@/components/PageHeader'
import { type UpdatesView, type UpgradeCheck } from '@/lib/api'
import { formatDateTime } from '@/lib/datetime'
import { startUpgrade } from '@/lib/upgrade'
import { useSession } from '@/hooks/useSession'
import { useUpdatesQuery, useUpgradeCheckQuery } from '@/hooks/useUpdates'
import { useUpgrade } from '@/hooks/useUpgrade'

/**
 * Updates (PRD v1.108): what this node runs beside what is waiting. The
 * Kanea card is the v1.107 check-and-upgrade out of its dialog; the OS half
 * is read facts, never install controls - the daemon only reads the package
 * lists, so the page names the command to run on the node instead.
 *
 * Admin-only at the daemon, like Settings and for the same reason: what a
 * node is missing is a list of things worth attacking.
 */
export function Updates() {
  const { session } = useSession()
  const admin = session?.role === 'admin'
  const check = useUpgradeCheckQuery(admin)
  const updates = useUpdatesQuery(admin)

  if (!admin) {
    return (
      <section className="space-y-3">
        <PageHeader title="Updates" />
        <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
          Updates are admin-only: the view lists what this node is missing. You are signed in
          as a viewer.
        </p>
      </section>
    )
  }

  const os = updates.data?.os
  return (
    <section className="space-y-4">
      <PageHeader title="Updates" subtitle="OS packages are reported, never installed" />

      <div className="grid gap-4 lg:grid-cols-2">
        <KaneaCard
          check={check.data}
          checkError={check.isError ? String(check.error) : null}
          checking={check.isFetching}
          onCheck={() => void check.refetch()}
        />
        <OSCard view={updates.data} loading={updates.isPending} error={updates.isError} />
      </div>
      {updates.data?.components?.length ? <ComponentsCard view={updates.data} /> : null}
      {os?.pending?.length ? <PendingCard os={os} /> : null}
    </section>
  )
}

function KaneaCard({
  check,
  checkError,
  checking,
  onCheck,
}: {
  check: UpgradeCheck | null | undefined
  checkError: string | null
  checking: boolean
  onCheck: () => void
}) {
  const { csrf } = useSession()
  const upgrade = useUpgrade()
  const [armed, setArmed] = useState(false)

  // An armed upgrade disarms itself: a button left reading "confirm?" for
  // minutes is a trap for the next person at the keyboard.
  useEffect(() => {
    if (!armed) return
    const timer = setTimeout(() => setArmed(false), 4000)
    return () => clearTimeout(timer)
  }, [armed])

  const busy = upgrade.phase !== 'idle'
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          Kanea
          {check?.update_available ? <Badge variant="warn">update available</Badge> : null}
          {check && !check.update_available ? <Badge variant="ok">up to date</Badge> : null}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {check === null ? (
          <p className="text-sm text-muted-foreground">
            This daemon cannot upgrade itself: use <code>kanea upgrade</code> on the node.
          </p>
        ) : (
          <>
            <div>
              <KeyValue label="Running" mono>
                {check?.running ?? '…'}
              </KeyValue>
              <KeyValue label="Latest release" mono>
                {check?.latest ?? '…'}
              </KeyValue>
              <KeyValue label="Checked">
                {check?.checked_at ? formatDateTime(check.checked_at) : '–'}
              </KeyValue>
            </div>
            {checkError ? <p className="text-xs text-destructive">{checkError}</p> : null}

            {upgrade.result ? (
              <ul className="flex flex-col gap-0.5 rounded-md bg-muted p-2 font-mono text-xs">
                {upgrade.result.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            ) : null}
            {upgrade.phase === 'installing' ? (
              <p className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 size={14} className="animate-spin" aria-hidden />
                Downloading and verifying… the pre-upgrade backup runs first.
              </p>
            ) : null}
            {upgrade.phase === 'waiting' ? (
              <p className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 size={14} className="animate-spin" aria-hidden />
                Restarting the daemons… this page reloads when {upgrade.result?.installed}{' '}
                answers.
              </p>
            ) : null}
            {upgrade.result?.restart_required ? (
              <p className="text-xs text-muted-foreground">
                The new binary is installed, but this daemon is not running under systemd, so
                nothing restarts by itself: run{' '}
                <code>systemctl restart kanea-edge kanead</code> on the node (or restart the
                processes however this node runs them) to finish.
              </p>
            ) : null}
            {upgrade.error ? <p className="text-xs text-destructive">{upgrade.error}</p> : null}

            <div className="flex items-center justify-end gap-2">
              <Button variant="outline" size="sm" disabled={busy || checking} onClick={onCheck}>
                {checking ? <Loader2 size={14} className="animate-spin" aria-hidden /> : null}
                Check for updates
              </Button>
              {check?.update_available ? (
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={() => {
                    if (armed) {
                      setArmed(false)
                      startUpgrade(csrf)
                    } else {
                      setArmed(true)
                    }
                  }}
                >
                  {armed ? 'Confirm upgrade?' : `Upgrade to ${check.latest}`}
                </Button>
              ) : null}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function OSCard({
  view,
  loading,
  error,
}: {
  view: UpdatesView | null | undefined
  loading: boolean
  error: boolean
}) {
  const os = view?.os
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          Operating system
          {os?.reboot_required ? <Badge variant="error">reboot required</Badge> : null}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {view === null ? (
          <p className="text-sm text-muted-foreground">This daemon does not inspect its host.</p>
        ) : error ? (
          <p className="text-sm text-muted-foreground">Cannot read the update state.</p>
        ) : loading ? (
          <CardSkeleton lines={5} title={false} />
        ) : os ? (
          <>
            <div>
              <KeyValue label="OS">{os.name || '–'}</KeyValue>
              <KeyValue label="Kernel" mono>
                {os.kernel || '–'}
              </KeyValue>
              {/* "–" is unknown, never zero (§9.2): an unsupported package
                  manager has no counts, and 0 would be a lie nobody measured. */}
              <KeyValue label="Pending updates" mono>
                {os.pending_total ?? '–'}
              </KeyValue>
              <KeyValue label="Security updates">
                {os.security_total === undefined ? (
                  '–'
                ) : os.security_total > 0 ? (
                  <Badge variant="warn">{os.security_total} security</Badge>
                ) : (
                  '0'
                )}
              </KeyValue>
              <KeyValue label="Package lists refreshed">
                {os.lists_refreshed_at ? formatDateTime(os.lists_refreshed_at) : '–'}
              </KeyValue>
            </div>
            {os.package_manager === 'unsupported' ? (
              <p className="text-xs text-muted-foreground">
                This node's package manager is not one Kanea can read yet, so the counts are
                unknown.
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                Kanea only reads the package lists. To install, run{' '}
                <code>apt update && apt upgrade</code> on the node.
              </p>
            )}
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}

function ComponentsCard({ view }: { view: UpdatesView }) {
  const components = view.components ?? []
  const allPinned =
    components.length > 0 && components.every((c) => c.installed !== undefined && c.installed === c.pinned)
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          Managed components
          {allPinned ? <Badge variant="ok">all at pinned versions</Badge> : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <THead>
            <TR>
              <TH>Component</TH>
              <TH>Installed</TH>
              <TH>Pinned by manifest</TH>
              <TH />
            </TR>
          </THead>
          <TBody>
            {components.map((c) => (
              <TR key={c.name}>
                <TD className="font-mono">{c.name}</TD>
                <TD className="font-mono">{c.installed ?? '–'}</TD>
                <TD className="font-mono">{c.pinned}</TD>
                <TD>
                  {c.installed === undefined ? (
                    <Badge variant="muted">no receipt</Badge>
                  ) : c.installed === c.pinned ? (
                    <Badge variant="ok">ok</Badge>
                  ) : (
                    <Badge variant="warn">drifted</Badge>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
        <p className="mt-3 text-xs text-muted-foreground">
          Kanea installs these at pinned versions. They change with a Kanea upgrade, not with{' '}
          <code>apt</code>.
        </p>
      </CardContent>
    </Card>
  )
}

function PendingCard({ os }: { os: UpdatesView['os'] }) {
  const pending = os.pending ?? []
  const more = (os.pending_total ?? pending.length) - pending.length
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-3">
          Pending packages
          <span className="text-xs font-normal text-muted-foreground">
            {os.pending_total ?? pending.length} upgradable
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <THead>
            <TR>
              <TH>Package</TH>
              <TH>Version</TH>
              <TH>Origin</TH>
              <TH />
            </TR>
          </THead>
          <TBody>
            {pending.map((p) => (
              <TR key={p.name}>
                <TD className="font-mono">{p.name}</TD>
                <TD className="font-mono">
                  {p.installed ? (
                    <>
                      {p.installed} <span className="text-muted-foreground">→</span> {p.candidate}
                    </>
                  ) : (
                    p.candidate
                  )}
                </TD>
                <TD className="text-muted-foreground">{p.origin ?? '–'}</TD>
                <TD>{p.security ? <Badge variant="error">security</Badge> : null}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
        {more > 0 ? (
          <p className="mt-3 text-xs text-muted-foreground">
            …and {more} more. See <code>apt list --upgradable</code> on the node.
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}
