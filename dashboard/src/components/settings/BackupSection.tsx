import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Label } from '@/components/ui/input'
import { KeyValue } from '@/components/KeyValue'
import {
  putBackupSettings,
  resetBackupSettings,
  type BackupSettingsRecord,
  type BackupSettingsView,
} from '@/lib/api'
import { replicationLag, when } from '@/lib/backups'
import {
  backupFormFromRecord,
  backupFormToRecord,
  describeBackupSource,
  type BackupForm,
} from '@/lib/settings'

/**
 * BackupSection edits the `settings/backup` record (PRD v1.46).
 *
 * The daemon probes a new destination before committing anything, so a Save
 * that fails leaves the old replication untouched: the 400's own message says
 * so and is shown verbatim. Revert deletes the record and the unit flags win
 * again, which is destructive enough to earn the two-click confirm the
 * Backups page uses for staging a restore.
 */
export function BackupSection({
  view,
  csrf,
  canWrite,
}: {
  view: BackupSettingsView
  csrf: string | undefined
  canWrite: boolean
}) {
  const client = useQueryClient()
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [confirmRevert, setConfirmRevert] = useState(false)
  const [form, setForm] = useState<BackupForm>(() => backupFormFromRecord(view.settings))

  const save = useMutation({
    mutationFn: (rec: BackupSettingsRecord) => putBackupSettings(rec, csrf),
    onSuccess: () => {
      setError('')
      setSaved(true)
      void client.invalidateQueries({ queryKey: ['settings'] })
      void client.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: Error) => {
      setSaved(false)
      setError(err.message)
    },
  })

  const revert = useMutation({
    mutationFn: () => resetBackupSettings(csrf),
    onSuccess: () => {
      setError('')
      setSaved(false)
      void client.invalidateQueries({ queryKey: ['settings'] })
      void client.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const source = describeBackupSource(view.source)
  const status = view.status

  const set = (patch: Partial<BackupForm>) => {
    setSaved(false)
    setForm((f) => ({ ...f, ...patch }))
  }

  const submit = () => {
    const built = backupFormToRecord(form)
    if ('error' in built) {
      setError(built.error)
      return
    }
    save.mutate(built.record)
  }

  return (
    <section className="space-y-3">
      <div className="flex items-baseline gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Backups</h2>
        <Badge variant={source.variant}>{source.label}</Badge>
      </div>

      {status ? (
        <Card>
          <CardHeader>
            <CardTitle>Replication</CardTitle>
          </CardHeader>
          <CardContent>
            <KeyValue label="Sink" mono>
              {status.sink || '-'}
            </KeyValue>
            <KeyValue label="Last segment" mono>
              {status.last_segment_at
                ? `${replicationLag(status.last_segment_at)} ago · ${when(status.last_segment_at)}`
                : 'never'}
            </KeyValue>
            <KeyValue label="Last snapshot" mono>
              {when(status.last_snapshot_at)}
            </KeyValue>
            <KeyValue label="Failures" mono>
              <span className={status.failures > 0 ? 'text-status-error' : undefined}>
                {status.failures}
              </span>
            </KeyValue>
          </CardContent>
        </Card>
      ) : (
        <p className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
          Replication is not running. Configure a destination below, or set{' '}
          <code className="font-mono text-xs">--backup-dir</code> /{' '}
          <code className="font-mono text-xs">--backup-s3</code> on the unit.
        </p>
      )}

      {canWrite ? (
        <Card>
          <CardHeader>
            <CardTitle>Destination</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {error ? (
              <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
                {error}
              </p>
            ) : null}
            {saved ? (
              <p className="rounded-md border border-status-ok/40 bg-status-ok/10 px-3 py-2 text-sm">
                Saved. The destination passed its probe and replication now ships there.
              </p>
            ) : null}

            <div className="flex items-center gap-2" role="radiogroup" aria-label="Destination type">
              <Button
                size="sm"
                variant={form.kind === 'dir' ? 'default' : 'outline'}
                onClick={() => set({ kind: 'dir' })}
              >
                Directory
              </Button>
              <Button
                size="sm"
                variant={form.kind === 's3' ? 'default' : 'outline'}
                onClick={() => set({ kind: 's3' })}
              >
                S3
              </Button>
            </div>

            {form.kind === 'dir' ? (
              <div className="space-y-1.5">
                <Label htmlFor="backup-dir">Directory</Label>
                <Input
                  id="backup-dir"
                  className="font-mono"
                  placeholder="/var/backups/kanea"
                  value={form.dir}
                  onChange={(e) => set({ dir: e.target.value })}
                />
              </div>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="backup-s3-url">Bucket URL</Label>
                  <Input
                    id="backup-s3-url"
                    className="font-mono"
                    placeholder="s3://bucket/prefix"
                    value={form.url}
                    onChange={(e) => set({ url: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="backup-s3-endpoint">Endpoint</Label>
                  <Input
                    id="backup-s3-endpoint"
                    className="font-mono"
                    placeholder="https://s3.example.com"
                    value={form.endpoint}
                    onChange={(e) => set({ endpoint: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="backup-s3-region">Region</Label>
                  <Input
                    id="backup-s3-region"
                    className="font-mono"
                    placeholder="us-east-1"
                    value={form.region}
                    onChange={(e) => set({ region: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="backup-s3-access-key">Access key id</Label>
                  <Input
                    id="backup-s3-access-key"
                    className="font-mono"
                    value={form.accessKey}
                    onChange={(e) => set({ accessKey: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5 sm:col-span-2">
                  <Label htmlFor="backup-s3-secret-ref">Secret key reference</Label>
                  <Input
                    id="backup-s3-secret-ref"
                    className="font-mono"
                    placeholder="secret:shared/backup-s3"
                    value={form.secretKeyRef}
                    onChange={(e) => set({ secretKeyRef: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">
                    A <code className="font-mono">secret:</code> reference, never the key itself.
                  </p>
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={form.pathStyle}
                    onChange={(e) => set({ pathStyle: e.target.checked })}
                  />
                  Path-style addressing
                </label>
              </div>
            )}

            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label htmlFor="backup-snapshot-interval">Snapshot interval</Label>
                <Input
                  id="backup-snapshot-interval"
                  className="font-mono"
                  placeholder="6h"
                  value={form.snapshotInterval}
                  onChange={(e) => set({ snapshotInterval: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="backup-segment-interval">Segment interval</Label>
                <Input
                  id="backup-segment-interval"
                  className="font-mono"
                  placeholder="1m"
                  value={form.segmentInterval}
                  onChange={(e) => set({ segmentInterval: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="backup-retention">Retention (archives)</Label>
                <Input
                  id="backup-retention"
                  className="font-mono"
                  placeholder="10"
                  inputMode="numeric"
                  value={form.retention}
                  onChange={(e) => set({ retention: e.target.value })}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Intervals are Go durations (<code className="font-mono">6h</code>,{' '}
              <code className="font-mono">1m</code>). Empty fields take the replicator's defaults.
            </p>

            <div className="flex items-center gap-2">
              <Button disabled={save.isPending} onClick={submit}>
                {save.isPending ? 'Probing destination…' : 'Save'}
              </Button>
              {view.source === 'store' ? (
                <Button
                  variant="outline"
                  className={confirmRevert ? 'border-status-warn text-status-warn' : ''}
                  disabled={revert.isPending}
                  onClick={() => {
                    if (!confirmRevert) {
                      setConfirmRevert(true)
                      return
                    }
                    setConfirmRevert(false)
                    revert.mutate()
                  }}
                >
                  {confirmRevert ? 'Confirm revert?' : 'Revert to unit flags'}
                </Button>
              ) : null}
            </div>
          </CardContent>
        </Card>
      ) : null}
    </section>
  )
}
