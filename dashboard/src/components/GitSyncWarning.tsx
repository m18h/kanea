/**
 * The GitOps warning both spec editors share: a synced project's next sync
 * wins over anything applied here. Warn, never block (an admin may be
 * intentionally hot-fixing) and require the checkbox so it was read. The
 * projects lookup stays at the call site; this only renders the verdict.
 */
export function GitSyncWarning({
  git,
  confirmed,
  onConfirm,
}: {
  git: { url: string; branch?: string | undefined }
  confirmed: boolean
  onConfirm: (v: boolean) => void
}) {
  return (
    <div className="rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2 text-sm">
      <p>
        This project syncs from <span className="font-mono">{git.url}</span>
        {git.branch ? (
          <>
            {' '}
            (<span className="font-mono">{git.branch}</span>)
          </>
        ) : null}
        . Changes applied here will be overwritten on the next sync: edit the
        repository instead, or confirm you want a hot-fix that the repository will
        later replace.
      </p>
      <label className="mt-2 flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => onConfirm(e.target.checked)}
        />
        Apply anyway; the next sync wins.
      </label>
    </div>
  )
}
