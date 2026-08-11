import { useQuery } from '@tanstack/react-query'
import { PageHeader } from '@/components/PageHeader'
import { AccountsSection } from '@/components/settings/AccountsSection'
import { AuditSection } from '@/components/settings/AuditSection'
import { BackupSection } from '@/components/settings/BackupSection'
import { NodeSection } from '@/components/settings/NodeSection'
import { NotificationsSection } from '@/components/settings/NotificationsSection'
import { fetchSettings } from '@/lib/api'
import { useSession } from '@/hooks/useSession'

/**
 * Settings (PRD v1.46, §12.2): the node's flag-decided facts, the two Store
 * records that supersede flags (backup destination, notification channels),
 * accounts and tokens, and the audit log.
 *
 * The whole view is admin-only at the daemon — it names credentials'
 * references and lists accounts, which is a list of things worth attacking —
 * so a viewer gets an explanation rather than a page of 403 banners. The
 * canWrite gate is the same one Backups uses; here it also gates the reads,
 * because the API does.
 */
export function Settings() {
  const { session, csrf } = useSession()
  const canWrite = session?.role === 'admin'

  const settings = useQuery({
    queryKey: ['settings'],
    queryFn: ({ signal }) => fetchSettings(signal),
    enabled: canWrite,
  })

  if (!canWrite) {
    return (
      <section className="space-y-3">
        <PageHeader title="Settings" />
        <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
          Settings are admin-only: the view includes account listings and the names of
          credential references. You are signed in as a viewer.
        </p>
      </section>
    )
  }

  return (
    <section className="space-y-8">
      <PageHeader
        title="Settings"
        subtitle={settings.data ? settings.data.node.network_mode : undefined}
      />

      {settings.isError ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          Cannot read the settings view. The daemon may predate PRD v1.46.
        </p>
      ) : null}

      {settings.data ? (
        <>
          <NodeSection node={settings.data.node} />
          <BackupSection view={settings.data.backup} csrf={csrf} canWrite={canWrite} />
          <NotificationsSection
            view={settings.data.notifications}
            csrf={csrf}
            canWrite={canWrite}
          />
        </>
      ) : null}

      <AccountsSection csrf={csrf} canWrite={canWrite} self={session?.subject} />
      <AuditSection />
    </section>
  )
}
