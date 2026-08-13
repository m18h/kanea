import { useQuery } from '@tanstack/react-query'
import { PageHeader } from '@/components/PageHeader'
import { AccountsSection } from '@/components/settings/AccountsSection'
import { AuditSection } from '@/components/settings/AuditSection'
import { BackupSection } from '@/components/settings/BackupSection'
import { NodeSection } from '@/components/settings/NodeSection'
import { NotificationsSection } from '@/components/settings/NotificationsSection'
import { CardSkeleton } from '@/components/Skeletons'
import { fetchSettings } from '@/lib/api'
import { Link } from '@/lib/router'
import { cn } from '@/lib/utils'
import { useSession } from '@/hooks/useSession'

/** The tab rail, in display order. Each id is a URL segment. */
const settingsTabs = [
  { id: 'node', label: 'Node' },
  { id: 'backup', label: 'Backup' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'accounts', label: 'Accounts' },
  { id: 'audit', label: 'Audit' },
] as const

type SettingsTab = (typeof settingsTabs)[number]['id']

function isSettingsTab(tab: string): tab is SettingsTab {
  return settingsTabs.some((t) => t.id === tab)
}

/**
 * Settings (PRD v1.46, §12.2): the node's flag-decided facts, the two Store
 * records that supersede flags (backup destination, notification channels),
 * accounts and tokens, and the audit log — one section per tab, deep-linkable
 * as /settings/<tab> through the ordinary router (bare /settings is the first
 * tab). Only the active tab mounts, so the Accounts and Audit queries run
 * when someone is actually looking.
 *
 * The whole view is admin-only at the daemon — it names credentials'
 * references and lists accounts, which is a list of things worth attacking —
 * so a viewer gets an explanation rather than a page of 403 banners. The
 * canWrite gate is the same one Backups uses; here it also gates the reads,
 * because the API does.
 */
export function Settings({ tab }: { tab?: string | undefined }) {
  const { session, csrf } = useSession()
  const canWrite = session?.role === 'admin'
  const active: SettingsTab | null =
    tab === undefined ? 'node' : isSettingsTab(tab) ? tab : null

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

  const needsSettings = active === 'node' || active === 'backup' || active === 'notifications'

  return (
    <section className="space-y-4">
      <PageHeader
        title="Settings"
        subtitle={settings.data ? settings.data.node.network_mode : undefined}
      />

      {settings.isError && needsSettings ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          Cannot read the settings view. The daemon may predate PRD v1.46.
        </p>
      ) : null}

      <div className="gap-6 md:grid md:grid-cols-[180px_1fr]">
        <TabRail active={active} />
        <div className="mt-4 min-w-0 md:mt-0">
          {active === null ? (
            <p className="text-sm text-muted-foreground">No such settings tab.</p>
          ) : null}
          {active === 'node' ? (
            settings.data ? (
              <NodeSection node={settings.data.node} />
            ) : settings.isError ? null : (
              <CardSkeleton lines={6} />
            )
          ) : null}
          {active === 'backup' ? (
            settings.data ? (
              <BackupSection view={settings.data.backup} csrf={csrf} canWrite={canWrite} />
            ) : settings.isError ? null : (
              <CardSkeleton lines={6} />
            )
          ) : null}
          {active === 'notifications' ? (
            settings.data ? (
              <NotificationsSection
                view={settings.data.notifications}
                csrf={csrf}
                canWrite={canWrite}
              />
            ) : settings.isError ? null : (
              <CardSkeleton lines={6} />
            )
          ) : null}
          {active === 'accounts' ? (
            <AccountsSection csrf={csrf} canWrite={canWrite} self={session?.subject} />
          ) : null}
          {active === 'audit' ? <AuditSection /> : null}
        </div>
      </div>
    </section>
  )
}

/**
 * TabRail is the left navigation: real links, so tabs are bookmarkable and
 * back/forward work for free. Below md it becomes a horizontal chip row —
 * five short labels scroll fine and stay links.
 */
function TabRail({ active }: { active: SettingsTab | null }) {
  return (
    <nav
      aria-label="Settings sections"
      className="flex gap-1 overflow-x-auto md:flex-col md:overflow-visible"
    >
      {settingsTabs.map((t) => {
        const current = active === t.id
        return (
          <Link
            key={t.id}
            to={`/settings/${t.id}`}
            aria-current={current ? 'page' : undefined}
            className={cn(
              'shrink-0 rounded-md px-3 py-1.5 text-sm transition-colors',
              current
                ? 'bg-muted font-medium text-foreground'
                : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground',
            )}
          >
            {t.label}
          </Link>
        )
      })}
    </nav>
  )
}
