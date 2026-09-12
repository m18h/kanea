import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  Boxes,
  DatabaseBackup,
  FolderTree,
  FunctionSquare,
  GitBranch,
  HardDrive,
  LayoutDashboard,
  LogOut,
  Moon,
  RefreshCw,
  Settings2,
  Sun,
  type LucideIcon,
} from 'lucide-react'
import { Avatar } from '@/components/Avatar'
import { Mark } from '@/components/Mark'
import { fetchHealth } from '@/lib/api'
import { isActive } from '@/lib/paths'
import { Link } from '@/lib/router'
import { cn } from '@/lib/utils'
import { useNavCounts } from '@/hooks/useNavCounts'
import { useRouter } from '@/hooks/useRouter'
import { useSession } from '@/hooks/useSession'
import { useSocketStatus } from '@/hooks/useSocketStatus'
import { useTheme } from '@/hooks/useTheme'
import { useUpdateAttention } from '@/hooks/useUpdates'
import { DisplaySettings } from '@/components/layout/DisplaySettings'

/** Sidebar is the shell's left rail: brand, nav, connection facts, user. */
export function Sidebar({ className }: { className?: string | undefined }) {
  const counts = useNavCounts()
  const attention = useUpdateAttention()
  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 10_000,
  })

  const nav: { to: string; label: string; icon: LucideIcon; exact: boolean; badge?: number | undefined }[] = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
    { to: '/projects', label: 'Projects', icon: FolderTree, exact: false },
    { to: '/services', label: 'Services', icon: Boxes, exact: false, badge: counts.services },
    { to: '/pipelines', label: 'Pipelines', icon: GitBranch, exact: false, badge: counts.buildsRunning },
    { to: '/functions', label: 'Functions', icon: FunctionSquare, exact: false, badge: counts.functions },
    // Projects and Storage carry no badge on purpose: each would cost the
    // sidebar a poll of its own on every page (a project list walks services,
    // allocs and pipeline configs), and neither number is one an operator is
    // waiting for the way a running build or a new alert is.
    { to: '/storage', label: 'Storage', icon: HardDrive, exact: false },
    { to: '/events', label: 'Events', icon: Activity, exact: false, badge: counts.alerts },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup, exact: false },
    { to: '/settings', label: 'Settings', icon: Settings2, exact: false },
  ]

  return (
    <aside
      className={cn(
        'flex w-[230px] shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground',
        className,
      )}
    >
      <div className="flex items-center gap-2 px-4 pb-4 pt-5">
        <Mark size={22} />
        <span className="text-base font-semibold tracking-tight">kanea</span>
        {health.data?.version ? (
          // Plain text again since v1.108: the Updates page is the control,
          // and the pinned nav item below carries the attention badge.
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">
            {`v${health.data.version.replace(/^v/, '')}`}
          </span>
        ) : null}
        <ThemeToggle />
      </div>

      <nav className="flex flex-col gap-0.5 px-2">
        {nav.map((item) => (
          <NavItem key={item.to} {...item} />
        ))}
      </nav>

      {/* Updates sits apart from the pages above it (PRD v1.108): those are
          the workloads, this is the node itself. Its badge is amber, not the
          muted count the others carry, because it counts actions waiting
          rather than things existing. */}
      <nav className="mt-auto flex flex-col px-2 pb-1">
        <NavItem to="/updates" label="Updates" icon={RefreshCw} exact={false} badge={attention} alert />
      </nav>

      <div className="border-t border-sidebar-border px-4 py-3">
        <SocketLine />
      </div>
      <UserRow />
    </aside>
  )
}

function NavItem({
  to,
  label,
  icon: Icon,
  exact,
  badge,
  alert,
}: {
  to: string
  label: string
  icon: LucideIcon
  exact: boolean
  badge?: number | undefined
  /** alert renders the badge amber: it counts actions waiting, not things
   * existing, which is the Updates item's case (PRD v1.108). */
  alert?: boolean | undefined
}) {
  const { path } = useRouter()
  const active = isActive(path, to, exact)
  return (
    <Link
      to={to}
      aria-current={active ? 'page' : undefined}
      className={cn(
        'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors',
        active
          ? 'bg-sidebar-accent font-medium text-primary'
          : 'text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground',
      )}
    >
      <Icon size={16} aria-hidden />
      <span>{label}</span>
      {badge !== undefined && badge > 0 ? (
        <span
          className={cn(
            'ml-auto rounded-full px-1.5 font-mono text-[11px] tabular-nums',
            alert ? 'bg-status-warn/20 text-status-warn' : 'bg-muted text-muted-foreground',
          )}
        >
          {badge}
        </span>
      ) : null}
    </Link>
  )
}

/**
 * ThemeToggle sits beside the version, out of the cog since v1.108: the one
 * icon whose meaning is legible without a label, and the brand row is where
 * the theme's evidence is.
 */
function ThemeToggle() {
  const [theme, setTheme] = useTheme()
  const dark = theme === 'dark'
  return (
    <button
      type="button"
      aria-label="Toggle theme"
      title="Toggle theme"
      className="rounded-md border border-sidebar-border p-1 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
      onClick={() => setTheme(dark ? 'light' : 'dark')}
    >
      {dark ? <Sun size={13} aria-hidden /> : <Moon size={13} aria-hidden />}
    </button>
  )
}

function SocketLine() {
  const up = useSocketStatus()
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span
        aria-hidden
        className={cn('size-1.5 rounded-full', up ? 'bg-status-ok' : 'bg-status-error')}
      />
      <span className={up ? 'text-muted-foreground' : 'text-status-error'}>
        {up ? 'websocket connected' : 'websocket reconnecting…'}
      </span>
    </div>
  )
}

function UserRow() {
  const { session, signOut } = useSession()
  if (!session) return null

  return (
    <div className="flex items-center gap-2.5 border-t border-sidebar-border px-4 py-3">
      <Avatar name={session.subject} />
      <div className="min-w-0">
        {/* Who you are and what you may do, always visible: a viewer who does
            not know they are one reads every missing button as broken. */}
        <div className="truncate text-sm font-medium">{session.subject}</div>
        <div className="truncate text-xs text-muted-foreground">
          {session.role} · {session.via}
        </div>
      </div>
      <div className="ml-auto flex items-center">
        {/* One cog rather than an icon per setting. Both live in this browser
            rather than on the node, so neither belongs on the admin-only
            Settings page; and the date format needs a label rather than an
            icon, because no icon says which of three orders is in force. */}
        <DisplaySettings />
        <button
          type="button"
          aria-label="Sign out"
          title="Sign out"
          className="rounded-md p-1.5 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
          onClick={() => void signOut()}
        >
          <LogOut size={15} />
        </button>
      </div>
    </div>
  )
}
