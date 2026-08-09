import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  Boxes,
  DatabaseBackup,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Moon,
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

/** Sidebar is the shell's left rail: brand, nav, connection facts, user. */
export function Sidebar({ className }: { className?: string | undefined }) {
  const counts = useNavCounts()
  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 10_000,
  })

  const nav: { to: string; label: string; icon: LucideIcon; exact: boolean; badge?: number | undefined }[] = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
    { to: '/services', label: 'Services', icon: Boxes, exact: false, badge: counts.services },
    { to: '/pipelines', label: 'Pipelines', icon: GitBranch, exact: false, badge: counts.buildsRunning },
    { to: '/events', label: 'Events', icon: Activity, exact: false, badge: counts.alerts },
    { to: '/backups', label: 'Backups', icon: DatabaseBackup, exact: false },
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
        {health.data ? (
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">
            v{health.data.version.replace(/^v/, '')}
          </span>
        ) : null}
      </div>

      <nav className="flex flex-col gap-0.5 px-2">
        {nav.map((item) => (
          <NavItem key={item.to} {...item} />
        ))}
      </nav>

      <div className="mt-auto border-t border-sidebar-border px-4 py-3">
        <SocketLine />
        <div className="mt-1 flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
          <span aria-hidden>◇</span> store idx {health.data?.store_index ?? '—'}
        </div>
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
}: {
  to: string
  label: string
  icon: LucideIcon
  exact: boolean
  badge?: number | undefined
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
        <span className="ml-auto rounded-full bg-muted px-1.5 font-mono text-[11px] tabular-nums text-muted-foreground">
          {badge}
        </span>
      ) : null}
    </Link>
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
  const [theme, setTheme] = useTheme()
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
        <button
          type="button"
          aria-label="Toggle theme"
          className="rounded-md p-1.5 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
        >
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
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
