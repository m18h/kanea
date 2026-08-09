import { Link } from '@/lib/router'

/** BackChip is the small bordered "← Somewhere" link above a detail page. */
export function BackChip({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
    >
      <span aria-hidden>←</span> {children}
    </Link>
  )
}
