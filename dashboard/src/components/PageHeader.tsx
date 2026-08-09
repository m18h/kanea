export interface PageHeaderProps {
  title: React.ReactNode
  /** subtitle is rendered mono and muted — it carries facts, not prose. */
  subtitle?: React.ReactNode | undefined
  actions?: React.ReactNode | undefined
}

/** PageHeader is every page's first row: title, mono subtitle, actions right. */
export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle !== undefined ? (
          <span className="font-mono text-xs text-muted-foreground">{subtitle}</span>
        ) : null}
      </div>
      {actions !== undefined ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  )
}
