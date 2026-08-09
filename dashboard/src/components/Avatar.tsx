import { cn } from '@/lib/utils'

/** Avatar renders a subject's first two characters on the accent colour. */
export function Avatar({ name, className }: { name: string; className?: string | undefined }) {
  const initials = name.slice(0, 2).toUpperCase() || '?'
  return (
    <span
      aria-hidden
      className={cn(
        'grid size-7 shrink-0 select-none place-items-center rounded-full bg-primary font-mono text-[11px] font-semibold text-primary-foreground',
        className,
      )}
    >
      {initials}
    </span>
  )
}
