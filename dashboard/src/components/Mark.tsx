import { cn } from '@/lib/utils'

export interface MarkProps {
  /** Rendered width and height in pixels. The mark is square. */
  size?: number
  className?: string | undefined
}

/**
 * Mark is the Kanea logo, inlined as SVG.
 *
 * The arc and the two dots take `currentColor`, so one component serves the
 * light and dark themes without a second asset and without a theme lookup —
 * the dashboard toggles `.dark` on <html>, and an <img> would not follow it.
 * Only the amber is fixed; it is the one part of the mark that is the same
 * colour on every surface. The source files live in `logo/` at the repo root.
 */
export function Mark({ size = 22, className }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      aria-hidden="true"
      className={cn('shrink-0', className)}
    >
      <path
        d="M44.5 10.35 A25 25 0 1 1 19.5 10.35"
        fill="none"
        stroke="currentColor"
        strokeWidth="5"
        strokeLinecap="round"
      />
      <rect x="28.5" y="1" width="7" height="12" rx="3.5" fill="#f2b544" />
      <rect x="28" y="21" width="8" height="6" rx="3" fill="currentColor" />
      <rect x="24" y="32" width="16" height="6" rx="3" fill="currentColor" opacity="0.65" />
    </svg>
  )
}
